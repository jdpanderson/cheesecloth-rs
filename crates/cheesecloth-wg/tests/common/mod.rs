//! Shared parts of the privileged tunnel tests.

use std::{
    ffi::CString,
    io, iter,
    net::{SocketAddr, UdpSocket},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use gotatun::{
    device::{Device, DeviceBuilder, Peer},
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
    udp::socket::UdpSocketFactory,
    x25519::{PublicKey, StaticSecret},
};
use tokio::sync::{Mutex, mpsc};

pub const LOCAL_V4: &str = "192.0.2.1";
pub const REMOTE_V4: &str = "192.0.2.2";
pub const LOCAL_V6: &str = "2001:db8:cc::1";
pub const REMOTE_V6: &str = "2001:db8:cc::2";

#[allow(unsafe_code, reason = "the standard library has no if_nametoindex")]
pub fn interface_exists(name: &str) -> bool {
    let name = CString::new(name).unwrap();
    // SAFETY: name is a live NUL-terminated string.
    unsafe { libc::if_nametoindex(name.as_ptr()) != 0 }
}

pub fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

pub fn application_socket(local: &str, remote: &str) -> Result<UdpSocket> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let socket = loop {
        match UdpSocket::bind(SocketAddr::new(local.parse()?, 0)) {
            Ok(socket) => break socket,
            // IPv6 duplicate-address detection is asynchronous.
            Err(error)
                if error.kind() == io::ErrorKind::AddrNotAvailable && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error.into()),
        }
    };
    socket.connect(SocketAddr::new(remote.parse()?, 9))?;
    socket.set_read_timeout(Some(Duration::from_millis(250)))?;
    Ok(socket)
}

pub fn exchange(local: &str, remote: &str) -> Result<()> {
    let socket = application_socket(local, remote)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    // A substantial payload tests packet transfer as well as handshakes.
    let payload = [0xa5; 1024];
    socket
        .send(&payload)
        .with_context(|| format!("sending to {remote}"))?;
    loop {
        let mut reply = [0; 2048];
        match socket.recv(&mut reply) {
            Ok(size) => {
                ensure!(reply[..size] == payload, "corrupt reply from {remote}");
                return Ok(());
            }
            Err(error) if is_timeout(&error) && Instant::now() < deadline => {}
            Err(error) => {
                return Err(error).with_context(|| format!("encrypted UDP exchange with {remote}"));
            }
        }
    }
}

/// Checks that traffic to the removed peer goes nowhere.
pub fn no_exchange(local: &str, remote: &str) -> Result<()> {
    let socket = application_socket(local, remote)?;
    match socket.send(b"removed peer must not receive this") {
        Ok(_) => {}
        // Kernel WireGuard refuses a packet that no peer may carry.
        #[cfg(target_os = "linux")]
        Err(error) if error.raw_os_error() == Some(libc::ENOKEY) => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("sending to removed peer {remote}"));
        }
    }
    let error = socket
        .recv(&mut [0; 256])
        .expect_err("removed peer still receives traffic");
    ensure!(is_timeout(&error), "unexpected receive error: {error}");
    Ok(())
}

pub fn check_nat_opener() -> Result<()> {
    let source = UdpSocket::bind("127.0.0.1:0")?;
    let receiver = UdpSocket::bind("127.0.0.1:0")?;
    receiver.set_read_timeout(Some(Duration::from_secs(2)))?;
    cheesecloth_wg::opener::send(source.local_addr()?.port(), receiver.local_addr()?)?;
    let mut payload = [0xff; 16];
    let (size, sender) = receiver.recv_from(&mut payload)?;
    ensure!(
        sender == source.local_addr()? && payload[..size] == [0],
        "incorrect NAT opener"
    );
    Ok(())
}

/// A WireGuard peer with no OS interface. It reflects every UDP packet it
/// receives through the tunnel back to the sender, so a reply must pass
/// through the interface under test and WireGuard both ways.
pub struct EchoPeer {
    pub endpoint: SocketAddr,
    error: Arc<std::sync::Mutex<Option<String>>>,
    device: Option<Device<(UdpSocketFactory, Echo, Echo)>>,
    runtime: tokio::runtime::Runtime,
}

impl EchoPeer {
    pub fn start(private: [u8; 32], peer: [u8; 32]) -> Result<Self> {
        let runtime = tokio::runtime::Runtime::new()?;
        // GotaTun binds the port it is given; find a free one first.
        let port = UdpSocket::bind("127.0.0.1:0")?.local_addr()?.port();
        let error = Arc::new(std::sync::Mutex::new(None));
        let (sender, receiver) = mpsc::channel(64);
        let echo = Echo {
            reflected: sender,
            pending: Arc::new(Mutex::new(receiver)),
            error: error.clone(),
        };
        let mut local = Peer::new(PublicKey::from(peer));
        local.allowed_ips = vec![
            format!("{LOCAL_V4}/32").parse()?,
            format!("{LOCAL_V6}/128").parse()?,
        ];
        let device = runtime.block_on(
            DeviceBuilder::new()
                .with_default_udp()
                .with_ip(echo)
                .with_listen_port(port)
                .with_private_key(StaticSecret::from(private))
                .with_peer(local)
                .build(),
        )?;
        Ok(Self {
            endpoint: SocketAddr::new("127.0.0.1".parse()?, port),
            error,
            device: Some(device),
            runtime,
        })
    }

    pub fn finish(mut self) -> Result<()> {
        if let Some(device) = self.device.take() {
            self.runtime.block_on(device.stop());
        }
        match self.error.lock().unwrap().take() {
            Some(error) => bail!("WireGuard echo peer: {error}"),
            None => Ok(()),
        }
    }
}

/// The echo peer's IP side: what WireGuard decrypts comes back to it.
#[derive(Clone)]
struct Echo {
    reflected: mpsc::Sender<Vec<u8>>,
    pending: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    error: Arc<std::sync::Mutex<Option<String>>>,
}

impl IpSend for Echo {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let mut packet = packet.into_bytes().to_vec();
        match reflect_udp(&mut packet) {
            Ok(true) => {
                let _ = self.reflected.send(packet).await;
            }
            Ok(false) => {}
            Err(e) => {
                self.error.lock().unwrap().get_or_insert(format!("{e:#}"));
            }
        }
        Ok(())
    }
}

impl IpRecv for Echo {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let bytes = self
            .pending
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "echo peer closed"))?;
        let mut packet = pool.get();
        packet[..bytes.len()].copy_from_slice(&bytes);
        packet.truncate(bytes.len());
        let packet = packet
            .try_into_ip()
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(iter::once(packet))
    }

    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(1420)
    }
}

/// Turns a UDP packet to port 9 into its reply. Returns false for other
/// packets, which the echo peer drops.
fn reflect_udp(packet: &mut [u8]) -> Result<bool> {
    ensure!(packet.len() >= 28, "short IP packet");
    let (source, destination, address_len, udp) = match packet[0] >> 4 {
        4 => {
            ensure!(packet[0] == 0x45, "expected IPv4 without options");
            // The OS may also send ICMP errors after an application socket closes.
            if packet[9] != 17 {
                return Ok(false);
            }
            (12, 16, 4, 20)
        }
        6 => {
            ensure!(packet.len() >= 48, "short IPv6 packet");
            if packet[6] != 17 {
                return Ok(false);
            }
            (8, 24, 16, 40)
        }
        version => bail!("unexpected IP version {version}"),
    };
    ensure!(
        packet[udp + 2..udp + 4] == 9u16.to_be_bytes(),
        "wrong UDP destination"
    );
    // Swapping addresses and ports preserves both IP and UDP checksum sums.
    for i in 0..address_len {
        packet.swap(source + i, destination + i);
    }
    packet.swap(udp, udp + 2);
    packet.swap(udp + 1, udp + 3);
    Ok(true)
}
