//! Real utun and encrypted packet tests. Run only on a disposable Mac with root.
#![cfg(target_os = "macos")]

use std::{
    ffi::CString,
    io,
    net::{SocketAddr, UdpSocket},
    path::Path,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use cheesecloth_wg::{Backend, BackendKind, InterfaceConfig, PeerConfig, generate_keypair};
use defguard_boringtun::noise::{Tunn, TunnResult};

const LOCAL_V4: &str = "192.0.2.1";
const REMOTE_V4: &str = "192.0.2.2";
const LOCAL_V6: &str = "2001:db8:cc::1";
const REMOTE_V6: &str = "2001:db8:cc::2";

#[test]
fn real_userspace_tunnel() -> Result<()> {
    ensure!(is_root(), "this test requires root");
    let dns_before = dns_settings()?;
    let name = (200..256)
        .map(|i| format!("utun{i}"))
        .find(|name| {
            !interface_exists(name)
                && !Path::new(&format!("/var/run/wireguard/{name}.sock")).exists()
        })
        .context("no unused test interface")?;
    let (private, public) = generate_keypair();
    let (remote_private, remote_public) = generate_keypair();
    let remote = EchoPeer::start(Tunn::new(
        remote_private.into(),
        public.0.into(),
        None,
        None,
        1,
        None,
    ))?;
    let config = InterfaceConfig {
        name: name.clone(),
        private_key: private,
        listen_port: 0,
        addresses: vec![
            format!("{LOCAL_V4}/32").parse()?,
            format!("{LOCAL_V6}/128").parse()?,
        ],
        routes: vec!["192.0.2.0/24".parse()?, "2001:db8:cc::/64".parse()?],
        mtu: Some(1280),
    };
    let peer = PeerConfig {
        key: remote_public,
        endpoint: Some(remote.endpoint),
        keepalive: 0,
        allowed_ips: vec![
            format!("{REMOTE_V4}/32").parse()?,
            format!("{REMOTE_V6}/128").parse()?,
        ],
    };

    // Reuse the same name and addresses to catch leaked interfaces or routes.
    for kind in [BackendKind::Auto, BackendKind::Userspace] {
        println!("checking {kind:?} on {name}");
        let mut interface = Interface(cheesecloth_wg::open(kind, &config)?);
        let backend = &mut interface.0;
        ensure!(backend.kind() == "userspace", "wrong backend selected");
        ensure!(
            command("/sbin/ifconfig", &[&name])?.contains("mtu 1280"),
            "MTU was not applied"
        );
        for address in [REMOTE_V4, REMOTE_V6] {
            ensure!(
                route_interface(address)? == name,
                "missing route to {address}"
            );
        }
        backend.set_peer(&peer)?;
        exchange(LOCAL_V4, REMOTE_V4)?;
        exchange(LOCAL_V6, REMOTE_V6)?;
        let status = backend.status()?;
        ensure!(
            status.len() == 1 && status[0].key == peer.key,
            "incorrect peers: {status:?}"
        );
        ensure!(
            status[0].handshake_age().is_some(),
            "no WireGuard handshake"
        );
        ensure!(
            status[0].rx_bytes > 0 && status[0].tx_bytes > 0,
            "no encrypted traffic"
        );

        backend.remove_peer(&peer.key)?;
        ensure!(
            backend.status()?.is_empty(),
            "removed peer is still present"
        );
        for (local, remote) in [(LOCAL_V4, REMOTE_V4), (LOCAL_V6, REMOTE_V6)] {
            let socket = application_socket(local, remote)?;
            socket.send(b"removed peer must not receive this")?;
            let error = socket
                .recv(&mut [0; 256])
                .expect_err("removed peer still receives traffic");
            ensure!(is_timeout(&error), "unexpected receive error: {error}");
        }
        backend.set_peer(&peer)?;
        exchange(LOCAL_V4, REMOTE_V4)?;
        exchange(LOCAL_V6, REMOTE_V6)?;
        backend.down().context("removing the interface")?;
        backend.down().context("repeating interface removal")?;
        ensure!(!interface_exists(&name), "interface survived removal");
        ensure!(
            !Path::new(&format!("/var/run/wireguard/{name}.sock")).exists(),
            "control socket survived removal"
        );
        ensure!(
            !command("/usr/sbin/netstat", &["-rn"])?
                .split_whitespace()
                .any(|field| field == name),
            "route survived removal"
        );
        cheesecloth_wg::remove_existing(BackendKind::Userspace, &name)?;
    }
    remote.finish()?;
    check_nat_opener()?;
    ensure!(dns_settings()? == dns_before, "DNS settings changed");
    Ok(())
}

// Keep cleanup active when an assertion or packet exchange fails.
struct Interface(Box<dyn Backend>);

impl Drop for Interface {
    fn drop(&mut self) {
        if let Err(error) = self.0.down() {
            eprintln!("interface cleanup failed: {error:#}");
        }
    }
}

#[allow(unsafe_code, reason = "the standard library has no geteuid")]
fn is_root() -> bool {
    // SAFETY: geteuid has no arguments or side effects.
    unsafe { libc::geteuid() == 0 }
}

#[allow(unsafe_code, reason = "the standard library has no if_nametoindex")]
fn interface_exists(name: &str) -> bool {
    let name = CString::new(name).unwrap();
    // SAFETY: name is a live NUL-terminated string.
    unsafe { libc::if_nametoindex(name.as_ptr()) != 0 }
}

fn command(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program).args(args).output()?;
    ensure!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn route_interface(address: &str) -> Result<String> {
    let family = if address.contains(':') {
        "-inet6"
    } else {
        "-inet"
    };
    command("/sbin/route", &["-n", "get", family, address])?
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("interface:")
                .map(|s| s.trim().to_owned())
        })
        .context("route has no interface")
}

fn dns_settings() -> Result<Vec<String>> {
    let services = command("/usr/sbin/networksetup", &["-listallnetworkservices"])?;
    let mut settings = Vec::new();
    for service in services.lines().skip(1) {
        let service = service.trim_start_matches('*');
        settings.push(service.to_owned());
        for flag in ["-getdnsservers", "-getsearchdomains"] {
            settings.push(command("/usr/sbin/networksetup", &[flag, service])?);
        }
    }
    Ok(settings)
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

fn application_socket(local: &str, remote: &str) -> Result<UdpSocket> {
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

fn exchange(local: &str, remote: &str) -> Result<()> {
    let socket = application_socket(local, remote)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    // A substantial payload tests packet transfer as well as handshakes.
    let payload = [0xa5; 1024];
    socket.send(&payload)?;
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

fn check_nat_opener() -> Result<()> {
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

// This peer owns no local overlay address or interface. Every reply must pass
// through utun and WireGuard; the OS cannot deliver it by a local loopback route.
struct EchoPeer {
    endpoint: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<()>>>,
}

impl EchoPeer {
    fn start(mut tunnel: Tunn) -> Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        let endpoint = socket.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = thread::spawn(move || {
            let mut input = [0; 65536];
            let mut output = [0; 65536];
            let mut encrypted = [0; 65536];
            while !stopped.load(Ordering::Relaxed) {
                let (size, sender) = match socket.recv_from(&mut input) {
                    Ok(packet) => packet,
                    Err(error) if is_timeout(&error) => continue,
                    Err(error) => return Err(error.into()),
                };
                let mut result = tunnel.decapsulate(Some(sender.ip()), &input[..size], &mut output);
                loop {
                    match result {
                        TunnResult::Done => break,
                        TunnResult::Err(error) => bail!("WireGuard echo peer: {error:?}"),
                        TunnResult::WriteToNetwork(packet) => {
                            socket.send_to(packet, sender)?;
                        }
                        TunnResult::WriteToTunnelV4(packet, _)
                        | TunnResult::WriteToTunnelV6(packet, _) => {
                            if reflect_udp(packet)? {
                                match tunnel.encapsulate(packet, &mut encrypted) {
                                    TunnResult::WriteToNetwork(packet) => {
                                        socket.send_to(packet, sender)?;
                                    }
                                    other => bail!("could not encrypt reply: {other:?}"),
                                }
                            }
                        }
                    }
                    result = tunnel.decapsulate(None, &[], &mut output);
                }
            }
            Ok(())
        });
        Ok(Self {
            endpoint,
            stop,
            worker: Some(worker),
        })
    }

    fn finish(mut self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        self.worker
            .take()
            .unwrap()
            .join()
            .map_err(|_| anyhow::anyhow!("echo peer panicked"))?
    }
}

impl Drop for EchoPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(Ok(())) => {}
                result => eprintln!("echo peer failed: {result:?}"),
            }
        }
    }
}

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
