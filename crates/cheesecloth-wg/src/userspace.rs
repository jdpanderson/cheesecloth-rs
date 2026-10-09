//! Userspace WireGuard: GotaTun inside this process, reading and writing a
//! TUN device. It works the same way on every supported OS.
//!
//! One task owns the GotaTun device and applies commands from the backend
//! in order. It also watches for the fatal I/O errors that stop the device,
//! and reports them from then on.

use std::{
    io, iter,
    sync::Arc,
    thread,
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, Result, anyhow, bail};
use cheesecloth_core::WgKey;
use gotatun::{
    device::{Device, DeviceBuilder, Peer},
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
    udp::socket::UdpSocketFactory,
    x25519::{PublicKey, StaticSecret},
};
use ipnetwork::IpNetwork;
use tokio::sync::{mpsc, oneshot};

use crate::{
    Backend, InterfaceConfig, PeerConfig, PeerStatus,
    runtime::Runtime,
    sys::{Os, Platform},
};

/// How long the OS may take to delete a closed TUN device.
const REMOVAL_TIMEOUT: Duration = Duration::from_secs(5);

type Transports = (UdpSocketFactory, Tun, Tun);

pub struct Userspace {
    name: String,
    /// `None` once the interface is down.
    running: Option<Running>,
}

struct Running {
    commands: mpsc::Sender<Command>,
    runtime: Runtime,
}

enum Command {
    SetPeer(Box<Peer>, oneshot::Sender<Result<()>>),
    RemovePeer(PublicKey, oneshot::Sender<Result<()>>),
    Status(oneshot::Sender<Result<Vec<PeerStatus>>>),
    /// Stops the device and ends the task.
    Stop(oneshot::Sender<Result<()>>),
}

impl Userspace {
    /// Creates the TUN device and starts WireGuard on it.
    pub fn open(config: &InterfaceConfig) -> Result<Self> {
        let runtime = Runtime::new()?;
        let name = config.name.clone();
        let addresses = config.addresses.clone();
        let mtu = config.mtu();
        let private_key = StaticSecret::from(config.private_key);
        let port = config.listen_port;
        let commands = runtime.run(async move {
            let tun = Tun {
                device: Arc::new(Os::create_tun(&name, &addresses, mtu)?),
                mtu,
            };
            let device = DeviceBuilder::new()
                .with_default_udp()
                .with_ip(tun)
                .with_listen_port(port)
                .build()
                .await?;
            // Setting the key binds the listen port. A device built without
            // peers binds it at no other time.
            device.set_private_key(private_key).await?;
            let (commands, receiver) = mpsc::channel(1);
            tokio::spawn(serve(device, receiver));
            anyhow::Ok(commands)
        })??;
        Ok(Self {
            name: config.name.clone(),
            running: Some(Running { commands, runtime }),
        })
    }

    fn running(&self) -> Result<&Running> {
        self.running.as_ref().context("the interface is down")
    }

    /// Confirms that the TUN device of an earlier run is gone. It closed
    /// when that process ended, so one that still exists is not ours.
    pub fn remove_existing(name: &str) -> Result<()> {
        if Os::interface_exists(name)? {
            bail!("interface {name} still exists; another program may own it");
        }
        Ok(())
    }
}

impl Running {
    /// Sends a command to the device's task and waits for its reply.
    fn call<T: Send + 'static>(
        &self,
        command: impl FnOnce(oneshot::Sender<Result<T>>) -> Command,
    ) -> Result<T> {
        let (reply, response) = oneshot::channel();
        let command = command(reply);
        let commands = self.commands.clone();
        self.runtime.run(async move {
            let stopped = || anyhow!("the WireGuard device has stopped");
            commands.send(command).await.map_err(|_| stopped())?;
            response.await.map_err(|_| stopped())?
        })?
    }
}

impl Backend for Userspace {
    fn set_peer(&mut self, peer: &PeerConfig) -> Result<()> {
        let mut p = Peer::new(PublicKey::from(peer.key.0));
        p.endpoint = peer.endpoint;
        p.keepalive = (peer.keepalive != 0).then_some(peer.keepalive);
        p.allowed_ips = peer
            .allowed_ips
            .iter()
            .map(|net| {
                IpNetwork::new(net.addr(), net.prefix_len()).expect("an IpNet prefix is valid")
            })
            .collect();
        self.running()?
            .call(|reply| Command::SetPeer(Box::new(p), reply))
    }

    fn remove_peer(&mut self, key: &WgKey) -> Result<()> {
        let key = PublicKey::from(key.0);
        self.running()?
            .call(|reply| Command::RemovePeer(key, reply))
    }

    fn status(&self) -> Result<Vec<PeerStatus>> {
        self.running()?.call(Command::Status)
    }

    /// Succeeds only once the interface is confirmed gone, so the caller can
    /// retry until it is.
    fn down(&mut self) -> Result<()> {
        if let Some(running) = self.running.take() {
            if let Err(e) = running.call(Command::Stop) {
                tracing::warn!("stopping userspace WireGuard: {e:#}");
            }
            // Dropping the runtime drops every task, which closes the TUN device.
            drop(running);
        }
        let deadline = Instant::now() + REMOVAL_TIMEOUT;
        while Os::interface_exists(&self.name)? {
            if Instant::now() >= deadline {
                bail!("interface {} is still present", self.name);
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "userspace"
    }
}

/// The task that owns the device. It ends when the device is stopped or the
/// backend is gone.
async fn serve(mut device: Device<Transports>, mut commands: mpsc::Receiver<Command>) {
    let mut failed = false;
    loop {
        tokio::select! {
            () = device.wait(), if !failed => {
                tracing::error!("userspace WireGuard stopped after an I/O error");
                failed = true;
            }
            command = commands.recv() => match command {
                None => break,
                Some(Command::SetPeer(peer, reply)) => {
                    let result = match healthy(failed) {
                        Ok(()) => device.add_or_update_peer(*peer).await.map_err(Into::into),
                        Err(e) => Err(e),
                    };
                    let _ = reply.send(result);
                }
                Some(Command::RemovePeer(key, reply)) => {
                    let result = match healthy(failed) {
                        // Removing an absent peer is not an error, as with the kernel.
                        Ok(()) => device.remove_peer(&key).await.map(drop).map_err(Into::into),
                        Err(e) => Err(e),
                    };
                    let _ = reply.send(result);
                }
                Some(Command::Status(reply)) => {
                    let result = match healthy(failed) {
                        Ok(()) => Ok(device.peers().await.into_iter().map(status).collect()),
                        Err(e) => Err(e),
                    };
                    let _ = reply.send(result);
                }
                Some(Command::Stop(reply)) => {
                    device.stop().await;
                    let _ = reply.send(Ok(()));
                    return;
                }
            },
        }
    }
    device.stop().await;
}

fn healthy(failed: bool) -> Result<()> {
    if failed {
        bail!("userspace WireGuard stopped after an I/O error");
    }
    Ok(())
}

fn status(p: gotatun::device::configure::PeerStats) -> PeerStatus {
    PeerStatus {
        key: WgKey(p.peer.public_key.to_bytes()),
        endpoint: p.peer.endpoint,
        last_handshake: p
            .stats
            .last_handshake
            .and_then(|age| SystemTime::now().checked_sub(age)),
        rx_bytes: p.stats.rx_bytes as u64,
        tx_bytes: p.stats.tx_bytes as u64,
        keepalive: p.peer.keepalive.unwrap_or(0),
    }
}

/// A tun-rs device as GotaTun's packet source and sink.
#[derive(Clone)]
struct Tun {
    device: Arc<tun_rs::AsyncDevice>,
    /// Set when the device is created and never changed.
    mtu: u16,
}

impl IpSend for Tun {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.device.send(&packet.into_bytes()).await?;
        Ok(())
    }
}

impl IpRecv for Tun {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let mut packet = pool.get();
        let size = self.device.recv(&mut packet).await?;
        packet.truncate(size);
        let packet = packet
            .try_into_ip()
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(iter::once(packet))
    }

    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(self.mtu)
    }
}
