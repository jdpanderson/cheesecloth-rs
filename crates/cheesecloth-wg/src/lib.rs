//! The data plane: WireGuard interface management (kernel where possible,
//! userspace otherwise), direct-path planning, and raw-socket NAT openers.
//!
//! Cheesecloth never handles data-plane packets itself. It only configures
//! WireGuard, and sends one-byte "NAT openers" from WireGuard's port when two
//! members behind NAT punch a path (see *WireGuard and NAT traversal* in DESIGN.md).

pub mod opener;
pub mod plan;

use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use cheesecloth_core::WgKey;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// After a dead path is removed, wait this long before punching again, so NAT
/// state left by WireGuard's retries expires. Just over the 30 s UDP timeout
/// that Linux-based routers use by default.
pub const REPUNCH_QUIET: Duration = Duration::from_secs(35);
/// Delay between the NAT openers and the designated initiator's handshake.
pub const INITIATOR_DELAY: Duration = Duration::from_millis(150);
/// How long a punch may take before it counts as failed.
pub const PUNCH_TIMEOUT: Duration = Duration::from_secs(10);
/// A path with keepalive on that hasn't handshaken for this long is dead.
/// WireGuard rehandshakes every 2 minutes while packets flow and gives up
/// after 90 s of failed attempts.
pub const DEAD_AFTER: Duration = Duration::from_secs(200);

pub fn generate_keypair() -> ([u8; 32], WgKey) {
    let private = defguard_wireguard_rs::key::Key::generate();
    let public = private.public_key();
    (private.as_array(), WgKey(public.as_array()))
}

pub fn public_key(private: &[u8; 32]) -> WgKey {
    WgKey(
        defguard_wireguard_rs::key::Key::new(*private)
            .public_key()
            .as_array(),
    )
}

#[derive(Clone, Debug)]
pub struct InterfaceConfig {
    pub name: String,
    pub private_key: [u8; 32],
    pub listen_port: u16,
    pub addresses: Vec<IpNet>,
    /// Routes to send into the interface (the overlay ranges).
    pub routes: Vec<IpNet>,
    pub mtu: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerConfig {
    pub key: WgKey,
    pub endpoint: Option<SocketAddr>,
    /// Persistent keepalive in seconds; 0 turns it off.
    pub keepalive: u16,
    pub allowed_ips: Vec<IpNet>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerStatus {
    pub key: WgKey,
    pub endpoint: Option<SocketAddr>,
    pub last_handshake: Option<SystemTime>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub keepalive: u16,
}

impl PeerStatus {
    /// Time since the last handshake, if there was one.
    pub fn handshake_age(&self) -> Option<Duration> {
        let t = self.last_handshake?;
        if t == SystemTime::UNIX_EPOCH {
            return None;
        }
        Some(SystemTime::now().duration_since(t).unwrap_or_default())
    }
}

/// What the reconciler needs from a WireGuard implementation.
pub trait Backend: Send {
    /// Creates and configures the interface (without peers).
    fn up(&mut self, config: &InterfaceConfig) -> Result<()>;
    /// Adds or updates a peer.
    fn set_peer(&mut self, peer: &PeerConfig) -> Result<()>;
    fn remove_peer(&mut self, key: &WgKey) -> Result<()>;
    fn status(&self) -> Result<Vec<PeerStatus>>;
    /// Removes the interface.
    fn down(&mut self) -> Result<()>;
    /// "kernel", "userspace" or "mock", for status output.
    fn kind(&self) -> &'static str;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    /// Kernel WireGuard where the OS has it, userspace otherwise.
    Auto,
    Kernel,
    Userspace,
    /// Records configuration without touching the system (tests).
    Mock,
}

impl std::str::FromStr for BackendKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "auto" => Ok(Self::Auto),
            "kernel" => Ok(Self::Kernel),
            "userspace" => Ok(Self::Userspace),
            "mock" => Ok(Self::Mock),
            _ => Err(format!("unknown WireGuard backend {s:?}")),
        }
    }
}

/// The default interface name for this OS.
pub fn default_interface_name() -> &'static str {
    if cfg!(target_os = "macos") {
        // macOS only allows utun interfaces for userspace tunnels.
        "utun77"
    } else if cfg!(target_os = "freebsd") {
        "wg77"
    } else {
        "cheesecloth0"
    }
}

/// Opens the WireGuard backend, creating the interface.
pub fn open(kind: BackendKind, config: &InterfaceConfig) -> Result<Box<dyn Backend>> {
    let mut backend: Box<dyn Backend> = match kind {
        BackendKind::Mock => Box::new(mock::Mock::default()),
        BackendKind::Kernel => Box::new(defguard::Defguard::kernel(&config.name)?),
        BackendKind::Userspace => Box::new(defguard::Defguard::userspace(&config.name)?),
        BackendKind::Auto => {
            if cfg!(target_os = "macos") {
                Box::new(defguard::Defguard::userspace(&config.name)?)
            } else {
                match defguard::Defguard::kernel(&config.name)
                    .and_then(|mut b| b.up(config).map(|_| b))
                {
                    Ok(b) => return Ok(Box::new(b)),
                    Err(e) => {
                        tracing::warn!("kernel WireGuard unavailable ({e:#}); using userspace");
                        Box::new(defguard::Defguard::userspace(&config.name)?)
                    }
                }
            }
        }
    };
    backend.up(config)?;
    Ok(backend)
}

/// Retries removal after a daemon restart without creating an interface.
/// Cleanup records name the actual backend, never the automatic selector.
pub fn remove_existing(kind: BackendKind, name: &str) -> Result<()> {
    if kind == BackendKind::Mock {
        return Ok(());
    }
    let mut backend = match kind {
        BackendKind::Kernel => defguard::Defguard::kernel(name)?,
        BackendKind::Userspace => defguard::Defguard::userspace(name)?,
        _ => anyhow::bail!("cleanup requires the actual WireGuard backend"),
    };
    backend.remove()
}

mod defguard {
    use super::*;
    #[cfg(not(target_os = "macos"))]
    use defguard_wireguard_rs::Kernel;
    #[cfg(not(windows))]
    use defguard_wireguard_rs::Userspace;
    use defguard_wireguard_rs::{
        InterfaceConfiguration, WGApi, WireguardInterfaceApi, key::Key, net::IpAddrMask, peer::Peer,
    };

    pub struct Defguard {
        api: Box<dyn WireguardInterfaceApi + Send>,
        kind: &'static str,
        up: bool,
        name: String,
        // BoringTun panics when a set changes an existing peer, and the panic
        // stops the whole device. For userspace, these are the keys that may
        // be installed, so set_peer removes them first. None for the kernel,
        // which changes peers in place.
        installed: Option<std::collections::HashSet<WgKey>>,
    }

    fn mask(net: &IpNet) -> IpAddrMask {
        IpAddrMask::new(net.addr(), net.prefix_len())
    }

    impl Defguard {
        pub fn kernel(name: &str) -> Result<Self> {
            #[cfg(target_os = "macos")]
            {
                let _ = name;
                anyhow::bail!("macOS has no kernel WireGuard");
            }
            #[cfg(not(target_os = "macos"))]
            Ok(Self {
                api: Box::new(WGApi::<Kernel>::new(name)?),
                kind: "kernel",
                up: false,
                name: name.into(),
                installed: None,
            })
        }

        pub fn userspace(name: &str) -> Result<Self> {
            #[cfg(windows)]
            {
                let _ = name;
                anyhow::bail!("Windows uses WireGuardNT only");
            }
            #[cfg(not(windows))]
            Ok(Self {
                api: Box::new(WGApi::<Userspace>::new(name)?),
                kind: "userspace",
                up: false,
                name: name.into(),
                installed: Some(Default::default()),
            })
        }

        pub(super) fn remove(&mut self) -> Result<()> {
            // A previous removal may have succeeded before the process could
            // record completion. Only confirmed absence makes retries succeed.
            #[cfg(unix)]
            if !interface_exists(&self.name)? {
                self.up = false;
                return Ok(());
            }
            #[cfg(target_os = "macos")]
            {
                // Dropping the owner stops BoringTun and releases its utun.
                // The library's remove_interface retains that owner and clears
                // system-wide DNS settings, which Cheesecloth never configures.
                self.api = Box::new(WGApi::<Userspace>::new(&self.name)?);
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while interface_exists(&self.name)? {
                    anyhow::ensure!(
                        std::time::Instant::now() < deadline,
                        "interface {} is still present",
                        self.name
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            #[cfg(not(target_os = "macos"))]
            self.api.remove_interface()?;
            #[cfg(unix)]
            anyhow::ensure!(
                !interface_exists(&self.name)?,
                "interface {} is still present",
                self.name
            );
            self.up = false;
            Ok(())
        }
    }

    #[cfg(unix)]
    #[allow(unsafe_code, reason = "the standard library has no if_nametoindex")]
    fn interface_exists(name: &str) -> Result<bool> {
        let name = std::ffi::CString::new(name)?;
        // SAFETY: name is a live, NUL-terminated string; this call retains no pointer.
        if unsafe { libc::if_nametoindex(name.as_ptr()) } != 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ENXIO | libc::ENODEV) => Ok(false),
            _ => Err(error.into()),
        }
    }

    impl Backend for Defguard {
        fn up(&mut self, config: &InterfaceConfig) -> Result<()> {
            self.api
                .create_interface()
                .context("creating the WireGuard interface")?;
            // A new device starts with no peers.
            if let Some(installed) = &mut self.installed {
                installed.clear();
            }
            let iface = InterfaceConfiguration {
                name: config.name.clone(),
                prvkey: Key::new(config.private_key).to_lower_hex(),
                addresses: config.addresses.iter().map(mask).collect(),
                port: config.listen_port,
                peers: Vec::new(),
                mtu: config.mtu,
                fwmark: None,
            };
            self.api
                .configure_interface(&iface)
                .context("configuring the WireGuard interface")?;
            // On Linux the interface addresses' prefixes already route the
            // overlay. Elsewhere, add the routes explicitly.
            if !cfg!(target_os = "linux") && !config.routes.is_empty() {
                let mut route_peer = Peer::new(Key::new([0; 32]));
                route_peer.allowed_ips = config.routes.iter().map(mask).collect();
                self.api
                    .configure_peer_routing(&[route_peer])
                    .context("adding overlay routes")?;
            }
            self.up = true;
            Ok(())
        }

        fn set_peer(&mut self, peer: &PeerConfig) -> Result<()> {
            let mut p = Peer::new(Key::new(peer.key.0));
            p.endpoint = peer.endpoint;
            p.persistent_keepalive_interval = Some(peer.keepalive);
            p.allowed_ips = peer.allowed_ips.iter().map(mask).collect();
            // The key stays listed even if the set below fails, because a
            // failed set may still have added the peer.
            if let Some(installed) = &mut self.installed
                && !installed.insert(peer.key)
            {
                self.api.remove_peer(&p.public_key)?;
            }
            self.api.configure_peer(&p)?;
            Ok(())
        }

        fn remove_peer(&mut self, key: &WgKey) -> Result<()> {
            self.api.remove_peer(&Key::new(key.0))?;
            if let Some(installed) = &mut self.installed {
                installed.remove(key);
            }
            Ok(())
        }

        fn status(&self) -> Result<Vec<PeerStatus>> {
            let host = self.api.read_interface_data()?;
            Ok(host
                .peers
                .values()
                .map(|p| PeerStatus {
                    key: WgKey(p.public_key.as_array()),
                    endpoint: p.endpoint,
                    last_handshake: p.last_handshake,
                    rx_bytes: p.rx_bytes,
                    tx_bytes: p.tx_bytes,
                    keepalive: p.persistent_keepalive_interval.unwrap_or(0),
                })
                .collect())
        }

        fn down(&mut self) -> Result<()> {
            if self.up {
                self.remove()?;
            }
            Ok(())
        }

        fn kind(&self) -> &'static str {
            self.kind
        }
    }
}

pub mod mock {
    //! A backend that only records configuration. Every peer with an endpoint
    //! is reported as having just handshaken.

    use super::*;

    #[derive(Default)]
    pub struct Mock {
        pub config: Option<InterfaceConfig>,
        pub peers: HashMap<WgKey, PeerConfig>,
    }

    impl Backend for Mock {
        fn up(&mut self, config: &InterfaceConfig) -> Result<()> {
            self.config = Some(config.clone());
            Ok(())
        }

        fn set_peer(&mut self, peer: &PeerConfig) -> Result<()> {
            self.peers.insert(peer.key, peer.clone());
            Ok(())
        }

        fn remove_peer(&mut self, key: &WgKey) -> Result<()> {
            self.peers.remove(key);
            Ok(())
        }

        fn status(&self) -> Result<Vec<PeerStatus>> {
            Ok(self
                .peers
                .values()
                .map(|p| PeerStatus {
                    key: p.key,
                    endpoint: p.endpoint,
                    last_handshake: p.endpoint.map(|_| SystemTime::now()),
                    rx_bytes: 0,
                    tx_bytes: 0,
                    keepalive: p.keepalive,
                })
                .collect())
        }

        fn down(&mut self) -> Result<()> {
            self.config = None;
            self.peers.clear();
            Ok(())
        }

        fn kind(&self) -> &'static str {
            "mock"
        }
    }
}

#[cfg(test)]
mod tests;
