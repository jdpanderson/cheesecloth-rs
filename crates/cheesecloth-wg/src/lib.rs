//! The data plane: WireGuard interface management (kernel where possible,
//! userspace otherwise), direct-path planning, and raw-socket NAT openers.
//!
//! Cheesecloth never handles data-plane packets itself. It only configures
//! WireGuard, and sends one-byte "NAT openers" from WireGuard's port when two
//! members behind NAT punch a path (see *WireGuard and NAT traversal* in DESIGN.md).
//! Userspace WireGuard runs inside this process, but on its own runtime.
//!
//! Everything that differs between operating systems is behind the private
//! `sys` module.

pub mod opener;
pub mod plan;
mod runtime;
mod sys;
mod userspace;

use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, SystemTime},
};

use anyhow::Result;
use cheesecloth_core::WgKey;
use gotatun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::sys::{Os, Platform};

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
/// WireGuard's usual MTU: a 1500-byte link less the largest (IPv6) overhead.
const DEFAULT_MTU: u16 = 1420;

pub fn generate_keypair() -> ([u8; 32], WgKey) {
    let private: [u8; 32] = rand::random();
    (private, public_key(&private))
}

pub fn public_key(private: &[u8; 32]) -> WgKey {
    WgKey(PublicKey::from(&StaticSecret::from(*private)).to_bytes())
}

#[derive(Clone, Debug)]
pub struct InterfaceConfig {
    pub name: String,
    pub private_key: [u8; 32],
    pub listen_port: u16,
    /// Each address's prefix is routed into the interface, on every OS.
    pub addresses: Vec<IpNet>,
    pub mtu: Option<u16>,
}

impl InterfaceConfig {
    fn mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_MTU)
    }
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

/// What the reconciler needs from a WireGuard implementation. [`open`]
/// creates the interface. Each call finishes before it returns.
pub trait Backend: Send {
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
    Os::DEFAULT_INTERFACE
}

/// Opens the WireGuard backend: creates the interface, configures it and
/// brings it up.
pub fn open(kind: BackendKind, config: &InterfaceConfig) -> Result<Box<dyn Backend>> {
    Ok(match kind {
        BackendKind::Mock => Box::new(mock::Mock::open(config)),
        BackendKind::Kernel => Os::open_kernel(config)?,
        BackendKind::Userspace => Box::new(userspace::Userspace::open(config)?),
        BackendKind::Auto if !Os::KERNEL_WIREGUARD => Box::new(userspace::Userspace::open(config)?),
        BackendKind::Auto => match Os::open_kernel(config) {
            Ok(backend) => backend,
            Err(e) => {
                tracing::warn!("kernel WireGuard unavailable ({e:#}); using userspace");
                Box::new(userspace::Userspace::open(config)?)
            }
        },
    })
}

/// Retries removal after a daemon restart without creating an interface.
/// Cleanup records name the actual backend, never the automatic selector.
pub fn remove_existing(kind: BackendKind, name: &str) -> Result<()> {
    match kind {
        BackendKind::Mock => Ok(()),
        BackendKind::Kernel => Os::remove_kernel(name),
        BackendKind::Userspace => userspace::Userspace::remove_existing(name),
        BackendKind::Auto => anyhow::bail!("cleanup requires the actual WireGuard backend"),
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

    impl Mock {
        pub fn open(config: &InterfaceConfig) -> Self {
            Self {
                config: Some(config.clone()),
                peers: HashMap::new(),
            }
        }
    }

    impl Backend for Mock {
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
