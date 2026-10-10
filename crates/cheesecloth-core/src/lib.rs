//! Core types for cheesecloth: identities, invite tokens, overlay addressing and
//! the cluster state machine that consensus agrees on.

pub mod addr;
pub mod fs;
mod id;
mod identity;
pub mod state;
pub mod token;

use std::time::SystemTime;

pub use id::{ClusterId, NodeId, ProposalId, WgKey};
pub use identity::{Domain, Identity, Signature, Signed, verify};

/// ALPN for the control plane. The authentication mode (raw public keys) is
/// part of this protocol version.
pub const ALPN: &[u8] = b"cheesecloth/2";
/// Default UDP port for WireGuard.
pub const DEFAULT_WG_PORT: u16 = 51820;
/// Default UDP port for the control plane (QUIC).
pub const DEFAULT_CONTROL_PORT: u16 = 51821;
/// Keepalive used behind NAT: just under the common 30 s UDP NAT timeout.
pub const NAT_KEEPALIVE_SECS: u16 = 25;
/// Keepalive behind NAT when the router maps the WireGuard port. The mapping
/// should not need a keepalive; this long interval tests that in practice.
pub const MAPPED_KEEPALIVE_SECS: u16 = 300;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bad signature")]
    BadSignature,
    #[error("parse error: {0}")]
    Parse(String),
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}
