//! The wire format: stream kinds and headers, and the messages carried on
//! them.
//!
//! Every stream starts with a one-byte stream kind, the 32-byte cluster ID and
//! the sender's clock (ms since the epoch, 8 bytes big-endian). Bidirectional
//! streams carry one request and one response: the responder's clock, then
//! `Result<Vec<u8>, String>`, postcard-encoded.

use std::net::SocketAddr;

use cheesecloth_core::{ClusterId, NodeId, Signed, now_ms};
use serde::{Deserialize, Serialize};

/// Largest encoded request or response accepted on a stream.
pub(crate) const MAX_MESSAGE: usize = 1 << 20;
/// Largest request on the join stream, the only one open to non-members.
pub(crate) const MAX_JOIN_MESSAGE: usize = 64 << 10;
/// Stream header: kind (1), cluster ID (32), sender's clock (8).
pub(crate) const HEADER_LEN: usize = 41;

/// A stream header for a new request.
pub(crate) fn header(kind: Kind, cluster: ClusterId) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0] = kind as u8;
    h[1..33].copy_from_slice(cluster.as_bytes());
    h[33..].copy_from_slice(&now_ms().to_be_bytes());
    h
}

/// What a stream carries. The first byte of every stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Kind {
    /// A member-to-member request on a direct connection (consensus,
    /// fetching agreed states, punch coordination, ...).
    Direct = 1,
    /// Soft state, one way.
    State = 2,
    /// "Pass this signed message on to its destination" (to a relay).
    Forward = 3,
    /// Invite redemption. The only stream open to non-members.
    Join = 4,
    /// "Dial me back at this address" reachability check.
    Probe = 5,
    /// A forwarded message, as delivered by a relay to its destination.
    Deliver = 6,
}

impl Kind {
    pub(crate) fn from_u8(b: u8) -> Option<Kind> {
        Some(match b {
            1 => Kind::Direct,
            2 => Kind::State,
            3 => Kind::Forward,
            4 => Kind::Join,
            5 => Kind::Probe,
            6 => Kind::Deliver,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DirectRequest {
    pub(crate) service: u8,
    pub(crate) body: Vec<u8>,
}

/// A message sent through a relay, signed end to end by its sender.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Envelope {
    pub(crate) cluster: ClusterId,
    pub(crate) from: NodeId,
    pub(crate) to: NodeId,
    /// Unique per sender; its high bits are the sender's clock in ms.
    pub(crate) seq: u64,
    /// For responses: the `seq` of the request.
    pub(crate) reply_to: Option<u64>,
    pub(crate) service: u8,
    pub(crate) body: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ForwardRequest {
    pub(crate) envelope: Signed<Envelope>,
    /// Time the delivery so the message reaches the destination at the same
    /// moment the relay's (empty) response reaches the sender. Used to
    /// synchronise hole punching without synchronised clocks.
    pub(crate) synchronized: bool,
}

/// Why a request didn't produce an answer. Whether it may have been acted on
/// decides whether it's safe to send it again another way.
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    /// The peer answered, with an error.
    #[error("{0}")]
    Remote(String),
    /// The request never reached the peer in full, so the peer can't have
    /// acted on it: safe to try another route.
    #[error("{0:#}")]
    NotSent(anyhow::Error),
    /// The request was sent in full but no answer came. The peer may have
    /// acted on it, so it must not be re-sent another way.
    #[error("no answer: {0:#}")]
    Lost(anyhow::Error),
}

/// A relay's report of what happened to a forwarded message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum ForwardOutcome {
    /// The destination answered (`None` for synchronized deliveries, which
    /// aren't waited for).
    Answered(Option<Signed<Envelope>>),
    /// The destination answered with an error.
    Refused(String),
    /// The message never reached the destination.
    NotDelivered(String),
    /// The message reached the destination, but its answer was lost.
    Lost(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ProbeRequest {
    pub(crate) addr: SocketAddr,
}
