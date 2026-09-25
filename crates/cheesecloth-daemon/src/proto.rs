//! Messages between daemons, carried by the control plane.

use std::net::SocketAddr;

use cheesecloth_core::{
    ClusterId, NodeId, Signed,
    state::{ClusterState, MemberInfo},
};
use cheesecloth_paxos::Reply;
use serde::{Deserialize, Serialize};

use crate::{
    node::{Chosen, proof::Certificate},
    soft::SoftState,
};

// Control-plane service numbers.

/// A CASPaxos request to this node's acceptor (`cheesecloth_paxos::Request`).
/// The answer is a `PaxosAnswer`.
pub const SVC_PAXOS: u8 = 1;
/// "Send me your agreed state, and the transitions from this configuration
/// on." The answer is a `node::proof::Proven`.
pub const SVC_FETCH: u8 = 2;
/// WireGuard hole-punch coordination.
pub const SVC_PUNCH: u8 = 3;
/// "Here is an agreed state" (a `node::proof::Proven`): sent to removed
/// members, and by a leaving member to the acceptors. The answer is the
/// version the receiver holds.
pub const SVC_STATE: u8 = 4;
/// "The value you accepted in this configuration at this ballot is agreed":
/// its `Certificate`.
pub const SVC_COMMIT: u8 = 5;
pub const SVC_VERIFY: u8 = 6;

/// An acceptor's answer to a CASPaxos request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaxosAnswer {
    pub promise: Option<Signed<crate::node::round::Promise>>,
    pub reply: Reply<NodeId, ClusterState>,
    /// The acceptor's signature on the value it accepted, when `reply`
    /// reports one.
    pub share: Option<Certificate>,
    /// With a stale answer: the proof of the state it carries, and the
    /// transitions from the request's configuration on.
    pub stale_proof: Option<(Certificate, Vec<Certificate>)>,
}

/// On the `join` stream, the only one open to non-members.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum JoinMessage {
    /// Redeem an invite. `info` must be signed by the connecting key.
    Redeem {
        secret: [u8; 32],
        info: Signed<MemberInfo>,
    },
    /// Check on a join waiting for approvals.
    Status {
        proposal: cheesecloth_core::ProposalId,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum JoinReply {
    /// The agreed state with the new member in it and a bounded seed of
    /// signed discovery entries. Normal synchronization supplies the rest.
    Joined {
        cluster_id: ClusterId,
        state: Box<Chosen>,
        /// The proof of `state`.
        cert: Box<Certificate>,
        soft: Vec<Signed<SoftState>>,
    },
    Pending {
        proposal: cheesecloth_core::ProposalId,
    },
    Rejected {
        reason: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PunchMessage {
    /// From the designated initiator: "let's punch; you'll see me at
    /// `initiator`, I'll send to you at `responder`".
    Offer {
        id: u64,
        initiator: SocketAddr,
        responder: SocketAddr,
    },
    /// Delivered by a relay at the same moment the initiator is told: send
    /// the NAT opener now.
    Go { id: u64 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PunchReply {
    Accepted,
    Refused(String),
    Done,
}
