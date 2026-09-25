//! The local API between the `cheesecloth` CLI and the daemon: one JSON request
//! per line on a Unix domain socket, answered by one JSON response line.

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
};

use anyhow::{Context, Result, anyhow};
use cheesecloth_core::{NodeId, WgKey};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ApiRequest {
    Status,
    Peers,
    Init {
        #[serde(default)]
        strict_security: bool,
        ipv4_range: Option<Ipv4Net>,
    },
    Invite,
    Join {
        token: String,
    },
    Remove {
        node: String,
    },
    Leave {
        /// Stop even if a step of leaving fails.
        #[serde(default)]
        force: bool,
    },
    Pending,
    Approve {
        proposal: cheesecloth_core::ProposalId,
    },
    Reject {
        proposal: cheesecloth_core::ProposalId,
    },
    ConfigGet,
    ConfigSet {
        key: String,
        value: String,
    },
}

/// Every response is `{"ok": ...}` or `{"err": "..."}`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiResponse {
    Ok(serde_json::Value),
    Err(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusView {
    pub security: String,
    pub quorum: usize,
    pub reachable_voters: usize,
    pub changes_paused: bool,
    pub strict_security: bool,
    pub buffer_nodes: u8,
    pub node_id: NodeId,
    pub name: String,
    /// "none", "pending" or "member".
    pub phase: String,
    pub cluster_id: Option<String>,
    pub pending_proposal: Option<cheesecloth_core::ProposalId>,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub relay: bool,
    pub public: bool,
    pub keepalive: u16,
    /// The acceptors of the agreed state.
    pub acceptors: Vec<NodeId>,
    /// The acceptor configuration number.
    pub config: Option<u64>,
    /// The version of the agreed state this node holds.
    pub version: Option<u64>,
    pub members: usize,
    pub control_addr: Option<SocketAddr>,
    pub wg_backend: Option<String>,
    pub wg_interface: String,
    pub wg_port: u16,
    /// Router port mappings, e.g. "wireguard 203.0.113.5:40123".
    #[serde(default)]
    pub port_mappings: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerView {
    pub node_id: NodeId,
    pub name: String,
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    pub relay: bool,
    pub acceptor: bool,
    pub this_node: bool,
    /// A live control-plane connection to this peer.
    pub connected: bool,
    /// Known to be alive: reached through live connections, directly or
    /// through other members. An acceptor that isn't present for 10 minutes
    /// is replaced.
    pub present: bool,
    pub wg_key: WgKey,
    /// How the WireGuard path is set up: lan, public, await, punch, or none.
    pub path: String,
    /// Detail such as "up", "punching", "quiet (retry in 20s)".
    pub path_state: String,
    pub wg_endpoint: Option<SocketAddr>,
    pub handshake_age_secs: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalView {
    pub id: cheesecloth_core::ProposalId,
    /// "join", "remove" or "setting".
    pub kind: String,
    /// The node joining or being removed; for joins, approve this key's fingerprint.
    pub node: Option<NodeId>,
    pub name: Option<String>,
    pub setting: Option<String>,
    pub proposer: NodeId,
    pub approvals: Vec<NodeId>,
    pub needed: u32,
    pub expires_in_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigView {
    pub approvals_required: u32,
    pub acceptors: u8,
    pub strict_security: bool,
    pub buffer_nodes: u8,
    pub catch_up_days: u32,
    pub ipv4_range: Ipv4Net,
    pub ipv6_prefix: String,
}

/// Sends one request to the daemon and returns its typed answer.
pub async fn call<T: DeserializeOwned>(socket: &Path, req: &ApiRequest) -> Result<T> {
    let stream = connect(socket).await?;
    let (read, mut write) = tokio::io::split(stream);
    let mut line = serde_json::to_string(req)?;
    line.push('\n');
    write.write_all(line.as_bytes()).await?;
    write.flush().await?;
    let mut reader = BufReader::new(read);
    let mut resp = String::new();
    reader.read_line(&mut resp).await?;
    if resp.is_empty() {
        return Err(anyhow!("the daemon closed the connection"));
    }
    match serde_json::from_str::<ApiResponse>(&resp)? {
        ApiResponse::Ok(v) => Ok(serde_json::from_value(v)?),
        ApiResponse::Err(e) => Err(anyhow!(e)),
    }
}

#[cfg(unix)]
async fn connect(socket: &Path) -> Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(socket)
        .await
        .with_context(|| {
            format!(
                "can't reach the cheesecloth daemon at {} (is it running, and do you have \
             permission?)",
                socket.display()
            )
        })
}

#[cfg(not(unix))]
async fn connect(_socket: &Path) -> Result<tokio::io::DuplexStream> {
    Err(anyhow!(
        "the local API needs Unix domain sockets on this platform"
    ))
}

/// The answer to `init`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitView {
    pub cluster_id: String,
    pub ipv4_range: Ipv4Net,
}

/// The answer to `invite`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InviteView {
    pub token: String,
    pub expires_at_ms: u64,
}

/// The answer to `join`: joined, or waiting for approvals.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinView {
    pub joined: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<Ipv4Addr>,
    /// The proposal waiting for approvals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal: Option<cheesecloth_core::ProposalId>,
    /// This node's key, for approvers to check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<NodeId>,
}

/// The answer to `leave`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum LeaveView {
    Left {
        remaining_members: usize,
        /// With `force`: the steps of leaving that failed.
        problems: Vec<String>,
    },
    /// Local cancellation; the remote proposal or admission may still exist.
    JoinCancelled {
        cluster_id: String,
        proposal: cheesecloth_core::ProposalId,
    },
}
