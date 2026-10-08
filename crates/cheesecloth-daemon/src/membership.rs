//! Joining and leaving: `init`, `join` (and waiting for approvals), `leave`,
//! and starting or tearing down the node.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use cheesecloth_core::{
    ClusterId, Domain,
    addr::random_ipv4_range,
    now_ms,
    state::{ClusterState, Command, CommandBody, MemberInfo, Outcome, Request, Settings},
    token::{InviteToken, TokenPeer},
};
use cheesecloth_net::CallError;
use ipnet::Ipv4Net;
use pnyx::Acceptor;
use tracing::{info, warn};

use crate::{
    Daemon, Phase, RelayMode,
    api::{InitView, JoinView, LeaveView},
    files::{Cleanup, ClusterFile, PendingJoin},
    local,
    node::{Chosen, Node, StoredAcceptor, proof},
    proto::{JoinMessage, JoinReply},
};

/// How often a joiner asks the same member again after losing its answer.
const JOIN_LOST_RETRIES: u32 = 3;

impl Daemon {
    /// Starts the node from the cluster files in the state directory.
    pub(crate) fn become_member(self: &Arc<Self>, cluster_id: ClusterId) -> Result<Arc<Node>> {
        let node = Node::start(
            self.opts.clone(),
            cluster_id,
            self.identity.clone(),
            self.wg_private,
            self.net.clone(),
            self.files.clone(),
        )?;
        *self.phase.write() = Phase::Member(node.clone());
        node.spawn_loops();
        let daemon = Arc::downgrade(self);
        let n = node.clone();
        let task = tokio::spawn(async move {
            n.removed.notified().await;
            let Some(daemon) = daemon.upgrade() else {
                return;
            };
            let _op = daemon.op.lock().await;
            if let Err(e) = daemon.teardown(&n).await {
                warn!("leaving the cluster: {e:#}");
            }
        });
        if let Some(previous) = self.removal_watch.lock().replace(task) {
            previous.abort();
        }
        Ok(node)
    }

    pub(crate) async fn stop_removal_watch(&self) {
        let task = self.removal_watch.lock().take();
        if let Some(task) = task {
            task.abort();
            if let Err(e) = task.await
                && !e.is_cancelled()
            {
                warn!("removal watcher failed: {e}");
            }
        }
    }

    /// Stops member work, then records cleanup before touching the interface
    /// or deleting state. An error leaves a retryable stopping phase.
    pub(crate) async fn teardown(&self, node: &Arc<Node>) -> Result<()> {
        self.stop_node(node, true).await
    }

    pub(crate) async fn stop_node(&self, node: &Arc<Node>, forget_cluster: bool) -> Result<()> {
        let still_current = matches!(&*self.phase.read(), Phase::Member(n) if Arc::ptr_eq(n, node));
        if !still_current {
            return Ok(());
        }
        let cleanup = Cleanup {
            cluster_id: node.cluster_id,
            interface: node.opts.interface.clone(),
            backend: None, // Captured after all member work has drained.
            forget_cluster,
            remaining_members: node
                .agreed()
                .state()
                .members
                .keys()
                .filter(|id| **id != node.me)
                .count(),
        };
        *self.phase.write() = Phase::Stopping {
            cleanup,
            node: Some(node.clone()),
            error: None,
        };
        self.finish_cleanup().await
    }

    pub(crate) async fn finish_cleanup(&self) -> Result<()> {
        let (mut cleanup, node) = match &*self.phase.read() {
            Phase::Stopping { cleanup, node, .. } => (cleanup.clone(), node.clone()),
            _ => return Ok(()),
        };
        let result = async {
            if let Some(node) = &node {
                node.quiesce().await;
                cleanup.backend = node
                    .wg
                    .lock()
                    .backend_kind()
                    .map(str::parse)
                    .transpose()
                    .map_err(anyhow::Error::msg)?;
                if let Phase::Stopping { cleanup: saved, .. } = &mut *self.phase.write() {
                    *saved = cleanup.clone();
                }
            }
            self.files.save_cleanup(&cleanup)?;
            if let Some(node) = node {
                node.stop().await?;
            } else if let Some(kind) = cleanup.backend {
                cheesecloth_wg::remove_existing(kind, &cleanup.interface)?;
            }
            self.files.finish_cleanup(cleanup.forget_cluster)?;
            Ok(())
        }
        .await;
        match &result {
            Ok(()) => {
                *self.phase.write() = if cleanup.forget_cluster {
                    Phase::None
                } else {
                    Phase::Stopped
                };
                info!("local cleanup complete");
            }
            Err(e) => {
                if let Phase::Stopping { error, .. } = &mut *self.phase.write() {
                    *error = Some(format!(
                        "local cleanup pending; retry `cheesecloth leave`: {e:#}"
                    ));
                }
            }
        }
        result
    }

    /// Our member record, as offered at init or join.
    fn initial_info(&self) -> MemberInfo {
        let advertised: Vec<SocketAddr> = self
            .opts
            .advertise
            .iter()
            .map(|ip| SocketAddr::new(*ip, self.opts.listen_port))
            .collect();
        let ifaces = self.opts.scan_interfaces(&[]);
        let control = local::control_addrs(
            &advertised,
            self.opts.bind_ip,
            self.opts.listen_port,
            &ifaces,
        );
        MemberInfo {
            node_id: self.node_id(),
            wg_key: cheesecloth_wg::public_key(&self.wg_private),
            name: self.opts.name.clone(),
            control_addrs: control,
            wg_port: self.opts.wg_port,
            relay: self.opts.relay == RelayMode::Always,
        }
    }

    // ------------------------------------------------------------ init

    pub async fn init(self: &Arc<Self>, ipv4_range: Option<Ipv4Net>) -> Result<InitView> {
        self.init_with_security(ipv4_range, false).await
    }

    pub async fn init_with_security(
        self: &Arc<Self>,
        ipv4_range: Option<Ipv4Net>,
        strict_security: bool,
    ) -> Result<InitView> {
        let _op = self.op.lock().await;
        if !matches!(&*self.phase.read(), Phase::None) {
            bail!("this node is already in a cluster");
        }
        let range = match ipv4_range {
            Some(r) => r.trunc(),
            None => random_ipv4_range(&local::existing_networks())
                .context("no free /24 in 100.64.0.0/10")?,
        };
        let nonce: [u8; 16] = rand::random();
        let founder = self.identity.seal(Domain::MemberInfo, &self.initial_info());
        let genesis = self.identity.seal(
            Domain::Command,
            &CommandBody {
                cluster_id: None,
                issued_at_ms: now_ms(),
                command: Command::Genesis {
                    nonce,
                    settings: Settings {
                        strict_security,
                        ..Settings::new(range)
                    },
                    founder,
                },
            },
        );
        let cluster_id = ClusterId::of_genesis(&genesis);
        // The first state needs no agreement: this node is the only member
        // and the only acceptor.
        let mut state = ClusterState::default();
        match state.apply(&Request {
            at_ms: now_ms(),
            command: genesis,
        }) {
            Ok(Outcome::Genesis { cluster_id: c }) if c == cluster_id => {}
            other => bail!("genesis failed: {other:?}"),
        }
        let first = Chosen::genesis(self.node_id(), state);
        let cert = proof::genesis(&self.identity, cluster_id, &first);
        self.files.delete_cluster()?;
        StoredAcceptor::create(self.files.acceptor(), Acceptor::genesis(first, cert))?;
        self.files.save_cluster(&ClusterFile {
            cluster_id,
            pending: None,
        })?;
        self.become_member(cluster_id)?;
        info!(cluster = %cluster_id.short(), %range, "created a new cluster");
        Ok(InitView {
            cluster_id: cluster_id.to_string(),
            ipv4_range: range,
        })
    }

    // ------------------------------------------------------------ join

    pub async fn join(self: &Arc<Self>, token: &str) -> Result<JoinView> {
        let _op = self.op.lock().await;
        if !matches!(&*self.phase.read(), Phase::None) {
            bail!("this node is already in a cluster (or waiting to join one)");
        }
        let token: InviteToken = token.parse()?;
        let info = self.identity.seal(Domain::MemberInfo, &self.initial_info());
        let msg = postcard::to_stdvec(&JoinMessage::Redeem {
            secret: token.secret,
            info,
        })?;
        let mut errors = Vec::new();
        let mut reply = None;
        'peers: for peer in &token.peers {
            let mut lost = 0;
            loop {
                match self.net.join(token.cluster_id, peer, &msg).await {
                    Ok(bytes) => {
                        reply = Some(postcard::from_bytes::<JoinReply>(&bytes)?);
                        break 'peers;
                    }
                    // The member answered: the invite has been redeemed (and burnt).
                    Err(CallError::Remote(e)) => bail!("join refused: {e}"),
                    // It never got the request: try the next member.
                    Err(CallError::NotSent(e)) => {
                        errors.push(format!("{}: {e:#}", peer.node_id.short()));
                        continue 'peers;
                    }
                    // It may have acted on it. Ask the same member again: a
                    // redemption that went through is answered as such.
                    Err(CallError::Lost(e)) => {
                        lost += 1;
                        if lost >= JOIN_LOST_RETRIES {
                            bail!(
                                "no answer from {} after it received the join request ({e:#}); \
                                 the invite may have been used. Check with a member \
                                 (`cheesecloth peers` or `cheesecloth pending`) before asking \
                                 for a new invite",
                                peer.node_id.short()
                            );
                        }
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
            }
        }
        let reply =
            reply.ok_or_else(|| anyhow!("couldn't reach any member: {}", errors.join("; ")))?;
        self.finish_join(token.cluster_id, reply, &token.peers)
    }

    fn finish_join(
        self: &Arc<Self>,
        cluster_id: ClusterId,
        reply: JoinReply,
        peers: &[TokenPeer],
    ) -> Result<JoinView> {
        match reply {
            JoinReply::Joined {
                cluster_id: c,
                state,
                cert,
                soft,
            } => {
                let st = state.state();
                if c != cluster_id || st.cluster_id != Some(cluster_id) {
                    bail!("joined an unexpected cluster");
                }
                let ipv4 = st
                    .members
                    .get(&self.node_id())
                    .context("the member's state doesn't list this node")?
                    .ipv4;
                st.verify_members()?;
                // This node trusts the member that redeemed its invite, as it
                // trusts the state: the proof need only be complete.
                cert.check_config(&cert.header.config, false)
                    .context("checking the proof of the state")?;
                if cert.header.cluster_id != cluster_id || !cert.proves(&state) {
                    bail!("the proof is for another state");
                }
                self.files.delete_consensus()?;
                StoredAcceptor::create(
                    self.files.acceptor(),
                    Acceptor::with_learned(*state, *cert),
                )?;
                self.files.save_cluster(&ClusterFile {
                    cluster_id,
                    pending: None,
                })?;
                let node = self.become_member(cluster_id)?;
                node.take_soft(soft);
                let ipv4 = Some(ipv4);
                info!(cluster = %cluster_id.short(), ?ipv4, "joined the cluster");
                Ok(JoinView {
                    joined: true,
                    cluster_id: Some(cluster_id.to_string()),
                    ipv4,
                    proposal: None,
                    node_id: None,
                })
            }
            JoinReply::Pending { proposal } => {
                let pending = PendingJoin {
                    proposal,
                    peers: peers.to_vec(),
                };
                self.files.save_cluster(&ClusterFile {
                    cluster_id,
                    pending: Some(pending.clone()),
                })?;
                self.begin_pending(cluster_id, pending);
                info!(%proposal, "join is waiting for approvals");
                Ok(JoinView {
                    joined: false,
                    cluster_id: None,
                    ipv4: None,
                    proposal: Some(proposal),
                    node_id: Some(self.node_id()),
                })
            }
            JoinReply::Rejected { reason } => bail!("join rejected: {reason}"),
        }
    }

    /// Starts one attempt. Pointer identity distinguishes it even from a later
    /// attempt to join the same cluster using the same proposal.
    pub(crate) fn begin_pending(self: &Arc<Self>, cluster_id: ClusterId, pending: PendingJoin) {
        let pending = Arc::new(pending);
        *self.phase.write() = Phase::Pending {
            cluster_id,
            pending: pending.clone(),
        };
        let daemon = Arc::downgrade(self);
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let Some(daemon) = daemon.upgrade() else {
                    return;
                };
                if !daemon.is_pending(&pending) {
                    return;
                }
                let msg = postcard::to_stdvec(&JoinMessage::Status {
                    proposal: pending.proposal,
                })
                .expect("serializable");
                for peer in &pending.peers {
                    let Ok(bytes) = daemon.net.join(cluster_id, peer, &msg).await else {
                        continue;
                    };
                    let Ok(reply) = postcard::from_bytes::<JoinReply>(&bytes) else {
                        continue;
                    };
                    match daemon.pending_reply(cluster_id, &pending, reply).await {
                        Ok(true) => return,
                        Ok(false) => break,
                        Err(e) => warn!("checking the pending join: {e:#}"),
                    }
                }
            }
        });
        if let Some(previous) = self.pending_poll.lock().replace(task) {
            previous.abort();
        }
    }

    fn is_pending(&self, attempt: &Arc<PendingJoin>) -> bool {
        matches!(&*self.phase.read(), Phase::Pending { pending, .. } if Arc::ptr_eq(pending, attempt))
    }

    /// Returns true when this poller is finished, including a stale response.
    /// The operation lock orders admission, rejection and local cancellation.
    async fn pending_reply(
        self: &Arc<Self>,
        cluster_id: ClusterId,
        attempt: &Arc<PendingJoin>,
        reply: JoinReply,
    ) -> Result<bool> {
        let _op = self.op.lock().await;
        if !self.is_pending(attempt) {
            return Ok(true);
        }
        match reply {
            JoinReply::Pending { .. } => Ok(false),
            JoinReply::Joined { .. } => {
                self.finish_join(cluster_id, reply, &attempt.peers)?;
                Ok(true)
            }
            JoinReply::Rejected { reason } => {
                self.files.delete_pending()?;
                *self.phase.write() = Phase::None;
                warn!("join rejected: {reason}");
                Ok(true)
            }
        }
    }

    /// Called under the operation lock. Aborting and awaiting also stops a
    /// network request or a response waiting for that lock.
    pub(crate) async fn stop_pending_poll(&self) {
        let task = self.pending_poll.lock().take();
        if let Some(task) = task {
            task.abort();
            if let Err(e) = task.await
                && !e.is_cancelled()
            {
                warn!("pending join task failed: {e}");
            }
        }
    }

    // ----------------------------------------------------------- leave

    /// Cancels a pending join locally, or leaves the cluster (see `Node::leave`).
    /// With `force`, a member stops even if a step fails and reports the errors.
    pub async fn leave(self: &Arc<Self>, force: bool) -> Result<LeaveView> {
        let _op = self.op.lock().await;
        let pending = match &*self.phase.read() {
            Phase::Pending {
                cluster_id,
                pending,
            } => Some((*cluster_id, pending.clone())),
            _ => None,
        };
        if let Some((cluster_id, pending)) = pending {
            self.files
                .delete_pending()
                .context("cancelling the pending join; retry `cheesecloth leave`")?;
            *self.phase.write() = Phase::None;
            self.stop_pending_poll().await;
            info!(%pending.proposal, "pending join cancelled locally");
            return Ok(LeaveView::JoinCancelled {
                cluster_id: cluster_id.to_string(),
                proposal: pending.proposal,
            });
        }
        let stopping = match &*self.phase.read() {
            Phase::Stopping { cleanup, .. } => {
                if !cleanup.forget_cluster {
                    bail!("shutdown cleanup pending; restart the daemon to retry");
                }
                Some(cleanup.remaining_members)
            }
            _ => None,
        };
        if let Some(remaining_members) = stopping {
            self.stop_removal_watch().await;
            self.finish_cleanup().await?;
            return Ok(LeaveView::Left {
                remaining_members,
                problems: Vec::new(),
            });
        }
        let node = self.require_node()?;
        let others = node.agreed().state().members.len().saturating_sub(1);
        let mut problems = if others > 0 {
            node.leave(force).await.context(
                "this node hasn't stopped; run `cheesecloth leave` again. If other members \
                 already count it as removed, they refuse it, and only \
                 `cheesecloth leave --force` stops it",
            )?
        } else {
            Vec::new()
        };
        self.stop_removal_watch().await;
        if let Err(e) = self.teardown(&node).await {
            if !force {
                return Err(e).context("local cleanup pending; retry `cheesecloth leave`");
            }
            problems.push(format!(
                "local cleanup pending; retry `cheesecloth leave`: {e:#}"
            ));
        }
        Ok(LeaveView::Left {
            remaining_members: others,
            problems,
        })
    }
}

#[cfg(test)]
mod tests;
