//! A running cluster member: consensus, soft state, reachability and the
//! loops that keep them up to date.
//!
//! - `view`: what this node knows about the members.
//! - `consensus`: agreeing on changes, and learning agreed states.
//! - `acceptors`: choosing the acceptor set.
//! - `join`: the member side of invite redemption.
//! - `softsync`: publishing and spreading soft state.
//! - `reach`: reachability, the relay role and connections.
//! - `problem`: reporting lasting failures of repeated work.
//! - `proof`: proof that a state was agreed.

mod acceptors;
mod consensus;
mod join;
#[cfg(test)]
mod lifecycle_tests;
mod problem;
pub mod proof;
mod reach;
pub(crate) mod round;
mod softsync;
#[cfg(test)]
mod tests;
mod view;

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64},
    },
    time::Instant,
};

use anyhow::{Context, Result, ensure};
use cheesecloth_core::{ClusterId, Identity, NodeId, WgKey, state::ClusterState};
use cheesecloth_net::{BoxFuture, Net};
use parking_lot::Mutex;
use pnyx::{Proposer, store::Stored};
use tokio::sync::{Notify, watch};

pub use reach::LocalFacts;

use crate::{
    Options, RelayMode,
    files::Files,
    lifetime,
    proto::*,
    soft::{SoftState, SoftTable},
    wgrec::WgState,
};

/// An agreed cluster state, with its version and acceptor set.
pub type Agreed = pnyx::Agreed<NodeId, ClusterState>;
/// An agreed cluster state, with the ballot it was accepted at.
pub type Chosen = pnyx::Chosen<NodeId, ClusterState>;
/// A node's acceptor state and proof of its latest learned value, saved to disk.
pub type StoredAcceptor = Stored<NodeId, ClusterState, proof::Certificate>;

/// A cluster member.
///
/// **Lock order.** Several fields are behind their own mutex. Code that holds
/// more than one takes them in this order, and never holds one across an
/// `.await`: `facts`, then `soft`, then `published`, then `wg`.
///
/// `proposer`, `learning` and `acceptor` are async mutexes, held across
/// `.await`: saving to disk runs on tokio's blocking threads, so a slow disk
/// doesn't stop other tasks. They are taken in this order: `proposer`, then
/// `learning`, then `acceptor` (a change holds `proposer` while this node's
/// own acceptor answers it). None of the other locks is held while waiting
/// for them. `proposer` allows one change at a time.
///
/// `state` is a watch: it's read by cloning the `Arc` out of it, which takes
/// no lock that could wait on these, so it may be read while holding one.
/// It's written only while holding `learning`, as are `cert` and
/// `transitions`, which are taken after `acceptor` and never held across an
/// `.await`.
pub struct Node {
    pub opts: Arc<Options>,
    pub cluster_id: ClusterId,
    pub me: NodeId,
    pub identity: Arc<Identity>,
    pub wg_private: [u8; 32],
    pub wg_public: WgKey,
    pub net: Net,
    /// The latest agreed state this node has learned.
    pub state: watch::Sender<Arc<Chosen>>,
    /// The proof of `state` (see `proof`).
    cert: Mutex<proof::Certificate>,
    /// The transitions this node has checked, to help nodes that are behind.
    transitions: Mutex<proof::Transitions>,
    /// This node's acceptor. Any member may be named an acceptor.
    acceptor: Arc<tokio::sync::Mutex<StoredAcceptor>>,
    proposer: tokio::sync::Mutex<Proposer<NodeId, ClusterState>>,
    /// Serialises saving learned states, so an older one never overwrites a
    /// newer one on disk.
    learning: tokio::sync::Mutex<()>,
    /// A fetch of a newer state is in progress.
    fetching: AtomicBool,
    /// Acceptors not seen present, and since when.
    absent: Mutex<HashMap<NodeId, Instant>>,
    /// A lasting failure of the acceptors check.
    acceptors_problem: problem::Problem,
    /// A lasting failure to update this node's member record.
    record_problem: problem::Problem,
    /// A lasting failure to fetch a newer state.
    catch_up_problem: problem::Problem,
    files: Files,
    pub soft: Mutex<SoftTable>,
    pub facts: Mutex<LocalFacts>,
    portmaps: Option<crate::portmap::PortMaps>,
    pub wg: Mutex<WgState>,
    /// Wakes the WireGuard reconciler early.
    pub wake: Notify,
    /// Wakes the soft state loop early, to publish a new state version.
    publish: Notify,
    /// Our soft state as last published.
    published: Mutex<Option<SoftState>>,
    /// The sequence number of our last published soft state.
    soft_seq: AtomicU64,
    /// Signalled when this node is no longer a member.
    pub removed: Notify,
    pub(crate) lifetime: Arc<lifetime::Lifetime>,
    stopping: tokio::sync::Mutex<()>,
}

impl Node {
    /// Lasting failures of this node's repeated work, as status warnings.
    pub fn problems(&self) -> Vec<String> {
        [
            &self.acceptors_problem,
            &self.record_problem,
            &self.catch_up_problem,
        ]
        .into_iter()
        .filter_map(|p| p.warning())
        .collect()
    }

    /// Starts a member from its acceptor state in `files`, which holds the
    /// latest agreed state it has learned.
    pub fn start(
        opts: Arc<Options>,
        cluster_id: ClusterId,
        identity: Arc<Identity>,
        wg_private: [u8; 32],
        net: Net,
        files: Files,
    ) -> Result<Arc<Node>> {
        let me = identity.node_id();
        // A state directory from an older version of cheesecloth has other
        // files, or files in another format.
        let unreadable = || {
            format!(
                "can't read the cluster state in {}; it may be from an older version of \
                 cheesecloth. To start over, delete cluster.json, acceptor.* and state.bin \
                 (if present) there, then run `cheesecloth init` or `cheesecloth join` again",
                files.dir.display()
            )
        };
        let acceptor = open_acceptor(&files)
            .with_context(unreadable)?
            .with_context(unreadable)?;
        let learned: Chosen = acceptor
            .acceptor()
            .learned()
            .cloned()
            .with_context(unreadable)?;
        let cert = acceptor
            .acceptor()
            .proof()
            .cloned()
            .with_context(unreadable)?;
        ensure!(
            learned.state().cluster_id == Some(cluster_id)
                && cert.header.cluster_id == cluster_id
                && cert.proves(&learned),
            "saved consensus state does not match the cluster record"
        );
        cert.check_config(&cert.header.config, false)?;
        // Transitions only help other nodes catch up: losing them is no
        // reason not to start.
        let transitions = proof::Transitions::load(&files.transitions()).unwrap_or_else(|e| {
            tracing::warn!("can't read the saved transitions, starting without them: {e}");
            proof::Transitions::default()
        });
        let portmaps = opts
            .port_mapping
            .then(|| crate::portmap::PortMaps::start(opts.wg_port, opts.listen_port));
        let node = Arc::new(Node {
            wg: Mutex::new(WgState::new(&opts)),
            opts,
            cluster_id,
            me,
            identity,
            wg_public: cheesecloth_wg::public_key(&wg_private),
            wg_private,
            net,
            proposer: tokio::sync::Mutex::new(Proposer::new(me, learned.clone())),
            state: watch::Sender::new(Arc::new(learned)),
            cert: Mutex::new(cert),
            transitions: Mutex::new(transitions),
            acceptor: Arc::new(tokio::sync::Mutex::new(acceptor)),
            learning: tokio::sync::Mutex::new(()),
            fetching: AtomicBool::new(false),
            absent: Mutex::default(),
            acceptors_problem: problem::Problem::new("checking the acceptors"),
            record_problem: problem::Problem::new("updating this node's member record"),
            catch_up_problem: problem::Problem::new("catching up to the latest state"),
            files,
            soft: Mutex::default(),
            facts: Mutex::default(),
            portmaps,
            wake: Notify::new(),
            publish: Notify::new(),
            published: Mutex::default(),
            soft_seq: AtomicU64::new(0),
            removed: Notify::new(),
            lifetime: Arc::default(),
            stopping: tokio::sync::Mutex::new(()),
        });
        // Until a dial-back gives a result, a node that was a relay
        // (because it was public) stays one. A restart doesn't remove it.
        let was_relay = node
            .agreed()
            .value
            .value
            .members
            .get(&me)
            .is_some_and(|m| m.info.relay);
        if node.opts.relay == RelayMode::Auto && was_relay {
            node.facts.lock().public = true;
        }
        node.refresh_facts();
        Ok(node)
    }

    /// Starts the background loops.
    pub fn spawn_loops(self: &Arc<Self>) {
        let n = self.clone();
        self.lifetime
            .spawn(async move { n.soft_state_loop().await });
        let n = self.clone();
        self.lifetime
            .spawn(async move { n.connection_loop().await });
        let n = self.clone();
        self.lifetime
            .spawn(async move { n.reachability_loop().await });
        let n = self.clone();
        self.lifetime.spawn(async move { n.acceptors_loop().await });
        let n = self.clone();
        self.lifetime
            .spawn(async move { crate::wgrec::run(n).await });
        let n = self.clone();
        self.lifetime
            .spawn(async move { n.membership_watch().await });
        let n = self.clone();
        self.lifetime
            .spawn(async move { crate::clock::run(n).await });
    }

    /// Stops all work before shared resources can be removed or reused.
    pub(crate) async fn quiesce(&self) {
        self.lifetime.stop().await;
    }

    /// A failed interface removal retains its backend for the next attempt.
    pub async fn stop(&self) -> Result<()> {
        let _stopping = self.stopping.lock().await;
        self.quiesce().await;
        if let Some(p) = &self.portmaps {
            p.stop().await;
        }
        for c in self.net.connections() {
            self.net.disconnect(&c.node);
        }
        self.wg.lock().down()
    }

    /// Serves a member's request for one of the control-plane services.
    pub fn handle(
        self: &Arc<Self>,
        from: NodeId,
        service: u8,
        body: Vec<u8>,
    ) -> BoxFuture<Result<Vec<u8>, String>> {
        let node = self.clone();
        Box::pin(async move {
            node.lifetime
                .run(async {
                    match service {
                        SVC_PAXOS => encode(&node.handle_wire(from, decode(&body)?).await?),
                        SVC_VERIFY => encode(&node.verify_round(from, decode(&body)?).await?),
                        SVC_FETCH => encode(&node.proven(decode(&body)?).await),
                        SVC_STATE => encode(&node.take_state(decode(&body)?).await?),
                        SVC_COMMIT => {
                            node.learn_commit(from, decode(&body)?).await?;
                            Ok(Vec::new())
                        }
                        SVC_PUNCH => {
                            encode(&crate::wgrec::handle_punch(&node, from, decode(&body)?))
                        }
                        _ => Err(format!("unknown service {service}")),
                    }
                })
                .await
                .map_err(|e| e.to_string())?
        })
    }

    /// Serves a request on the join stream (possibly from a non-member).
    pub fn handle_join(
        self: &Arc<Self>,
        from: NodeId,
        body: Vec<u8>,
    ) -> BoxFuture<Result<Vec<u8>, String>> {
        let node = self.clone();
        Box::pin(async move {
            node.lifetime
                .run(async {
                    let reply = node
                        .join_request(from, decode(&body)?)
                        .await
                        .map_err(|e| format!("{e:#}"))?;
                    encode(&reply)
                })
                .await
                .map_err(|e| e.to_string())?
        })
    }
}

impl Node {
    /// Notices when this node stops being a member (removed, or left).
    async fn membership_watch(self: Arc<Self>) {
        let mut rx = self.state.subscribe();
        loop {
            let member = rx.borrow_and_update().state().is_member(&self.me);
            // Soft state follows the membership: drop entries of former
            // members, and take in entries that arrived before a new
            // member's join reached us.
            let merged = {
                let mut table = self.soft.lock();
                table.prune(|n| self.is_member(n));
                table.retry_parked(|n| self.is_member(n))
            };
            if !merged.is_empty() {
                self.wake.notify_one();
                self.spread(merged, None);
            }
            if !member {
                tracing::warn!("this node is no longer a member of the cluster");
                self.removed.notify_one();
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }
}

/// Opens this node's acceptor state, or returns `None` if there is none.
///
/// If `acceptor.bin` exists, it holds the newest state: an older version of
/// cheesecloth wrote it, a move was cut short, or the node was downgraded and
/// upgraded again. Its state is then saved in a pnyx store, in place of any
/// state there, and `acceptor.bin` is deleted. This is safe to repeat after a
/// crash: the node sends no replies until it has started, so the same state
/// is saved again.
fn open_acceptor(files: &Files) -> Result<Option<StoredAcceptor>> {
    let legacy = files.legacy_acceptor();
    match std::fs::read(&legacy) {
        Ok(bytes) => {
            let acceptor = postcard::from_bytes(&bytes)
                .with_context(|| format!("decoding {}", legacy.display()))?;
            let stored = StoredAcceptor::create(files.acceptor(), acceptor)
                .context("saving the acceptor state in the new format")?;
            files.delete_legacy_acceptor()?;
            tracing::info!("moved the acceptor state from acceptor.bin to the new format");
            return Ok(Some(stored));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {}", legacy.display())),
    }
    Ok(StoredAcceptor::open_existing(files.acceptor())?)
}

/// Decodes a control-plane message, with the error as a string for the peer.
fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, String> {
    postcard::from_bytes(body).map_err(|e| e.to_string())
}

/// Encodes a control-plane reply, with the error as a string for the peer.
fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    postcard::to_stdvec(value).map_err(|e| e.to_string())
}
