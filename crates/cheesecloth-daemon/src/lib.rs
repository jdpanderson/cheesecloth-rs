//! The cheesecloth daemon. It owns the node's keys, its control-plane endpoint,
//! consensus and the WireGuard interface, and serves the local API used by the
//! `cheesecloth` CLI.
//!
//! - `membership`: init, join, leave.
//! - `commands`: invites, removal, approvals, settings.
//! - `views`: status and peers.
//! - `local_api`: the local API server for the CLI.
//! - `ipc`: its transport, a Unix socket or a named pipe on Windows.
//! - `node`: a running cluster member and its loops.

pub mod api;
mod clock;
mod commands;
mod files;
mod ipc;
mod lifetime;
mod local;
mod local_api;
mod membership;
mod node;
mod options;
mod portmap;
mod proto;
mod soft;
#[cfg(test)]
mod testing;
mod views;
mod wgrec;

use std::{
    net::SocketAddr,
    sync::{Arc, Weak},
};

use anyhow::{Context, Result};
use cheesecloth_core::{ClusterId, Identity, NodeId};
use cheesecloth_net::{BoxFuture, Net, NetOptions};
use parking_lot::{Mutex, RwLock};
use tokio::sync::Notify;
use tracing::{info, warn};

pub use options::{Options, RelayMode, socket_path};

use files::{Cleanup, Files, PendingJoin};
use local_api::StopRequest;
use node::Node;

/// Where this node is in its cluster membership.
enum Phase {
    /// Not in a cluster.
    None,
    /// Waiting for approvals of our join.
    Pending {
        cluster_id: ClusterId,
        pending: Arc<PendingJoin>,
    },
    Member(Arc<Node>),
    Stopping {
        cleanup: Cleanup,
        node: Option<Arc<Node>>,
        error: Option<String>,
    },
    Stopped,
}

pub struct Daemon {
    opts: Arc<Options>,
    files: Files,
    identity: Arc<Identity>,
    wg_private: [u8; 32],
    net: Net,
    api_work: Arc<lifetime::Lifetime>,
    phase: RwLock<Phase>,
    /// Serialises init/join/leave.
    op: tokio::sync::Mutex<()>,
    /// The one polling task owned by the current pending join.
    pending_poll: Mutex<Option<tokio::task::JoinHandle<()>>>,
    removal_watch: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// `stop` requests, answered when shutdown has finished.
    stop_requests: Mutex<Vec<StopRequest>>,
    stop_requested: Notify,
}

impl Daemon {
    /// Loads keys and any existing cluster state, and binds the control plane.
    pub async fn start(mut opts: Options) -> Result<Arc<Daemon>> {
        opts.check().map_err(anyhow::Error::msg)?;
        let files = Files::new(&opts.state_dir)?;
        let identity = Arc::new(Identity::load_or_create(&files.identity())?);
        let wg_private = files.load_or_create_wg_key()?;
        // The control plane's QUIC keep-alive is always 25 s (NetOptions's
        // default), whatever --keepalive says: it keeps NAT mappings to relays
        // open and stops idle links between relays from dropping.
        let net_opts = NetOptions::new(SocketAddr::new(opts.bind_ip, opts.listen_port));
        let bound = Net::bind(net_opts, identity.clone())?;
        let control = bound.local_addr()?;
        // Port 0 lets the system choose; peers need the port it chose.
        opts.listen_port = control.port();
        let opts = Arc::new(opts);
        info!(node = %identity.node_id(), %control, "cheesecloth daemon starting");
        // The control plane calls back into the daemon, which owns it.
        let daemon = Arc::new_cyclic(|daemon| {
            let callbacks = Arc::new(Callbacks(daemon.clone()));
            Daemon {
                opts,
                files,
                identity,
                wg_private,
                net: bound.start(callbacks.clone(), callbacks),
                api_work: Arc::default(),
                phase: RwLock::new(Phase::None),
                op: tokio::sync::Mutex::new(()),
                pending_poll: Mutex::new(None),
                removal_watch: Mutex::new(None),
                stop_requests: Mutex::default(),
                stop_requested: Notify::new(),
            }
        });

        if let Some(cleanup) = daemon.files.load_cleanup()? {
            *daemon.phase.write() = Phase::Stopping {
                cleanup,
                node: None,
                error: None,
            };
            if let Err(e) = daemon.finish_cleanup().await {
                let leaving = matches!(&*daemon.phase.read(), Phase::Stopping { cleanup, .. } if cleanup.forget_cluster);
                if !leaving {
                    daemon.net.close();
                    return Err(e).context("shutdown cleanup pending; restart the daemon to retry");
                }
                warn!("local cleanup pending; retry `cheesecloth leave`: {e:#}");
                return Ok(daemon);
            }
            *daemon.phase.write() = Phase::None;
        }

        match daemon.files.load_cluster()? {
            None => info!("not in a cluster; waiting for `cheesecloth init` or `cheesecloth join`"),
            Some(c) => match c.pending {
                Some(pending) => {
                    info!(proposal = %pending.proposal, "join is waiting for approvals");
                    daemon.begin_pending(c.cluster_id, pending);
                }
                None => {
                    daemon.become_member(c.cluster_id)?;
                }
            },
        }
        Ok(daemon)
    }

    pub fn node_id(&self) -> NodeId {
        self.identity.node_id()
    }

    fn node(&self) -> Option<Arc<Node>> {
        match &*self.phase.read() {
            Phase::Member(n) => Some(n.clone()),
            _ => None,
        }
    }

    fn require_node(&self) -> Result<Arc<Node>> {
        self.node().context("this node is not in a cluster")
    }

    /// Stops everything (process shutdown). The node stays in its cluster.
    pub async fn shutdown(&self) {
        let _op = self.op.lock().await;
        self.api_work.stop().await;
        self.stop_pending_poll().await;
        self.stop_removal_watch().await;
        if matches!(&*self.phase.read(), Phase::Pending { .. }) {
            // Invalidate replies in this process, but leave the saved attempt
            // intact so the next daemon can resume it.
            *self.phase.write() = Phase::None;
        }
        let stopping = matches!(&*self.phase.read(), Phase::Stopping { .. });
        if let Some(node) = self.node() {
            if let Err(e) = self.stop_node(&node, false).await {
                warn!("shutdown cleanup failed: {e:#}");
            }
        } else if stopping && let Err(e) = self.finish_cleanup().await {
            warn!("shutdown cleanup pending: {e:#}");
        }
        if !matches!(&*self.phase.read(), Phase::Stopping { .. }) {
            *self.phase.write() = Phase::Stopped;
        }
        self.net.close();
        self.answer_stop_requests().await;
    }
}

/// Net is owned by Daemon; callbacks must not own it back. With no daemon,
/// they answer as a node that is in no cluster.
pub(crate) struct Callbacks(pub(crate) Weak<Daemon>);

impl Callbacks {
    fn node(&self) -> Option<Arc<Node>> {
        self.0.upgrade()?.node()
    }
}

impl cheesecloth_net::Directory for Callbacks {
    fn cluster_id(&self) -> Option<ClusterId> {
        let daemon = self.0.upgrade()?;
        match &*daemon.phase.read() {
            Phase::Member(n) => Some(n.cluster_id),
            Phase::Pending { cluster_id, .. } => Some(*cluster_id),
            Phase::None | Phase::Stopping { .. } | Phase::Stopped => None,
        }
    }

    fn is_member(&self, node: &NodeId) -> bool {
        self.node().is_some_and(|n| n.is_member(node))
    }

    fn is_relay(&self, node: &NodeId) -> bool {
        self.node().is_some_and(|n| n.is_relay(node))
    }

    fn dial_addrs(&self, node: &NodeId) -> Vec<SocketAddr> {
        self.node().map(|n| n.dial_addrs(node)).unwrap_or_default()
    }

    fn forwarders(&self, node: &NodeId) -> Vec<NodeId> {
        self.node().map(|n| n.forwarders(node)).unwrap_or_default()
    }
}

impl cheesecloth_net::Handler for Callbacks {
    fn request(
        &self,
        from: NodeId,
        service: u8,
        body: Vec<u8>,
    ) -> BoxFuture<Result<Vec<u8>, String>> {
        match self.node() {
            Some(n) => n.handle(from, service, body),
            None => Box::pin(async { Err("not in a cluster".into()) }),
        }
    }

    fn join(&self, from: NodeId, body: Vec<u8>) -> BoxFuture<Result<Vec<u8>, String>> {
        match self.node() {
            Some(n) => n.handle_join(from, body),
            None => Box::pin(async { Err("not in a cluster".into()) }),
        }
    }

    fn state(&self, from: NodeId, body: Vec<u8>) {
        if let Some(n) = self.node() {
            n.merge_soft(from, &body);
        }
    }

    fn connected(&self, peer: NodeId) {
        if let Some(n) = self.node() {
            n.on_connected(peer);
        }
    }
}

/// Runs the daemon until interrupted or asked to stop.
pub async fn run(opts: Options) -> Result<()> {
    let daemon = Daemon::start(opts).await?;
    serve(daemon, shutdown_signal()).await
}

/// Serves the local API until `signal` completes, a `stop` request arrives or
/// the API fails, then shuts the daemon down.
async fn serve(daemon: Arc<Daemon>, signal: impl Future<Output = ()>) -> Result<()> {
    let mut api = tokio::spawn(daemon.clone().serve_api());
    let stop = tokio::select! {
        r = &mut api => Err(r),
        _ = signal => Ok("shutting down"),
        _ = daemon.stop_requested.notified() => Ok("shutting down: stop requested"),
    };
    let result = match stop {
        Err(r) => r.map_err(anyhow::Error::from).and_then(|r| r),
        Ok(reason) => {
            info!("{reason}");
            api.abort();
            match api.await {
                Err(e) if e.is_cancelled() => Ok(()),
                r => r.map_err(anyhow::Error::from).and_then(|r| r),
            }
        }
    };
    daemon.shutdown().await;
    result
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("signal handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
