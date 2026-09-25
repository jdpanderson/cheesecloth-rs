//! The WireGuard reconciler turns cluster state and soft state into peers.
//! It shares the backend lock with asynchronous punch handlers (see
//! *WireGuard and NAT traversal* in DESIGN.md).

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use cheesecloth_core::{
    NodeId, WgKey,
    addr::node_ipv6,
    state::{Member, MemberInfo},
};
use cheesecloth_wg::{
    Backend, DEAD_AFTER, INITIATOR_DELAY, InterfaceConfig, PUNCH_TIMEOUT, PeerConfig, PeerStatus,
    REPUNCH_QUIET,
    plan::{self, Path},
};
use ipnet::IpNet;
use tracing::{debug, info, warn};

use crate::{
    Options,
    node::{Chosen, Node},
    proto::{PunchMessage, PunchReply, SVC_PUNCH},
    soft::{Observed, SoftState},
};

/// Observed endpoints are only reported for handshakes this recent.
const OBSERVED_MAX_AGE: Duration = Duration::from_secs(180);
/// How long an offer may go unanswered.
const OFFER_TIMEOUT: Duration = Duration::from_secs(15);
/// After this many failed punches in a row, retry less often.
const FAST_RETRIES: u32 = 3;
const SLOW_RETRY: Duration = Duration::from_secs(300);
/// A punched path whose peer no longer reports handshakes with us (e.g. it
/// restarted) is treated as dead once it has been up this long.
const UP_GRACE: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
enum Punch {
    Idle,
    /// Initiator: an offer is on its way.
    Offered {
        since: Instant,
    },
    /// Both: openers sent or about to be, waiting for a handshake.
    Opening {
        id: u64,
        since: Instant,
        initiator: bool,
        endpoint: SocketAddr,
    },
    Up {
        since: Instant,
    },
    /// Delete the old path before starting its quiet period (zero for a reset).
    Removing {
        quiet_for: Duration,
    },
    /// A dead or failed path, silenced until `until`.
    Quiet {
        until: Instant,
    },
}

#[derive(Clone, Debug)]
struct PeerState {
    key: WgKey,
    path: Option<Path>,
    /// What we last configured, or `None` if the peer isn't configured.
    applied: Option<PeerConfig>,
    punch: Punch,
    failures: u32,
    /// Why the peer couldn't be configured, until it can.
    error: Option<String>,
}

impl PeerState {
    fn retry_delay(&self) -> Duration {
        if self.failures > FAST_RETRIES {
            SLOW_RETRY
        } else {
            REPUNCH_QUIET
        }
    }

    fn removed(&mut self) {
        self.applied = None;
        if let Punch::Removing { quiet_for } = self.punch {
            self.punch = if quiet_for.is_zero() {
                Punch::Idle
            } else {
                Punch::Quiet {
                    until: Instant::now() + quiet_for,
                }
            };
        }
    }
}

pub struct WgState {
    backend: Option<Box<dyn Backend>>,
    /// Why the interface couldn't be brought up, and when.
    error: Option<(String, Instant)>,
    /// Why the interface couldn't be read, until it can.
    status_error: Option<String>,
    /// Failed revocations, including keys found only in the backend. Membership
    /// is checked again before every retry; this is not an unconditional queue.
    removals: BTreeMap<WgKey, String>,
    peers: HashMap<NodeId, PeerState>,
    status: HashMap<WgKey, PeerStatus>,
    opener_warned: bool,
    kind: cheesecloth_wg::BackendKind,
}

impl WgState {
    pub fn new(opts: &Options) -> Self {
        Self {
            backend: None,
            error: None,
            status_error: None,
            removals: BTreeMap::new(),
            peers: HashMap::new(),
            status: HashMap::new(),
            opener_warned: false,
            kind: opts.backend,
        }
    }

    pub fn backend_kind(&self) -> Option<&'static str> {
        self.backend.as_ref().map(|b| b.kind())
    }

    pub fn error(&self) -> Option<String> {
        self.error.as_ref().map(|(e, _)| e.clone())
    }

    /// Problems for `status` output.
    pub fn warnings(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .error()
            .into_iter()
            .chain(self.status_error.clone())
            .map(|e| format!("WireGuard: {e}"))
            .collect();
        let mut peers: Vec<(&NodeId, &String)> = self
            .peers
            .iter()
            .filter_map(|(n, p)| Some((n, p.error.as_ref()?)))
            .collect();
        peers.sort();
        out.extend(
            peers
                .into_iter()
                .map(|(n, e)| format!("WireGuard peer {}: {e}", n.short())),
        );
        out.extend(
            self.removals
                .iter()
                .map(|(key, e)| format!("WireGuard key {key}: removal pending: {e}")),
        );
        out
    }

    /// Notes whether the interface could be read, logging changes.
    fn note_status(&mut self, res: Result<Vec<PeerStatus>>) -> Option<Vec<PeerStatus>> {
        match res {
            Ok(status) => {
                if self.status_error.take().is_some() {
                    info!("reading the WireGuard interface works again");
                }
                Some(status)
            }
            Err(e) => {
                let msg = format!("reading the interface: {e:#}");
                if self.status_error.as_ref() != Some(&msg) {
                    warn!("WireGuard: {msg}");
                }
                self.status_error = Some(msg);
                None
            }
        }
    }

    /// Notes whether a peer could be configured, logging changes.
    fn note_peer(&mut self, node: &NodeId, res: Result<()>) {
        let Some(p) = self.peers.get_mut(node) else {
            return;
        };
        match res {
            Ok(()) => {
                if p.error.take().is_some() {
                    info!(peer = %node.short(), "WireGuard peer configured");
                }
            }
            Err(e) => {
                let msg = format!("{e:#}");
                if p.error.as_ref() != Some(&msg) {
                    warn!(peer = %node.short(), "configuring WireGuard peer: {msg}");
                }
                p.error = Some(msg);
            }
        }
    }

    pub fn down(&mut self) -> Result<()> {
        if let Some(b) = &mut self.backend
            && let Err(e) = b.down()
        {
            let message = format!("removing the WireGuard interface: {e:#}");
            self.error = Some((message.clone(), Instant::now()));
            bail!(message);
        }
        self.backend = None;
        self.peers.clear();
        self.status.clear();
        self.removals.clear();
        self.error = None;
        self.status_error = None;
        Ok(())
    }

    /// Peer endpoints this node's WireGuard has recently handshaken with.
    pub fn observed(&self, members: &BTreeMap<NodeId, Member>) -> Vec<Observed> {
        let by_key: HashMap<WgKey, NodeId> =
            members.iter().map(|(n, m)| (m.info.wg_key, *n)).collect();
        let mut out: Vec<Observed> = self
            .status
            .values()
            .filter_map(|s| {
                let node = *by_key.get(&s.key)?;
                (s.handshake_age()? < OBSERVED_MAX_AGE).then_some(Observed {
                    node,
                    endpoint: s.endpoint?,
                })
            })
            .collect();
        out.sort();
        out
    }

    /// For `peers` output: path kind, state detail, endpoint, handshake age.
    pub fn describe(&self, node: &NodeId) -> (String, String, Option<SocketAddr>, Option<u64>) {
        let Some(p) = self.peers.get(node) else {
            return ("none".into(), "not configured".into(), None, None);
        };
        let status = self.status.get(&p.key);
        let kind = match p.path {
            Some(Path::Lan(_)) => "lan",
            Some(Path::Public(_)) => "public",
            Some(Path::Await) => "await",
            Some(Path::Punch) => "punch",
            None => "none",
        };
        let age = status.and_then(|s| s.handshake_age());
        let detail = match (&p.path, &p.punch) {
            (Some(Path::Punch), Punch::Idle) => "waiting to punch".to_string(),
            (Some(Path::Punch), Punch::Offered { .. }) => "offer sent".to_string(),
            (Some(Path::Punch), Punch::Opening { .. }) => "punching".to_string(),
            (Some(Path::Punch), Punch::Removing { .. }) => "waiting for peer removal".to_string(),
            (Some(Path::Punch), Punch::Quiet { until }) => format!(
                "no path; retry in {}s",
                until.saturating_duration_since(Instant::now()).as_secs()
            ),
            _ => match age {
                Some(a) if a < DEAD_AFTER => "up".to_string(),
                Some(_) => "stale".to_string(),
                None => "no handshake yet".to_string(),
            },
        };
        (
            kind.into(),
            detail,
            status.and_then(|s| s.endpoint),
            age.map(|a| a.as_secs()),
        )
    }

    fn apply(&mut self, node: NodeId, cfg: PeerConfig) -> Result<()> {
        let b = self.backend.as_mut().context("no interface")?;
        let peer = self.peers.get_mut(&node).context("unknown peer")?;
        if peer.key != cfg.key {
            bail!("peer key changed");
        }
        if matches!(peer.punch, Punch::Removing { .. } | Punch::Quiet { .. }) {
            bail!("peer is being removed or is in its quiet period");
        }
        if peer.applied.as_ref() != Some(&cfg) {
            debug!(peer = %node.short(), endpoint = ?cfg.endpoint, keepalive = cfg.keepalive, "configuring WireGuard peer");
            b.set_peer(&cfg)?;
            peer.applied = Some(cfg);
        }
        Ok(())
    }

    fn remove_key(&mut self, key: &WgKey) -> Result<()> {
        self.backend
            .as_mut()
            .context("no interface")?
            .remove_peer(key)
            .context("removing peer")?;
        // A failed write may have left the key installed. Only acknowledge a
        // successful removal, or absence observed in a fresh status snapshot.
        self.status.remove(key);
        for peer in self.peers.values_mut().filter(|p| p.key == *key) {
            peer.removed();
        }
        Ok(())
    }

    fn quiet(&mut self, node: &NodeId) -> Result<()> {
        if let Some(p) = self.peers.get_mut(node) {
            if !matches!(p.punch, Punch::Removing { .. }) {
                p.failures += 1;
                p.punch = Punch::Removing {
                    quiet_for: p.retry_delay(),
                };
            }
            self.finish_punch_removal(node)?;
        }
        Ok(())
    }

    fn finish_punch_removal(&mut self, node: &NodeId) -> Result<()> {
        let peer = self.peers.get(node).context("unknown peer")?;
        if !matches!(peer.punch, Punch::Removing { .. }) {
            return Ok(());
        }
        let key = peer.key;
        self.remove_key(&key)?;
        Ok(())
    }

    /// Reconcile authorization against both our bookkeeping and backend keys.
    /// Known revocations still run when the interface cannot be read.
    fn revoke(&mut self, members: &BTreeMap<NodeId, Member>, me: NodeId, fresh: bool) {
        let authorized: BTreeSet<WgKey> = members
            .iter()
            .filter(|(id, _)| **id != me)
            .map(|(_, m)| m.info.wg_key)
            .collect();
        let unwanted: BTreeSet<WgKey> = self
            .peers
            .values()
            .map(|p| p.key)
            .chain(self.status.keys().copied())
            .chain(self.removals.keys().copied())
            .filter(|key| !authorized.contains(key))
            .collect();
        // Retain the deletion work by key, not an active peer entry: a late
        // punch response must not be able to configure a revoked peer again.
        self.peers
            .retain(|id, p| *id != me && members.get(id).is_some_and(|m| m.info.wg_key == p.key));
        self.removals.retain(|key, _| {
            if authorized.contains(key) {
                info!(%key, "WireGuard removal cancelled: key is authorized again");
                false
            } else {
                true
            }
        });
        for key in unwanted {
            let result = if fresh && !self.status.contains_key(&key) {
                Ok(())
            } else {
                self.remove_key(&key)
            };
            match result {
                Ok(()) => {
                    self.removals.remove(&key);
                    info!(%key, "unauthorized WireGuard peer is absent");
                }
                Err(e) => {
                    let message = format!("{e:#}");
                    if self.removals.get(&key) != Some(&message) {
                        warn!(%key, "removing unauthorized WireGuard peer: {message}");
                    }
                    self.removals.insert(key, message);
                }
            }
        }
    }
}

fn allowed_ips(node: &Node, peer: &NodeId, ipv4: Ipv4Addr) -> Vec<IpNet> {
    vec![
        IpNet::new(IpAddr::V4(ipv4), 32).expect("valid"),
        IpNet::new(IpAddr::V6(node_ipv6(&node.cluster_id, peer)), 128).expect("valid"),
    ]
}

/// The WireGuard keepalive for punched paths: never off, or the NAT mapping
/// would expire.
fn wg_nat_keepalive(node: &Node) -> u16 {
    match node.wg_keepalive() {
        0 => cheesecloth_core::NAT_KEEPALIVE_SECS,
        k => k,
    }
}

pub async fn run(node: Arc<Node>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = node.wake.notified() => {}
        }
        for (peer, initiator_ep, responder_ep) in reconcile(&node) {
            let n = node.clone();
            node.lifetime.spawn(async move {
                if let Err(e) = start_punch(&n, peer, initiator_ep, responder_ep).await {
                    info!(peer = %peer.short(), "punch not started: {e:#}");
                    let mut wg = n.wg.lock();
                    if wg.peers.get(&peer).is_some_and(|p| {
                        p.path == Some(Path::Punch)
                            && matches!(
                                p.punch,
                                Punch::Offered { .. }
                                    | Punch::Opening {
                                        initiator: true,
                                        ..
                                    }
                            )
                    }) {
                        let result = wg.quiet(&peer);
                        wg.note_peer(&peer, result);
                    }
                }
            });
        }
    }
}

/// A punch this node should start, as initiator: the peer, our endpoint and
/// the peer's endpoint, as relays observe them.
type PunchStart = (NodeId, SocketAddr, SocketAddr);

/// Everything a pass needs from outside the WireGuard lock, gathered first
/// (lock order: facts, soft, then wg).
struct Inputs {
    /// The agreed state, for its members.
    agreed: Arc<Chosen>,
    my_ipv4: Ipv4Addr,
    local: plan::Local,
    public_ips: HashMap<NodeId, IpAddr>,
    keepalive: u16,
    nat_keepalive: u16,
    soft: HashMap<NodeId, SoftState>,
    /// Endpoints as relays observe them.
    observed: HashMap<NodeId, SocketAddr>,
}

impl Inputs {
    fn members(&self) -> &BTreeMap<NodeId, Member> {
        &self.agreed.state().members
    }

    fn gather(node: &Node) -> Option<Inputs> {
        let agreed = node.agreed();
        let members = &agreed.state().members;
        let my_ipv4 = members.get(&node.me)?.ipv4;
        let facts = node.facts.lock().clone();
        let table = node.soft.lock();
        let observed = table.observations(members.keys().copied());
        let public_ip = |id: &NodeId| {
            if *id == node.me && facts.public {
                return facts.public_ip;
            }
            match table.get(id) {
                Some(s) if s.public => s.public_ip,
                s => observed
                    .get(id)
                    .map(|e| e.ip())
                    .or(s.and_then(|s| s.public_ip)),
            }
        };
        let local = plan::Local {
            public: !facts.wg_public.is_empty(),
            nets: facts.ifaces.nets.clone(),
            public_ip: public_ip(&node.me),
            have_relays: members.iter().any(|(id, member)| {
                if *id == node.me {
                    facts.relay
                } else {
                    table.get(id).map_or(member.info.relay, |s| s.relay)
                }
            }),
        };
        let public_ips = members
            .keys()
            .filter_map(|id| public_ip(id).map(|ip| (*id, ip)))
            .collect();
        let soft = members
            .keys()
            .filter_map(|id| table.get(id).map(|s| (*id, s.clone())))
            .collect();
        drop(table);
        Some(Inputs {
            agreed,
            my_ipv4,
            local,
            public_ips,
            keepalive: node.wg_keepalive(),
            nat_keepalive: wg_nat_keepalive(node),
            soft,
            observed,
        })
    }

    /// How the peer can be reached, as far as we know.
    fn remote(&self, id: &NodeId, info: &MemberInfo) -> plan::Remote {
        let s = self.soft.get(id);
        plan::Remote {
            public_endpoints: match s {
                Some(s) => s.wg_public.clone(),
                None if info.relay => info
                    .control_addrs
                    .iter()
                    .map(|a| SocketAddr::new(a.ip(), info.wg_port))
                    .collect(),
                None => Vec::new(),
            },
            lan_endpoints: s.map(|s| s.wg_lan.clone()).unwrap_or_default(),
            public_ip: self.public_ips.get(id).copied(),
        }
    }
}

/// One pass: bring the interface up, sync peers, advance punch state.
/// Returns the punches to start (as initiator). A peer that can't be
/// configured doesn't stop the others; it's retried on the next pass.
fn reconcile(node: &Node) -> Vec<PunchStart> {
    let Some(inputs) = Inputs::gather(node) else {
        return Vec::new();
    };
    let mut wg = node.wg.lock();
    if !wg.ensure_up(node, inputs.my_ipv4) {
        return Vec::new();
    }

    // Kernel view. Path decisions need a fresh snapshot, but known revocations
    // must not depend on the status read succeeding.
    let status = wg.backend.as_ref().expect("up").status();
    let status = wg.note_status(status);
    let fresh = status.is_some();
    if let Some(status) = status {
        wg.status = status.into_iter().map(|s| (s.key, s)).collect();
        let wg = &mut *wg;
        for peer in wg.peers.values_mut() {
            if !wg.status.contains_key(&peer.key) {
                peer.removed();
            }
        }
    }
    wg.revoke(inputs.members(), node.me, fresh);
    if !fresh {
        return Vec::new();
    }

    let mut starts = Vec::new();
    for (id, Member { info, ipv4, .. }) in inputs.members() {
        if *id == node.me {
            continue;
        }
        let path = plan::plan(&inputs.local, &inputs.remote(id, info));
        let entry = wg.peers.entry(*id).or_insert_with(|| PeerState {
            key: info.wg_key,
            path: None,
            applied: None,
            punch: Punch::Idle,
            failures: 0,
            error: None,
        });
        let changed = entry.path != Some(path);
        entry.path = Some(path);
        let peer = PeerConfig {
            key: info.wg_key,
            endpoint: None,
            keepalive: inputs.keepalive,
            allowed_ips: allowed_ips(node, id, *ipv4),
        };
        let res = match path {
            Path::Lan(e) | Path::Public(e) => {
                entry.punch = Punch::Idle;
                wg.apply(
                    *id,
                    PeerConfig {
                        endpoint: Some(e),
                        ..peer
                    },
                )
            }
            Path::Await => {
                entry.punch = Punch::Idle;
                wg.apply(*id, peer)
            }
            Path::Punch => {
                if changed {
                    wg.peers.get_mut(id).expect("present").punch = Punch::Removing {
                        quiet_for: Duration::ZERO,
                    };
                }
                wg.step_punch(node, *id, peer, &inputs)
                    .map(|s| starts.extend(s))
            }
        };
        wg.note_peer(id, res);
    }
    starts
}

impl WgState {
    /// Brings the interface up if it isn't. Returns whether it's up. After a
    /// failure, waits 30 s before trying again.
    fn ensure_up(&mut self, node: &Node, my_ipv4: Ipv4Addr) -> bool {
        if self.backend.is_some() {
            return true;
        }
        if let Some((_, when)) = &self.error
            && when.elapsed() < Duration::from_secs(30)
        {
            return false;
        }
        let nets = node.overlay_nets();
        let prefix4 = nets
            .iter()
            .find_map(|n| match n {
                IpNet::V4(v4) => Some(v4.prefix_len()),
                _ => None,
            })
            .unwrap_or(24);
        let config = InterfaceConfig {
            name: node.opts.interface.clone(),
            private_key: node.wg_private,
            listen_port: node.opts.wg_port,
            addresses: vec![
                IpNet::new(IpAddr::V4(my_ipv4), prefix4).expect("valid prefix"),
                IpNet::new(IpAddr::V6(node_ipv6(&node.cluster_id, &node.me)), 64)
                    .expect("valid prefix"),
            ],
            routes: nets,
            mtu: None,
        };
        match cheesecloth_wg::open(self.kind, &config) {
            Ok(b) => {
                info!(interface = %config.name, kind = b.kind(), ipv4 = %my_ipv4, "WireGuard interface up");
                self.backend = Some(b);
                self.error = None;
                true
            }
            Err(e) => {
                warn!("bringing up WireGuard: {e:#}");
                self.error = Some((format!("{e:#}"), Instant::now()));
                false
            }
        }
    }

    /// Advances the punch state machine for one peer that both sides reach
    /// only through NAT. `peer` is its configuration with keepalive and
    /// allowed IPs filled in. Returns a punch to start, if this node is the
    /// designated initiator and it's time.
    fn step_punch(
        &mut self,
        node: &Node,
        id: NodeId,
        peer: PeerConfig,
        inputs: &Inputs,
    ) -> Result<Option<PunchStart>> {
        let age = self.status.get(&peer.key).and_then(|s| s.handshake_age());
        let p = self.peers.get_mut(&id).expect("present");
        match p.punch.clone() {
            Punch::Idle => {
                let initiator = node.me < id;
                let mine = inputs.observed.get(&node.me).copied();
                let theirs = inputs.observed.get(&id).copied();
                if let (true, Some(mine), Some(theirs)) = (initiator, mine, theirs) {
                    p.punch = Punch::Offered {
                        since: Instant::now(),
                    };
                    return Ok(Some((id, mine, theirs)));
                }
            }
            Punch::Offered { since } => {
                if since.elapsed() > OFFER_TIMEOUT {
                    self.quiet(&id)?;
                }
            }
            Punch::Opening {
                since,
                initiator,
                endpoint,
                ..
            } => {
                if age.is_some_and(|a| a < since.elapsed()) {
                    info!(peer = %id.short(), %endpoint, secs = since.elapsed().as_secs_f32(), "punched a direct WireGuard path");
                    p.punch = Punch::Up {
                        since: Instant::now(),
                    };
                    p.failures = 0;
                    if !initiator {
                        let cfg = PeerConfig {
                            endpoint: Some(endpoint),
                            keepalive: inputs.nat_keepalive,
                            ..peer
                        };
                        self.apply(id, cfg)?;
                    }
                } else if since.elapsed() > PUNCH_TIMEOUT {
                    info!(peer = %id.short(), %endpoint, "punch failed; retrying later");
                    self.quiet(&id)?;
                }
            }
            Punch::Up { since } => {
                // The peer's own view: does its WireGuard still handshake
                // with us? (It doesn't after a restart.)
                let peer_sees_us = inputs
                    .soft
                    .get(&id)
                    .map(|s| s.observed.iter().any(|o| o.node == node.me));
                let forgotten = peer_sees_us == Some(false) && since.elapsed() > UP_GRACE;
                if age.is_none_or(|a| a > DEAD_AFTER) || forgotten {
                    info!(peer = %id.short(), forgotten, "direct path is dead; silencing it before retrying");
                    self.quiet(&id)?;
                }
            }
            Punch::Removing { quiet_for } => {
                self.finish_punch_removal(&id)?;
                if quiet_for.is_zero() {
                    return self.step_punch(node, id, peer, inputs);
                }
            }
            Punch::Quiet { until } => {
                if self.status.contains_key(&peer.key) {
                    // Unexpected backend state must not consume a quiet period
                    // while WireGuard is still sending packets for this peer.
                    p.punch = Punch::Removing {
                        quiet_for: p.retry_delay(),
                    };
                    self.finish_punch_removal(&id)?;
                } else if Instant::now() >= until {
                    p.punch = Punch::Idle;
                }
            }
        }
        Ok(None)
    }
}

fn opener(node: &Node, to: SocketAddr) {
    if let Err(e) = cheesecloth_wg::opener::send(node.opts.wg_port, to) {
        let mut wg = node.wg.lock();
        if !wg.opener_warned {
            warn!("can't send NAT openers ({e}); punching may fail behind some routers");
            wg.opener_warned = true;
        }
    }
}

/// Initiator side of a punch.
async fn start_punch(
    node: &Arc<Node>,
    peer: NodeId,
    mine: SocketAddr,
    theirs: SocketAddr,
) -> Result<()> {
    // A relay connected to both of us times the "go".
    let relays = node.relays();
    let relay = {
        let soft = node.soft.lock();
        relays
            .into_iter()
            .filter(|r| node.net.is_connected(r))
            .find(|r| soft.get(r).is_some_and(|s| s.connected.contains(&peer)))
    }
    .context("no relay connected to both of us")?;
    let id: u64 = rand::random();
    let offer = PunchMessage::Offer {
        id,
        initiator: mine,
        responder: theirs,
    };
    let reply = node
        .net
        .request(
            peer,
            SVC_PUNCH,
            postcard::to_stdvec(&offer)?,
            Duration::from_secs(10),
        )
        .await?;
    match postcard::from_bytes::<PunchReply>(&reply)? {
        PunchReply::Accepted => {}
        PunchReply::Refused(why) => bail!("refused: {why}"),
        PunchReply::Done => bail!("unexpected reply"),
    }
    let (key, allowed) = {
        let agreed = node.agreed();
        let m = agreed
            .value
            .value
            .members
            .get(&peer)
            .context("not a member")?;
        (m.info.wg_key, allowed_ips(node, &peer, m.ipv4))
    };
    {
        let mut wg = node.wg.lock();
        if !wg.peers.get(&peer).is_some_and(|p| {
            p.path == Some(Path::Punch) && matches!(p.punch, Punch::Offered { .. })
        }) {
            bail!("punch is no longer pending");
        }
        wg.apply(
            peer,
            PeerConfig {
                key,
                endpoint: Some(theirs),
                keepalive: 0,
                allowed_ips: allowed.clone(),
            },
        )?;
        if let Some(p) = wg.peers.get_mut(&peer) {
            p.punch = Punch::Opening {
                id,
                since: Instant::now(),
                initiator: true,
                endpoint: theirs,
            };
        }
    }
    // Returns when the relay's timed delivery reaches the responder.
    node.net
        .forward_via(
            relay,
            peer,
            SVC_PUNCH,
            postcard::to_stdvec(&PunchMessage::Go { id })?,
            true,
        )
        .await?;
    opener(node, theirs);
    tokio::time::sleep(INITIATOR_DELAY).await;
    let nat_ka = wg_nat_keepalive(node);
    let mut wg = node.wg.lock();
    if !wg.peers.get(&peer).is_some_and(|p| {
        p.path == Some(Path::Punch)
            && (matches!(p.punch, Punch::Opening { id: pending, initiator: true, .. } if pending == id)
                || matches!(p.punch, Punch::Up { .. })
                    && p.applied.as_ref().is_some_and(|c| {
                        c.key == key && c.endpoint == Some(theirs)
                    }))
    }) {
        bail!("punch is no longer opening");
    }
    wg.apply(
        peer,
        PeerConfig {
            key,
            endpoint: Some(theirs),
            keepalive: nat_ka,
            allowed_ips: allowed,
        },
    )?;
    debug!(peer = %peer.short(), %theirs, via = %relay.short(), "punch: opener sent, handshake started");
    Ok(())
}

/// Responder side of a punch.
pub fn handle_punch(node: &Arc<Node>, from: NodeId, msg: PunchMessage) -> PunchReply {
    let Some((info, ipv4)) = node
        .agreed()
        .value
        .value
        .members
        .get(&from)
        .map(|m| (m.info.clone(), m.ipv4))
    else {
        return PunchReply::Refused("not a member".into());
    };
    match msg {
        PunchMessage::Offer { id, initiator, .. } => {
            let allowed = allowed_ips(node, &from, ipv4);
            let mut wg = node.wg.lock();
            let Some(p) = wg.peers.get_mut(&from) else {
                return PunchReply::Refused("not ready".into());
            };
            if p.path != Some(Path::Punch) {
                return PunchReply::Refused("no punch needed".into());
            }
            if let Punch::Quiet { until } = p.punch
                && Instant::now() >= until
            {
                p.punch = Punch::Idle;
            }
            if let Err(e) = wg.apply(
                from,
                PeerConfig {
                    key: info.wg_key,
                    endpoint: Some(initiator),
                    keepalive: 0,
                    allowed_ips: allowed,
                },
            ) {
                return PunchReply::Refused(format!("{e:#}"));
            }
            if let Some(p) = wg.peers.get_mut(&from) {
                p.punch = Punch::Opening {
                    id,
                    since: Instant::now(),
                    initiator: false,
                    endpoint: initiator,
                };
            }
            PunchReply::Accepted
        }
        PunchMessage::Go { id } => {
            let endpoint = {
                let wg = node.wg.lock();
                match wg.peers.get(&from).map(|p| &p.punch) {
                    Some(Punch::Opening {
                        id: pid,
                        endpoint,
                        initiator: false,
                        ..
                    }) if *pid == id => Some(*endpoint),
                    _ => None,
                }
            };
            match endpoint {
                Some(e) => {
                    opener(node, e);
                    PunchReply::Done
                }
                None => PunchReply::Refused("no such punch".into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        RelayMode,
        testing::{Harness, harness, harness_with},
    };

    const R_WG: &str = "203.0.113.1:51820";
    const MY_NAT: &str = "198.51.100.1:40000";
    const P_NAT: &str = "198.51.100.2:40001";

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// This node and peer 1 are behind different NATs; peer 0 is a relay
    /// that observes both.
    async fn behind_nat() -> Harness {
        let h = harness(RelayMode::Never, &[true, false]).await;
        {
            let mut f = h.node.facts.lock();
            f.public = false;
            f.wg_public.clear();
            f.ifaces.nets = vec!["10.1.0.0/24".parse().unwrap()];
        }
        let (me, p) = (h.node.me, h.peers[1].id());
        h.soft(
            0,
            SoftState {
                public: true,
                relay: true,
                wg_public: vec![sa(R_WG)],
                connected: vec![me, p],
                observed: vec![
                    Observed {
                        node: me,
                        endpoint: sa(MY_NAT),
                    },
                    Observed {
                        node: p,
                        endpoint: sa(P_NAT),
                    },
                ],
                ..Default::default()
            },
        );
        h.soft(
            1,
            SoftState {
                wg_lan: vec![sa("10.2.0.5:51820")],
                ..Default::default()
            },
        );
        h
    }

    fn applied(h: &Harness, node: &NodeId) -> Option<PeerConfig> {
        h.node.wg.lock().peers.get(node)?.applied.clone()
    }

    #[tokio::test]
    async fn reconcile_picks_a_path_for_each_peer() {
        let h = behind_nat().await;
        let (r, p) = (h.peers[0].id(), h.peers[1].id());
        // A leftover peer of a former member.
        let gone = NodeId([9; 32]);
        reconcile(&h.node);
        h.node.wg.lock().peers.insert(
            gone,
            PeerState {
                key: WgKey([9; 32]),
                path: Some(Path::Await),
                applied: None,
                punch: Punch::Idle,
                failures: 0,
                error: None,
            },
        );
        reconcile(&h.node);
        {
            let wg = h.node.wg.lock();
            assert_eq!(wg.backend_kind(), Some("mock"));
            assert!(!wg.peers.contains_key(&gone), "former member removed");
            let (kind, detail, endpoint, age) = wg.describe(&r);
            assert_eq!((kind.as_str(), detail.as_str()), ("public", "up"));
            assert_eq!(endpoint, Some(sa(R_WG)));
            assert!(age.is_some());
            let (kind, _, _, _) = wg.describe(&p);
            assert_eq!(kind, "punch");
            assert_eq!(wg.describe(&gone).0, "none");
            let observed = wg.observed(&h.node.agreed().state().members);
            assert_eq!(
                observed,
                vec![Observed {
                    node: r,
                    endpoint: sa(R_WG)
                }]
            );
        }
        let cfg = applied(&h, &r).unwrap();
        assert_eq!(cfg.keepalive, cheesecloth_core::NAT_KEEPALIVE_SECS);
        assert_eq!(cfg.allowed_ips.len(), 2);

        // Peer 1 turns out to be on our LAN, behind the same NAT.
        h.soft(
            0,
            SoftState {
                public: true,
                relay: true,
                wg_public: vec![sa(R_WG)],
                observed: vec![
                    Observed {
                        node: h.node.me,
                        endpoint: sa(MY_NAT),
                    },
                    Observed {
                        node: p,
                        endpoint: sa("198.51.100.1:40002"),
                    },
                ],
                ..Default::default()
            },
        );
        h.soft(
            1,
            SoftState {
                wg_lan: vec![sa("10.1.0.7:51820")],
                ..Default::default()
            },
        );
        reconcile(&h.node);
        assert_eq!(h.node.wg.lock().describe(&p).0, "lan");
        assert_eq!(
            applied(&h, &p).unwrap().endpoint,
            Some(sa("10.1.0.7:51820"))
        );

        h.node.wg.lock().down().unwrap();
        assert!(h.node.wg.lock().backend_kind().is_none());
    }

    #[tokio::test]
    async fn a_public_non_relay_still_has_a_direct_wireguard_path() {
        let h = behind_nat().await;
        let id = h.peers[1].id();
        let endpoint = sa("203.0.113.8:51820");
        h.soft(
            1,
            SoftState {
                public: true,
                relay: false,
                public_ip: Some(endpoint.ip()),
                wg_public: vec![endpoint],
                ..Default::default()
            },
        );
        reconcile(&h.node);
        assert!(!h.node.is_relay(&id));
        assert_eq!(h.node.wg.lock().describe(&id).0, "public");
        let cfg = applied(&h, &id).unwrap();
        assert_eq!(cfg.endpoint, Some(endpoint));
        assert_eq!(cfg.allowed_ips.len(), 2);
    }

    /// The mock, failing on demand.
    #[derive(Clone, Default)]
    struct Flaky {
        mock: Arc<parking_lot::Mutex<cheesecloth_wg::mock::Mock>>,
        fail_status: Arc<std::sync::atomic::AtomicBool>,
        fail_down: Arc<std::sync::atomic::AtomicBool>,
        down_attempts: Arc<std::sync::atomic::AtomicUsize>,
        fail_peer: Arc<parking_lot::Mutex<Option<WgKey>>>,
        fail_remove: Arc<parking_lot::Mutex<Option<WgKey>>>,
        remove_then_fail: Arc<std::sync::atomic::AtomicBool>,
        removal_attempts: Arc<parking_lot::Mutex<Vec<WgKey>>>,
    }

    impl Backend for Flaky {
        fn up(&mut self, config: &InterfaceConfig) -> Result<()> {
            self.mock.lock().up(config)
        }
        fn set_peer(&mut self, peer: &PeerConfig) -> Result<()> {
            if *self.fail_peer.lock() == Some(peer.key) {
                bail!("no buffer space available");
            }
            self.mock.lock().set_peer(peer)
        }
        fn remove_peer(&mut self, key: &WgKey) -> Result<()> {
            self.removal_attempts.lock().push(*key);
            if *self.fail_remove.lock() == Some(*key) {
                if self
                    .remove_then_fail
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    self.mock.lock().remove_peer(key)?;
                }
                bail!("deletion temporarily unavailable");
            }
            self.mock.lock().remove_peer(key)
        }
        fn status(&self) -> Result<Vec<PeerStatus>> {
            if self.fail_status.load(std::sync::atomic::Ordering::Relaxed) {
                bail!("no such device");
            }
            self.mock.lock().status()
        }
        fn down(&mut self) -> Result<()> {
            self.down_attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fail_down.load(std::sync::atomic::Ordering::SeqCst) {
                bail!("interface removal temporarily unavailable");
            }
            self.mock.lock().down()
        }
        fn kind(&self) -> &'static str {
            "mock"
        }
    }

    #[tokio::test]
    async fn failed_interface_cleanup_is_reported_retained_and_retryable() {
        use std::sync::atomic::Ordering::SeqCst;
        for force in [false, true] {
            let (d, _dir) = crate::testing::daemon("cleanup", RelayMode::Never).await;
            d.init(None).await.unwrap();
            let node = d.node().unwrap();
            node.quiesce().await;
            let flaky = Flaky::default();
            flaky.fail_down.store(true, SeqCst);
            node.wg.lock().backend = Some(Box::new(flaky.clone()));
            let result = d.leave(force).await;
            if force {
                assert!(
                    matches!(result.unwrap(), crate::api::LeaveView::Left { problems, .. } if problems.len() == 1)
                );
            } else {
                assert!(result.unwrap_err().to_string().contains("cleanup pending"));
            }
            assert_eq!(flaky.down_attempts.load(SeqCst), 1);
            assert!(node.wg.lock().backend.is_some());
            assert!(d.files.load_cleanup().unwrap().is_some());
            assert!(d.files.load_cluster().unwrap().is_some());
            assert_eq!(d.status().await.unwrap().phase, "stopping");
            assert!(d.invite().await.is_err());
            assert!(d.init(None).await.is_err());
            assert!(d.leave(false).await.is_err());
            assert_eq!(flaky.down_attempts.load(SeqCst), 2);
            flaky.fail_down.store(false, SeqCst);
            d.leave(false).await.unwrap();
            assert_eq!(flaky.down_attempts.load(SeqCst), 3);
            assert!(node.wg.lock().backend.is_none());
            assert!(d.files.load_cleanup().unwrap().is_none());
            assert!(d.files.load_cluster().unwrap().is_none());
            d.init(None).await.unwrap();
            d.shutdown().await;
        }
    }

    #[tokio::test]
    async fn failed_shutdown_cleanup_retains_membership_and_can_be_retried() {
        use std::sync::atomic::Ordering::SeqCst;
        let (d, _dir) = crate::testing::daemon("shutdown-cleanup", RelayMode::Never).await;
        d.init(None).await.unwrap();
        let node = d.node().unwrap();
        node.quiesce().await;
        let flaky = Flaky::default();
        flaky.fail_down.store(true, SeqCst);
        node.wg.lock().backend = Some(Box::new(flaky.clone()));
        d.shutdown().await;
        assert!(node.wg.lock().backend.is_some());
        assert!(!d.files.load_cleanup().unwrap().unwrap().forget_cluster);
        assert!(d.files.load_cluster().unwrap().is_some());
        flaky.fail_down.store(false, SeqCst);
        d.shutdown().await;
        assert!(node.wg.lock().backend.is_none());
        assert!(d.files.load_cleanup().unwrap().is_none());
        assert!(d.files.load_cluster().unwrap().is_some());
        let mut opts = (*d.opts).clone();
        opts.listen_port = 0;
        let restarted = crate::Daemon::start(opts).await.unwrap();
        assert_eq!(restarted.node().unwrap().cluster_id, node.cluster_id);
        restarted.shutdown().await;
    }

    #[tokio::test]
    async fn restart_resumes_cleanup_without_loading_partially_deleted_consensus() {
        let (d, _dir) = crate::testing::daemon("cleanup-restart", RelayMode::Never).await;
        d.init(None).await.unwrap();
        d.node().unwrap().quiesce().await;
        // Interface removal succeeds, but state deletion fails halfway through.
        std::fs::create_dir(d.files.transitions()).unwrap();
        assert!(d.leave(false).await.is_err());
        assert!(!d.files.acceptor().exists());
        assert!(d.files.load_cleanup().unwrap().is_some());
        let mut opts = (*d.opts).clone();
        opts.listen_port = 0;
        d.shutdown().await;
        drop(d);
        let restarted = crate::Daemon::start(opts).await.unwrap();
        assert_eq!(restarted.status().await.unwrap().phase, "stopping");
        assert!(restarted.node().is_none());
        std::fs::remove_dir(restarted.files.transitions()).unwrap();
        restarted.leave(false).await.unwrap();
        assert!(restarted.files.load_cleanup().unwrap().is_none());
        restarted.init(None).await.unwrap();
        restarted.shutdown().await;
    }

    async fn remove_member(h: &Harness, id: NodeId) -> Member {
        let mut chosen = (*h.node.agreed()).clone();
        let member = chosen.value.value.members.remove(&id).unwrap();
        chosen.value.version += 1;
        h.learn(chosen).await.unwrap();
        member
    }

    async fn restore_member(h: &Harness, id: NodeId, member: Member) {
        let mut chosen = (*h.node.agreed()).clone();
        chosen.value.value.members.insert(id, member);
        chosen.value.version += 1;
        h.learn(chosen).await.unwrap();
    }

    #[tokio::test]
    async fn failed_revocations_are_retried_and_reported_without_blocking_other_peers() {
        let h = harness(RelayMode::Never, &[true, true]).await;
        let flaky = Flaky::default();
        h.node.wg.lock().backend = Some(Box::new(flaky.clone()));
        reconcile(&h.node);
        let (gone, staying) = (h.peers[0].id(), h.peers[1].id());
        let member = remove_member(&h, gone).await;
        let key = member.info.wg_key;
        *flaky.fail_remove.lock() = Some(key);
        for attempt in 1..=3 {
            reconcile(&h.node);
            assert_eq!(flaky.removal_attempts.lock().len(), attempt);
            assert!(flaky.mock.lock().peers.contains_key(&key));
            assert!(applied(&h, &staying).is_some());
            let wg = h.node.wg.lock();
            assert!(
                !wg.peers.contains_key(&gone),
                "revoked nodes have no active peer state"
            );
            assert!(wg.removals.contains_key(&key));
            let warnings = wg.warnings();
            assert_eq!(warnings.len(), 1);
            assert!(warnings[0].contains("removal pending"));
            assert!(warnings[0].contains(&key.to_string()));
        }
        // No active entry remains through which a late punch could re-add it.
        let stale = flaky.mock.lock().peers[&key].clone();
        assert!(h.node.wg.lock().apply(gone, stale).is_err());
        *flaky.fail_remove.lock() = None;
        reconcile(&h.node);
        assert!(!flaky.mock.lock().peers.contains_key(&key));
        assert!(h.node.wg.lock().warnings().is_empty());
        assert!(h.node.wg.lock().removals.is_empty());
        reconcile(&h.node);
        assert_eq!(
            flaky.removal_attempts.lock().len(),
            4,
            "finished work is not repeated"
        );
    }

    #[tokio::test]
    async fn known_revocations_do_not_wait_for_a_successful_status_read() {
        let h = harness(RelayMode::Never, &[true]).await;
        let flaky = Flaky::default();
        h.node.wg.lock().backend = Some(Box::new(flaky.clone()));
        reconcile(&h.node);
        let key = remove_member(&h, h.peers[0].id()).await.info.wg_key;
        flaky
            .fail_status
            .store(true, std::sync::atomic::Ordering::Relaxed);
        reconcile(&h.node);
        assert_eq!(*flaky.removal_attempts.lock(), [key]);
        assert!(!flaky.mock.lock().peers.contains_key(&key));
        assert!(h.node.wg.lock().removals.is_empty());
        assert!(h.node.wg.lock().warnings()[0].contains("reading the interface"));
    }

    #[tokio::test]
    async fn untracked_backend_keys_are_removed_and_failed_deletions_survive_read_errors() {
        let h = harness(RelayMode::Never, &[]).await;
        let flaky = Flaky::default();
        h.node.wg.lock().backend = Some(Box::new(flaky.clone()));
        let key = WgKey([7; 32]);
        flaky
            .mock
            .lock()
            .set_peer(&PeerConfig {
                key,
                endpoint: Some(sa(P_NAT)),
                keepalive: 25,
                allowed_ips: vec!["100.64.0.7/32".parse().unwrap()],
            })
            .unwrap();
        *flaky.fail_remove.lock() = Some(key);
        reconcile(&h.node);
        assert!(h.node.wg.lock().peers.is_empty());
        assert!(h.node.wg.lock().removals.contains_key(&key));
        // This key has never had a NodeId entry. Retained removal work is
        // sufficient even if subsequent reads fail.
        flaky
            .fail_status
            .store(true, std::sync::atomic::Ordering::Relaxed);
        reconcile(&h.node);
        assert_eq!(flaky.removal_attempts.lock().len(), 2);
        *flaky.fail_remove.lock() = None;
        reconcile(&h.node);
        assert!(flaky.mock.lock().peers.is_empty());
        assert!(h.node.wg.lock().removals.is_empty());
        flaky
            .fail_status
            .store(false, std::sync::atomic::Ordering::Relaxed);
        reconcile(&h.node);
        assert!(h.node.wg.lock().warnings().is_empty());
    }

    #[tokio::test]
    async fn observed_absence_completes_a_removal_whose_answer_was_an_error() {
        let h = harness(RelayMode::Never, &[true]).await;
        let flaky = Flaky::default();
        h.node.wg.lock().backend = Some(Box::new(flaky.clone()));
        reconcile(&h.node);
        let key = remove_member(&h, h.peers[0].id()).await.info.wg_key;
        *flaky.fail_remove.lock() = Some(key);
        flaky
            .remove_then_fail
            .store(true, std::sync::atomic::Ordering::Relaxed);
        reconcile(&h.node);
        assert!(h.node.wg.lock().removals.contains_key(&key));
        assert!(!flaky.mock.lock().peers.contains_key(&key));
        reconcile(&h.node);
        assert_eq!(
            *flaky.removal_attempts.lock(),
            [key],
            "fresh absence needs no further deletion"
        );
        assert!(h.node.wg.lock().warnings().is_empty());
    }

    #[tokio::test]
    async fn a_rejoined_key_cancels_its_old_removal() {
        let h = harness(RelayMode::Never, &[true]).await;
        let flaky = Flaky::default();
        h.node.wg.lock().backend = Some(Box::new(flaky.clone()));
        reconcile(&h.node);
        let id = h.peers[0].id();
        let mut member = remove_member(&h, id).await;
        let key = member.info.wg_key;
        *flaky.fail_remove.lock() = Some(key);
        reconcile(&h.node);
        assert!(h.node.wg.lock().removals.contains_key(&key));
        member.ipv4 = Ipv4Addr::new(100, 64, 0, 99);
        restore_member(&h, id, member).await;
        reconcile(&h.node);
        assert_eq!(
            *flaky.removal_attempts.lock(),
            [key],
            "the old removal was cancelled"
        );
        assert!(
            flaky.mock.lock().peers[&key]
                .allowed_ips
                .contains(&"100.64.0.99/32".parse().unwrap())
        );
        assert!(h.node.wg.lock().warnings().is_empty());
    }

    #[tokio::test]
    async fn rejoining_with_a_new_key_still_removes_the_old_key() {
        let h = harness(RelayMode::Never, &[true]).await;
        let flaky = Flaky::default();
        h.node.wg.lock().backend = Some(Box::new(flaky.clone()));
        reconcile(&h.node);
        let id = h.peers[0].id();
        let mut member = remove_member(&h, id).await;
        let old = member.info.wg_key;
        *flaky.fail_remove.lock() = Some(old);
        reconcile(&h.node);
        let new = WgKey([11; 32]);
        member.info.wg_key = new;
        member.signed_info = h.peers[0]
            .identity
            .seal(cheesecloth_core::Domain::MemberInfo, &member.info);
        restore_member(&h, id, member).await;
        *flaky.fail_remove.lock() = None;
        reconcile(&h.node);
        assert!(!flaky.mock.lock().peers.contains_key(&old));
        assert!(flaky.mock.lock().peers.contains_key(&new));
        assert_eq!(applied(&h, &id).unwrap().key, new);
        assert!(h.node.wg.lock().warnings().is_empty());
    }

    #[tokio::test]
    async fn missing_authorized_backend_peers_are_reinstalled() {
        let h = harness(RelayMode::Never, &[true]).await;
        let flaky = Flaky::default();
        h.node.wg.lock().backend = Some(Box::new(flaky.clone()));
        reconcile(&h.node);
        let cfg = applied(&h, &h.peers[0].id()).unwrap();
        flaky.mock.lock().remove_peer(&cfg.key).unwrap();
        reconcile(&h.node);
        assert_eq!(flaky.mock.lock().peers.get(&cfg.key), Some(&cfg));
    }

    #[tokio::test]
    async fn a_quiet_period_starts_only_when_the_backend_peer_is_removed() {
        let h = behind_nat().await;
        let flaky = Flaky::default();
        h.node.wg.lock().backend = Some(Box::new(flaky.clone()));
        reconcile(&h.node);
        let id = h.peers[1].id();
        let key = h.peers[1].info.wg_key;
        {
            let mut wg = h.node.wg.lock();
            wg.apply(
                id,
                PeerConfig {
                    key,
                    endpoint: Some(sa(P_NAT)),
                    keepalive: 25,
                    allowed_ips: vec![],
                },
            )
            .unwrap();
            *flaky.fail_remove.lock() = Some(key);
            let result = wg.quiet(&id);
            assert!(result.is_err());
            wg.note_peer(&id, result);
            assert!(wg.peers[&id].applied.is_some());
            assert!(matches!(wg.peers[&id].punch, Punch::Removing { .. }));
        }
        reconcile(&h.node);
        assert!(matches!(punch_of(&h, &id), Punch::Removing { .. }));
        assert_eq!(
            h.node.wg.lock().peers[&id].failures,
            1,
            "deletion retries are not new punch attempts"
        );
        assert!(flaky.mock.lock().peers.contains_key(&key));
        assert!(h.node.wg.lock().warnings()[0].contains("removing peer"));
        let offer = PunchMessage::Offer {
            id: 19,
            initiator: sa(P_NAT),
            responder: sa(MY_NAT),
        };
        assert!(matches!(
            handle_punch(&h.node, id, offer.clone()),
            PunchReply::Refused(_)
        ));
        *flaky.fail_remove.lock() = None;
        let succeeded_after = Instant::now();
        reconcile(&h.node);
        let Punch::Quiet { until } = punch_of(&h, &id) else {
            panic!("not quiet")
        };
        assert!(until >= succeeded_after + REPUNCH_QUIET);
        assert!(!flaky.mock.lock().peers.contains_key(&key));
        assert!(applied(&h, &id).is_none());
        assert!(h.node.wg.lock().warnings().is_empty());
        assert!(
            matches!(handle_punch(&h.node, id, offer), PunchReply::Refused(_)),
            "an offer cannot shorten the quiet period"
        );
    }

    #[tokio::test]
    async fn fresh_absence_starts_the_quiet_period_after_an_ambiguous_removal() {
        let h = behind_nat().await;
        let flaky = Flaky::default();
        h.node.wg.lock().backend = Some(Box::new(flaky.clone()));
        reconcile(&h.node);
        let id = h.peers[1].id();
        let key = h.peers[1].info.wg_key;
        {
            let mut wg = h.node.wg.lock();
            wg.apply(
                id,
                PeerConfig {
                    key,
                    endpoint: Some(sa(P_NAT)),
                    keepalive: 25,
                    allowed_ips: vec![],
                },
            )
            .unwrap();
            *flaky.fail_remove.lock() = Some(key);
            flaky
                .remove_then_fail
                .store(true, std::sync::atomic::Ordering::Relaxed);
            let result = wg.quiet(&id);
            assert!(result.is_err());
            wg.note_peer(&id, result);
        }
        let attempts = flaky.removal_attempts.lock().len();
        let observed_after = Instant::now();
        reconcile(&h.node);
        let Punch::Quiet { until } = punch_of(&h, &id) else {
            panic!("not quiet")
        };
        assert!(until >= observed_after + REPUNCH_QUIET);
        assert_eq!(flaky.removal_attempts.lock().len(), attempts);
        assert!(applied(&h, &id).is_none());
        assert!(h.node.wg.lock().warnings().is_empty());
    }

    #[tokio::test]
    async fn a_path_reset_retries_removal_until_a_public_path_replaces_it() {
        let h = behind_nat().await;
        let flaky = Flaky::default();
        h.node.wg.lock().backend = Some(Box::new(flaky.clone()));
        let id = h.peers[1].id();
        let key = h.peers[1].info.wg_key;
        h.soft(
            1,
            SoftState {
                wg_public: vec![sa(P_NAT)],
                ..Default::default()
            },
        );
        reconcile(&h.node);
        assert_eq!(h.node.wg.lock().describe(&id).0, "public");
        *flaky.fail_remove.lock() = Some(key);
        h.soft(1, SoftState::default());
        for attempts in 1..=2 {
            assert!(
                reconcile(&h.node).is_empty(),
                "cannot punch until removal succeeds"
            );
            assert_eq!(flaky.removal_attempts.lock().len(), attempts);
            assert!(
                matches!(punch_of(&h, &id), Punch::Removing { quiet_for } if quiet_for.is_zero())
            );
            assert!(applied(&h, &id).is_some());
        }
        let new_endpoint = sa("198.51.100.3:51820");
        h.soft(
            1,
            SoftState {
                wg_public: vec![new_endpoint],
                ..Default::default()
            },
        );
        reconcile(&h.node);
        assert_eq!(flaky.removal_attempts.lock().len(), 2);
        assert_eq!(flaky.mock.lock().peers[&key].endpoint, Some(new_endpoint));
        assert!(matches!(punch_of(&h, &id), Punch::Idle));
        assert!(h.node.wg.lock().warnings().is_empty());
    }

    #[tokio::test]
    async fn a_failing_peer_doesnt_stop_the_others() {
        // Two relays: public paths to both.
        let h = harness(RelayMode::Never, &[true, true]).await;
        let flaky = Flaky::default();
        h.node.wg.lock().backend = Some(Box::new(flaky.clone()));
        let (first, second) = {
            let mut ids = [h.peers[0].id(), h.peers[1].id()];
            ids.sort();
            (ids[0], ids[1])
        };
        let key = h.node.agreed().state().members[&first].info.wg_key;
        *flaky.fail_peer.lock() = Some(key);
        reconcile(&h.node);
        assert!(applied(&h, &first).is_none());
        assert!(
            applied(&h, &second).is_some(),
            "configured despite the first"
        );
        let warnings = h.node.wg.lock().warnings();
        assert_eq!(
            warnings,
            vec![format!(
                "WireGuard peer {}: no buffer space available",
                first.short()
            )]
        );
        // Retried on the next pass; the warning is removed when it succeeds.
        *flaky.fail_peer.lock() = None;
        reconcile(&h.node);
        assert!(applied(&h, &first).is_some());
        assert!(h.node.wg.lock().warnings().is_empty());
    }

    #[tokio::test]
    async fn an_unreadable_interface_is_reported() {
        let h = harness(RelayMode::Never, &[true]).await;
        let flaky = Flaky::default();
        h.node.wg.lock().backend = Some(Box::new(flaky.clone()));
        let p = h.peers[0].id();
        flaky
            .fail_status
            .store(true, std::sync::atomic::Ordering::Relaxed);
        // The pass stops: nothing is configured without the interface state.
        reconcile(&h.node);
        assert!(applied(&h, &p).is_none());
        assert_eq!(
            h.node.wg.lock().warnings(),
            vec!["WireGuard: reading the interface: no such device".to_string()]
        );
        flaky
            .fail_status
            .store(false, std::sync::atomic::Ordering::Relaxed);
        reconcile(&h.node);
        assert!(applied(&h, &p).is_some());
        assert!(h.node.wg.lock().warnings().is_empty());
    }

    #[tokio::test]
    async fn a_public_node_waits_for_nated_peers() {
        // Advertised, so it doesn't depend on the host having a global address.
        let h = harness_with(RelayMode::Always, &[false], |o| {
            o.advertise = vec!["203.0.113.1".parse().unwrap()]
        })
        .await;
        let p = h.peers[0].id();
        reconcile(&h.node);
        let wg = h.node.wg.lock();
        let (kind, detail, _, _) = wg.describe(&p);
        assert_eq!(
            (kind.as_str(), detail.as_str()),
            ("await", "no handshake yet")
        );
        assert_eq!(wg.peers[&p].applied.as_ref().unwrap().endpoint, None);
        // Public: no keepalive, except on punched paths.
        assert_eq!(h.node.wg_keepalive(), 0);
        assert_eq!(
            wg_nat_keepalive(&h.node),
            cheesecloth_core::NAT_KEEPALIVE_SECS
        );
    }

    /// A peer in the punch state `punch`, with a WireGuard key of its own.
    fn punch_peer(h: &Harness, id: NodeId, punch: Punch) {
        h.node.wg.lock().peers.insert(
            id,
            PeerState {
                key: WgKey(id.0),
                path: Some(Path::Punch),
                applied: None,
                punch,
                failures: 0,
                error: None,
            },
        );
    }

    fn step(h: &Harness, id: NodeId, inputs: &Inputs) -> Option<PunchStart> {
        let peer = PeerConfig {
            key: WgKey(id.0),
            endpoint: None,
            keepalive: 25,
            allowed_ips: vec![],
        };
        let mut wg = h.node.wg.lock();
        wg.step_punch(&h.node, id, peer, inputs).unwrap()
    }

    fn punch_of(h: &Harness, id: &NodeId) -> Punch {
        h.node.wg.lock().peers[id].punch.clone()
    }

    fn handshake(h: &Harness, id: NodeId, ago: Duration) {
        h.node.wg.lock().status.insert(
            WgKey(id.0),
            PeerStatus {
                key: WgKey(id.0),
                endpoint: Some(sa(P_NAT)),
                last_handshake: Some(std::time::SystemTime::now() - ago),
                rx_bytes: 0,
                tx_bytes: 0,
                keepalive: 25,
            },
        );
    }

    #[tokio::test]
    async fn the_punch_state_machine() {
        let h = harness(RelayMode::Never, &[]).await;
        let mut inputs = Inputs::gather(&h.node).unwrap();
        assert!(h.node.wg.lock().ensure_up(&h.node, inputs.my_ipv4));
        // The lower node ID initiates.
        let (lo, hi) = (NodeId([0; 32]), NodeId([0xff; 32]));
        inputs.observed.insert(h.node.me, sa(MY_NAT));
        inputs.observed.insert(lo, sa(P_NAT));
        inputs.observed.insert(hi, sa(P_NAT));
        let ago = |s| Instant::now() - Duration::from_secs(s);

        // Idle: the initiator offers, the other side waits.
        punch_peer(&h, hi, Punch::Idle);
        punch_peer(&h, lo, Punch::Idle);
        assert_eq!(h.node.wg.lock().describe(&hi).1, "waiting to punch");
        assert_eq!(step(&h, hi, &inputs), Some((hi, sa(MY_NAT), sa(P_NAT))));
        assert!(matches!(punch_of(&h, &hi), Punch::Offered { .. }));
        assert_eq!(h.node.wg.lock().describe(&hi).1, "offer sent");
        assert_eq!(step(&h, lo, &inputs), None);
        assert!(matches!(punch_of(&h, &lo), Punch::Idle));

        // An unanswered offer is given up, and retried after a quiet period.
        punch_peer(&h, hi, Punch::Offered { since: ago(16) });
        step(&h, hi, &inputs);
        assert!(matches!(punch_of(&h, &hi), Punch::Quiet { .. }));
        assert!(
            h.node
                .wg
                .lock()
                .describe(&hi)
                .1
                .starts_with("no path; retry in")
        );
        punch_peer(
            &h,
            hi,
            Punch::Quiet {
                until: Instant::now(),
            },
        );
        step(&h, hi, &inputs);
        assert!(matches!(punch_of(&h, &hi), Punch::Idle));

        // Opening: a handshake since the punch began means it worked. The
        // responder then sets the endpoint and keepalive.
        let opening = |since| Punch::Opening {
            id: 1,
            since,
            initiator: false,
            endpoint: sa(P_NAT),
        };
        punch_peer(&h, lo, opening(ago(2)));
        assert_eq!(h.node.wg.lock().describe(&lo).1, "punching");
        handshake(&h, lo, Duration::from_secs(1));
        step(&h, lo, &inputs);
        assert!(matches!(punch_of(&h, &lo), Punch::Up { .. }));
        let cfg = applied(&h, &lo).unwrap();
        assert_eq!(cfg.endpoint, Some(sa(P_NAT)));
        assert_eq!(cfg.keepalive, inputs.nat_keepalive);
        // ... and no handshake before the timeout means it failed.
        punch_peer(&h, hi, opening(ago(11)));
        step(&h, hi, &inputs);
        assert!(matches!(punch_of(&h, &hi), Punch::Quiet { .. }));
        assert!(applied(&h, &hi).is_none());

        // Up: stays up while handshakes continue and the peer sees us.
        inputs.soft.insert(
            lo,
            SoftState {
                observed: vec![Observed {
                    node: h.node.me,
                    endpoint: sa(MY_NAT),
                }],
                ..Default::default()
            },
        );
        punch_peer(&h, lo, Punch::Up { since: ago(60) });
        step(&h, lo, &inputs);
        assert!(matches!(punch_of(&h, &lo), Punch::Up { .. }));
        // The peer forgot us (it restarted): dead.
        inputs.soft.get_mut(&lo).unwrap().observed.clear();
        step(&h, lo, &inputs);
        assert!(matches!(punch_of(&h, &lo), Punch::Quiet { .. }));
        // No handshakes for too long: dead.
        punch_peer(&h, hi, Punch::Up { since: ago(60) });
        handshake(&h, hi, DEAD_AFTER + Duration::from_secs(1));
        step(&h, hi, &inputs);
        assert!(matches!(punch_of(&h, &hi), Punch::Quiet { .. }));
        assert!(
            h.node
                .wg
                .lock()
                .describe(&hi)
                .1
                .starts_with("no path; retry in 3")
        );
    }

    #[tokio::test]
    async fn repeated_failures_retry_slowly() {
        let h = harness(RelayMode::Never, &[]).await;
        let id = NodeId([0xff; 32]);
        punch_peer(&h, id, Punch::Idle);
        let mut wg = h.node.wg.lock();
        assert!(wg.ensure_up(&h.node, Ipv4Addr::new(100, 64, 0, 1)));
        for i in 1..=FAST_RETRIES + 1 {
            wg.quiet(&id).unwrap();
            let Punch::Quiet { until } = wg.peers[&id].punch else {
                panic!()
            };
            let wait = until - Instant::now();
            if i <= FAST_RETRIES {
                assert!(wait <= REPUNCH_QUIET, "{i}: {wait:?}");
            } else {
                assert!(wait > REPUNCH_QUIET, "{i}: {wait:?}");
            }
        }
    }

    #[tokio::test]
    async fn the_responder_answers_offers_and_go() {
        let h = behind_nat().await;
        let (r, p) = (h.peers[0].id(), h.peers[1].id());
        let offer = |id| PunchMessage::Offer {
            id,
            initiator: sa(P_NAT),
            responder: sa(MY_NAT),
        };
        let refused = |reply: PunchReply, why: &str| match reply {
            PunchReply::Refused(w) => assert!(w.contains(why), "{w}"),
            other => panic!("{other:?}"),
        };
        refused(
            handle_punch(&h.node, NodeId([7; 32]), offer(1)),
            "not a member",
        );
        refused(handle_punch(&h.node, p, offer(1)), "not ready");
        reconcile(&h.node);
        refused(handle_punch(&h.node, r, offer(1)), "no punch needed");

        assert!(matches!(
            handle_punch(&h.node, p, offer(7)),
            PunchReply::Accepted
        ));
        assert!(matches!(
            punch_of(&h, &p),
            Punch::Opening {
                id: 7,
                initiator: false,
                ..
            }
        ));
        assert_eq!(applied(&h, &p).unwrap().endpoint, Some(sa(P_NAT)));
        refused(
            handle_punch(&h.node, p, PunchMessage::Go { id: 8 }),
            "no such punch",
        );
        // The opener itself needs privileges the tests don't have; the reply
        // doesn't depend on it.
        assert!(matches!(
            handle_punch(&h.node, p, PunchMessage::Go { id: 7 }),
            PunchReply::Done
        ));
    }

    #[tokio::test]
    async fn a_punch_needs_a_relay_connected_to_both() {
        let h = behind_nat().await;
        let p = h.peers[1].id();
        let e = start_punch(&h.node, p, sa(MY_NAT), sa(P_NAT))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("no relay connected"), "{e:#}");
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_failed_interface_is_retried_later() {
        let h = harness(RelayMode::Never, &[]).await;
        let mut wg = h.node.wg.lock();
        wg.kind = cheesecloth_wg::BackendKind::Kernel;
        let ip = Ipv4Addr::new(100, 64, 0, 1);
        assert!(!wg.ensure_up(&h.node, ip));
        let err = wg.error().unwrap();
        assert!(err.contains("kernel"), "{err}");
        // Not retried right away.
        wg.kind = cheesecloth_wg::BackendKind::Mock;
        assert!(!wg.ensure_up(&h.node, ip));
        wg.error = Some((err, Instant::now() - Duration::from_secs(31)));
        assert!(wg.ensure_up(&h.node, ip));
        assert!(wg.error().is_none());
    }
}
