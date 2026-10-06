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

/// The WireGuard keepalive for punched paths: `--keepalive` if set and not
/// off, else the NAT default. Never off, or the NAT mapping would expire.
fn wg_nat_keepalive(node: &Node) -> u16 {
    match node.opts.keepalive {
        Some(k) if k > 0 => k,
        _ => cheesecloth_core::NAT_KEEPALIVE_SECS,
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
mod tests;
