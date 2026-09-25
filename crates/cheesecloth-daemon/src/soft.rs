//! Soft state: fast-changing facts that don't go through consensus
//! (addresses, connections, WireGuard endpoints seen by each kernel), and the
//! version of the agreed state each node holds.
//!
//! Every node signs its own entry and publishes it only when it changes. A node
//! that learns a newer entry passes just that entry on to its other
//! connections, so changes spread through the relays. The whole table is sent
//! only when a connection comes up, so a new or reconnected node catches up.
//! Signatures mean no node can forge another's entry.

use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use cheesecloth_core::{Domain, NodeId, Signed};
use rand::{Rng, seq::IndexedRandom};
use serde::{Deserialize, Serialize};

/// Entries from nodes that aren't members yet (as far as this node knows) are
/// kept aside, up to this many, and retried when the membership changes.
const MAX_PARKED: usize = 256;
const MAX_ENTRY_BYTES: usize = 128 << 10;
const MAX_ADDRESSES: usize = 32;
const MAX_PEERS: usize = 1024;
pub(crate) const MAX_BATCH_BYTES: usize = 256 << 10;
pub(crate) const JOIN_SEED_BYTES: usize = 64 << 10;

/// A WireGuard peer endpoint that this node's kernel recently handshook with.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Observed {
    pub node: NodeId,
    pub endpoint: SocketAddr,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftState {
    pub node: NodeId,
    /// Publication time (ms); newer entries replace older ones.
    pub seq: u64,
    /// Confirmed publicly reachable.
    pub public: bool,
    /// Currently accepting control-plane forwarding requests.
    pub relay: bool,
    /// Public only through a router port mapping: the node is itself behind
    /// NAT, so its kernel's view of other nodes' endpoints may be rewritten by
    /// its router and is trusted less.
    pub via_mapping: bool,
    /// The node's public IP: its own if public, else as a relay observed it.
    pub public_ip: Option<IpAddr>,
    /// Current control-plane addresses.
    pub control_addrs: Vec<SocketAddr>,
    /// WireGuard endpoints on the public internet (public nodes only).
    pub wg_public: Vec<SocketAddr>,
    /// WireGuard endpoints on the node's LANs.
    pub wg_lan: Vec<SocketAddr>,
    /// Members this node has a live control-plane connection to (sorted).
    pub connected: Vec<NodeId>,
    /// WireGuard peer endpoints in this node's kernel with recent handshakes
    /// (sorted).
    pub observed: Vec<Observed>,
    /// The version of the agreed state this node holds. A node that sees a
    /// higher one fetches the state from this node.
    pub version: u64,
}

impl SoftState {
    fn valid(&self) -> bool {
        fn unique<T: Ord>(items: &[T], max: usize) -> bool {
            items.len() <= max && items.iter().collect::<BTreeSet<_>>().len() == items.len()
        }
        unique(&self.control_addrs, MAX_ADDRESSES)
            && unique(&self.wg_public, MAX_ADDRESSES)
            && unique(&self.wg_lan, MAX_ADDRESSES)
            && unique(&self.connected, MAX_PEERS)
            && self.observed.len() <= MAX_PEERS
            && self
                .observed
                .iter()
                .map(|o| o.node)
                .collect::<BTreeSet<_>>()
                .len()
                == self.observed.len()
    }

    /// Apply the same bounds to our own publication. Discovery is a hint;
    /// membership and certificates remain complete in the agreed state.
    pub fn bound(&mut self) {
        fn bound<T: Ord>(items: &mut Vec<T>, max: usize) {
            items.sort();
            items.dedup();
            items.truncate(max);
        }
        bound(&mut self.control_addrs, MAX_ADDRESSES);
        bound(&mut self.wg_public, MAX_ADDRESSES);
        bound(&mut self.wg_lan, MAX_ADDRESSES);
        bound(&mut self.connected, MAX_PEERS);
        self.observed.sort();
        self.observed.dedup_by_key(|o| o.node);
        self.observed.truncate(MAX_PEERS);
    }

    /// Same content, ignoring the publication time.
    pub fn same_as(&self, other: &SoftState) -> bool {
        SoftState {
            seq: 0,
            ..self.clone()
        } == SoftState {
            seq: 0,
            ..other.clone()
        }
    }
}

#[derive(Default)]
pub struct SoftTable {
    entries: HashMap<NodeId, (SoftState, Signed<SoftState>)>,
    parked: HashMap<NodeId, (u64, Signed<SoftState>)>,
    fetch_failures: HashMap<NodeId, (u32, Instant)>,
}

impl SoftTable {
    /// Merges an entry if it's validly signed, from a member and newer than
    /// ours. Returns true if it changed the table. Valid entries from unknown
    /// nodes are parked (see `retry_parked`).
    pub fn merge(
        &mut self,
        signed: Signed<SoftState>,
        is_member: impl Fn(&NodeId) -> bool,
    ) -> bool {
        if signed.body.len() > MAX_ENTRY_BYTES {
            return false;
        }
        let Ok(st) = signed.open(Domain::SoftState) else {
            return false;
        };
        if st.node != signed.signer || !st.valid() {
            return false;
        }
        if let Some((cur, _)) = self.entries.get(&st.node)
            && cur.seq >= st.seq
        {
            return false;
        }
        if !is_member(&st.node) {
            let newer = self
                .parked
                .get(&st.node)
                .is_none_or(|(seq, _)| *seq < st.seq);
            if newer && (self.parked.len() < MAX_PARKED || self.parked.contains_key(&st.node)) {
                self.parked.insert(st.node, (st.seq, signed));
            }
            return false;
        }
        self.parked.remove(&st.node);
        self.entries.insert(st.node, (st, signed));
        true
    }

    /// Merges parked entries whose nodes have since become members. Returns the
    /// entries that were merged.
    pub fn retry_parked(&mut self, is_member: impl Fn(&NodeId) -> bool) -> Vec<Signed<SoftState>> {
        let ready: Vec<NodeId> = self
            .parked
            .keys()
            .filter(|n| is_member(n))
            .copied()
            .collect();
        let mut merged = Vec::new();
        for n in ready {
            if let Some((_, signed)) = self.parked.remove(&n)
                && self.merge(signed.clone(), &is_member)
            {
                merged.push(signed);
            }
        }
        merged
    }

    pub fn get(&self, node: &NodeId) -> Option<&SoftState> {
        self.entries.get(node).map(|(s, _)| s)
    }

    pub fn all(&self) -> impl Iterator<Item = &SoftState> {
        self.entries.values().map(|(s, _)| s)
    }

    /// The nodes known to be alive, seen from `me`, which is connected to
    /// `direct`: the nodes reached from `me` by following connections, first
    /// its own, then those listed by nodes already reached.
    ///
    /// A live node's entry is current: it publishes again soon after a
    /// connection comes or goes. A node that stopped keeps its last entry,
    /// but once its connections time out no live node leads to it, so the
    /// connections that entry lists don't count.
    pub fn live(&self, me: NodeId, direct: impl IntoIterator<Item = NodeId>) -> BTreeSet<NodeId> {
        let mut live = BTreeSet::from([me]);
        let mut todo: Vec<NodeId> = direct.into_iter().collect();
        while let Some(n) = todo.pop() {
            if live.insert(n)
                && let Some(s) = self.get(&n)
            {
                todo.extend(s.connected.iter().copied());
            }
        }
        live
    }

    /// A node to fetch the agreed state from, with the version it holds: one
    /// of the `live` nodes with the highest version above `ours`, chosen at
    /// random. Failed or unhelpful sources are temporarily excluded, allowing
    /// a lower advertised version to supply useful verified progress.
    pub fn fetch_source(
        &self,
        live: &BTreeSet<NodeId>,
        ours: u64,
        rng: &mut impl Rng,
    ) -> Option<(NodeId, u64)> {
        self.fetch_source_at(live, ours, rng, Instant::now())
    }

    fn fetch_source_at(
        &self,
        live: &BTreeSet<NodeId>,
        ours: u64,
        rng: &mut impl Rng,
        now: Instant,
    ) -> Option<(NodeId, u64)> {
        let newer: Vec<&SoftState> = self
            .all()
            .filter(|s| s.version > ours && live.contains(&s.node))
            .filter(|s| {
                self.fetch_failures
                    .get(&s.node)
                    .is_none_or(|(_, retry)| *retry <= now)
            })
            .collect();
        let best = newer.iter().map(|s| s.version).max()?;
        let at_best: Vec<NodeId> = newer
            .iter()
            .filter(|s| s.version == best)
            .map(|s| s.node)
            .collect();
        at_best.choose(rng).map(|n| (*n, best))
    }

    pub fn fetched(&mut self, node: NodeId, progress: bool, now: Instant) {
        if progress {
            self.fetch_failures.remove(&node);
        } else if self.entries.contains_key(&node) {
            let failures = self
                .fetch_failures
                .get(&node)
                .map_or(1, |(n, _)| n.saturating_add(1));
            let delay = Duration::from_secs((2u64.saturating_pow(failures.min(8))).min(300));
            self.fetch_failures.insert(node, (failures, now + delay));
        }
    }

    /// Every signed entry, for a new connection.
    pub fn signed(&self) -> Vec<Signed<SoftState>> {
        self.entries.values().map(|(_, s)| s.clone()).collect()
    }

    /// A small discovery seed for admission. The admitting member and relays
    /// come first; the rest arrives through normal batched synchronization.
    pub fn seed(&self, me: NodeId) -> Vec<Signed<SoftState>> {
        let mut entries: Vec<_> = self.entries.values().collect();
        entries.sort_by_key(|(s, _)| (s.node != me, !s.relay, s.node));
        let mut bytes = 10;
        entries
            .into_iter()
            .filter_map(|(_, signed)| {
                let size = postcard::to_stdvec(signed).expect("serializable").len();
                if bytes + size > JOIN_SEED_BYTES {
                    return None;
                }
                bytes += size;
                Some(signed.clone())
            })
            .collect()
    }

    /// Drops the entries of nodes that are no longer members.
    pub fn prune(&mut self, is_member: impl Fn(&NodeId) -> bool) {
        self.entries.retain(|n, _| is_member(n));
        self.fetch_failures.retain(|n, _| is_member(n));
    }

    /// `node`'s endpoint as observed by a public node: a relay's kernel sees
    /// the NAT mapping of the node's WireGuard port.
    ///
    /// Nodes with a public address of their own are preferred over nodes that
    /// are public only through a port mapping; among equals, the most recently
    /// published observation wins.
    pub fn observed_by_public(&self, node: &NodeId) -> Option<SocketAddr> {
        self.all()
            .filter(|s| s.public && s.node != *node)
            .flat_map(|s| s.observed.iter().map(move |o| (s, o)))
            .filter(|(_, o)| o.node == *node)
            .max_by_key(|(s, _)| (!s.via_mapping, s.seq))
            .map(|(_, o)| o.endpoint)
    }

    /// One pass over all observations, for a coherent reconciliation snapshot.
    pub fn observations(
        &self,
        targets: impl IntoIterator<Item = NodeId>,
    ) -> HashMap<NodeId, SocketAddr> {
        // Only index current members, even if a peer advertises observations
        // of unrelated IDs. Temporary storage remains proportional to members.
        let mut best: HashMap<_, Option<((bool, u64), SocketAddr)>> =
            targets.into_iter().map(|id| (id, None)).collect();
        for s in self.all().filter(|s| s.public) {
            for o in s.observed.iter().filter(|o| o.node != s.node) {
                let Some(entry) = best.get_mut(&o.node) else {
                    continue;
                };
                let rank = (!s.via_mapping, s.seq);
                if entry.is_none_or(|(old, _)| rank >= old) {
                    *entry = Some((rank, o.endpoint));
                }
            }
        }
        best.into_iter()
            .filter_map(|(node, observation)| observation.map(|(_, endpoint)| (node, endpoint)))
            .collect()
    }
}

/// Size by encoded bytes, including the vector length prefix. Each input has
/// already passed the per-entry budget at merge or local publication.
pub fn batches<'a>(entries: impl IntoIterator<Item = &'a Signed<SoftState>>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut batch = Vec::new();
    let mut size = 10;
    for entry in entries {
        let bytes = postcard::to_stdvec(entry).expect("serializable").len();
        assert!(bytes + 10 <= MAX_BATCH_BYTES, "unbounded soft entry");
        if size + bytes > MAX_BATCH_BYTES {
            out.push(postcard::to_stdvec(&batch).expect("serializable"));
            batch.clear();
            size = 10;
        }
        size += bytes;
        batch.push(entry);
    }
    if !batch.is_empty() {
        out.push(postcard::to_stdvec(&batch).expect("serializable"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheesecloth_core::Identity;

    fn entry(id: &Identity, seq: u64) -> Signed<SoftState> {
        id.seal(
            Domain::SoftState,
            &SoftState {
                node: id.node_id(),
                seq,
                ..Default::default()
            },
        )
    }

    #[test]
    fn only_newer_entries_from_members_merge() {
        let a = Identity::generate();
        let mut t = SoftTable::default();
        assert!(t.merge(entry(&a, 10), |_| true));
        assert!(!t.merge(entry(&a, 10), |_| true), "same entry again");
        assert!(!t.merge(entry(&a, 5), |_| true), "older entry");
        assert!(t.merge(entry(&a, 11), |_| true));

        // Someone else's key can't publish a's entry.
        let b = Identity::generate();
        let forged = b.seal(
            Domain::SoftState,
            &SoftState {
                node: a.node_id(),
                seq: 99,
                ..Default::default()
            },
        );
        assert!(!t.merge(forged, |_| true));
        assert_eq!(t.get(&a.node_id()).unwrap().seq, 11);
    }

    #[test]
    fn entries_from_unknown_nodes_wait_for_membership() {
        let a = Identity::generate();
        let mut t = SoftTable::default();
        assert!(!t.merge(entry(&a, 10), |_| false));
        assert!(t.get(&a.node_id()).is_none());
        assert!(t.retry_parked(|_| false).is_empty());
        assert_eq!(t.retry_parked(|_| true).len(), 1);
        assert_eq!(t.get(&a.node_id()).unwrap().seq, 10);
        t.prune(|_| false);
        assert!(t.get(&a.node_id()).is_none());
    }

    #[test]
    fn only_live_nodes_count_as_connected() {
        let [relay, other_relay, member, dead, site] = [(); 5].map(|()| Identity::generate());
        let me = NodeId([1; 32]);
        let connected = |id: &Identity, to: &[&Identity]| {
            id.seal(
                Domain::SoftState,
                &SoftState {
                    node: id.node_id(),
                    seq: 1,
                    connected: to.iter().map(|t| t.node_id()).collect(),
                    ..Default::default()
                },
            )
        };
        let mut t = SoftTable::default();
        // me - relay - other_relay - member: a member behind NAT at another
        // relay.
        t.merge(connected(&relay, &[&other_relay]), |_| true);
        t.merge(connected(&other_relay, &[&member, &relay]), |_| true);
        // `dead` stopped, and its last entry still lists `site`.
        t.merge(connected(&dead, &[&site]), |_| true);

        let live = t.live(me, [relay.node_id()]);
        let expected =
            BTreeSet::from([me, relay.node_id(), other_relay.node_id(), member.node_id()]);
        assert_eq!(live, expected);

        // Cut off from everyone: only this node.
        assert_eq!(t.live(me, []), BTreeSet::from([me]));
    }

    #[test]
    fn the_state_is_fetched_from_a_live_node_with_the_newest_version() {
        let [dead, old, e, f] = [(); 4].map(|()| Identity::generate());
        let version = |id: &Identity, version| {
            id.seal(
                Domain::SoftState,
                &SoftState {
                    node: id.node_id(),
                    seq: 1,
                    version,
                    ..Default::default()
                },
            )
        };
        let mut t = SoftTable::default();
        t.merge(version(&dead, 13), |_| true);
        t.merge(version(&old, 11), |_| true);
        t.merge(version(&e, 12), |_| true);
        t.merge(version(&f, 12), |_| true);
        let live = BTreeSet::from([old.node_id(), e.node_id(), f.node_id()]);
        let mut rng = rand::rng();

        // `dead` shows the highest version, but isn't live. Both live nodes
        // at version 12 are chosen, at random.
        let mut seen = BTreeSet::new();
        for _ in 0..100 {
            let (node, v) = t.fetch_source(&live, 11, &mut rng).unwrap();
            assert_eq!(v, 12);
            seen.insert(node);
        }
        assert_eq!(seen, BTreeSet::from([e.node_id(), f.node_id()]));

        // Nothing newer than ours among the live nodes.
        assert_eq!(t.fetch_source(&live, 12, &mut rng), None);
        assert_eq!(t.fetch_source(&BTreeSet::new(), 0, &mut rng), None);
    }

    #[test]
    fn direct_observers_beat_port_mapped_ones() {
        let (direct, mapped, target) =
            (Identity::generate(), Identity::generate(), NodeId([7; 32]));
        let mut t = SoftTable::default();
        let obs = |id: &Identity, seq, via_mapping, port| {
            id.seal(
                Domain::SoftState,
                &SoftState {
                    node: id.node_id(),
                    seq,
                    public: true,
                    via_mapping,
                    observed: vec![Observed {
                        node: target,
                        endpoint: SocketAddr::from(([203, 0, 113, 1], port)),
                    }],
                    ..Default::default()
                },
            )
        };
        t.merge(obs(&direct, 1, false, 51820), |_| true);
        t.merge(obs(&mapped, 2, true, 49168), |_| true);
        assert_eq!(t.observed_by_public(&target).unwrap().port(), 51820);
    }

    #[test]
    fn failed_sources_back_off_without_blocking_lower_versions_and_recover() {
        let (bad, healthy) = (Identity::generate(), Identity::generate());
        let mut table = SoftTable::default();
        for (id, version) in [(&bad, u64::MAX), (&healthy, 42)] {
            assert!(table.merge(
                id.seal(
                    Domain::SoftState,
                    &SoftState {
                        node: id.node_id(),
                        seq: 1,
                        version,
                        ..Default::default()
                    }
                ),
                |_| true
            ));
        }
        let live = BTreeSet::from([bad.node_id(), healthy.node_id()]);
        let now = Instant::now();
        let mut rng = rand::rng();
        assert_eq!(
            table.fetch_source_at(&live, 1, &mut rng, now).unwrap().0,
            bad.node_id()
        );
        table.fetched(bad.node_id(), false, now);
        assert_eq!(
            table.fetch_source_at(&live, 1, &mut rng, now).unwrap().0,
            healthy.node_id()
        );
        assert_eq!(
            table
                .fetch_source_at(&live, 1, &mut rng, now + Duration::from_secs(2))
                .unwrap()
                .0,
            bad.node_id()
        );
        table.fetched(bad.node_id(), true, now);
        assert_eq!(
            table.fetch_source_at(&live, 1, &mut rng, now).unwrap().0,
            bad.node_id()
        );
        table.fetched(bad.node_id(), false, now);
        table.prune(|id| *id != bad.node_id());
        assert!(table.fetch_failures.is_empty());
    }

    #[test]
    fn dense_valid_tables_are_batched_without_losing_entries() {
        let targets: Vec<_> = (0..MAX_PEERS)
            .map(|i| {
                let mut id = [0; 32];
                id[..8].copy_from_slice(&(i as u64).to_be_bytes());
                NodeId(id)
            })
            .collect();
        let mut table = SoftTable::default();
        for _ in 0..20 {
            let id = Identity::generate();
            let mut state = SoftState {
                node: id.node_id(),
                seq: 1,
                connected: targets.clone(),
                observed: targets
                    .iter()
                    .map(|node| Observed {
                        node: *node,
                        endpoint: "[2001:db8::1]:51820".parse().unwrap(),
                    })
                    .collect(),
                ..Default::default()
            };
            state.bound();
            assert!(state.valid());
            let signed = id.seal(Domain::SoftState, &state);
            assert!(signed.body.len() < MAX_ENTRY_BYTES);
            assert!(table.merge(signed, |_| true));
        }
        let all = table.signed();
        assert!(postcard::to_stdvec(&all).unwrap().len() > 1 << 20);
        let batches = batches(&all);
        assert!(batches.len() > 1);
        let mut restored = SoftTable::default();
        for batch in batches {
            assert!(batch.len() <= MAX_BATCH_BYTES);
            assert!(batch.len() <= cheesecloth_net::MAX_PAYLOAD);
            for signed in postcard::from_bytes::<Vec<Signed<SoftState>>>(&batch).unwrap() {
                assert!(restored.merge(signed, |_| true));
            }
        }
        for state in table.all() {
            assert_eq!(restored.get(&state.node), Some(state));
        }
        let seed = table.seed(all[0].signer);
        assert!(postcard::to_stdvec(&seed).unwrap().len() <= JOIN_SEED_BYTES);
    }

    #[test]
    fn invalid_discovery_fields_are_rejected_before_parking() {
        let id = Identity::generate();
        let address = "192.0.2.1:51820".parse().unwrap();
        for state in [
            SoftState {
                connected: vec![id.node_id(); 2],
                ..Default::default()
            },
            SoftState {
                control_addrs: vec![address; 2],
                ..Default::default()
            },
            SoftState {
                observed: vec![
                    Observed {
                        node: id.node_id(),
                        endpoint: address
                    };
                    2
                ],
                ..Default::default()
            },
            SoftState {
                wg_lan: (0..=MAX_ADDRESSES)
                    .map(|i| SocketAddr::new(address.ip(), i as u16))
                    .collect(),
                ..Default::default()
            },
        ] {
            let mut table = SoftTable::default();
            let signed = id.seal(
                Domain::SoftState,
                &SoftState {
                    node: id.node_id(),
                    seq: 1,
                    ..state
                },
            );
            assert!(!table.merge(signed, |_| false));
            assert!(table.parked.is_empty());
        }
    }

    #[test]
    fn observation_index_preserves_mapping_freshness_and_self_exclusion() {
        let ids: Vec<_> = (0..5).map(|_| Identity::generate()).collect();
        let mut table = SoftTable::default();
        for (i, id) in ids.iter().enumerate() {
            assert!(
                table.merge(
                    id.seal(
                        Domain::SoftState,
                        &SoftState {
                            node: id.node_id(),
                            seq: i as u64,
                            public: i != 4,
                            via_mapping: i == 3,
                            observed: ids
                                .iter()
                                .map(|target| Observed {
                                    node: target.node_id(),
                                    endpoint: SocketAddr::from(([192, 0, 2, 1], i as u16)),
                                })
                                .collect(),
                            ..Default::default()
                        }
                    ),
                    |_| true
                )
            );
        }
        let index = table.observations(ids.iter().map(Identity::node_id));
        for id in ids {
            assert_eq!(
                index.get(&id.node_id()).copied(),
                table.observed_by_public(&id.node_id())
            );
        }
    }

    #[test]
    fn publication_time_alone_is_not_a_change() {
        let a = SoftState {
            seq: 1,
            ..Default::default()
        };
        let b = SoftState {
            seq: 2,
            ..Default::default()
        };
        assert!(a.same_as(&b));
        assert!(!a.same_as(&SoftState { public: true, ..b }));
    }
}
