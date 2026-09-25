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
    let expected = BTreeSet::from([me, relay.node_id(), other_relay.node_id(), member.node_id()]);
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
    let (direct, mapped, target) = (Identity::generate(), Identity::generate(), NodeId([7; 32]));
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
