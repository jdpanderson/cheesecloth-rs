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
        assert!(matches!(punch_of(&h, &id), Punch::Removing { quiet_for } if quiet_for.is_zero()));
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
