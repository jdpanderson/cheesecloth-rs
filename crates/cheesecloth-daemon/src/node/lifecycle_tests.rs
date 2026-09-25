use super::*;
use crate::{RelayMode, testing};

#[tokio::test]
async fn a_queued_invite_cannot_write_after_leave_and_reinitialization() {
    let (daemon, _dir) = testing::daemon("lifetime", RelayMode::Never).await;
    daemon.init(None).await.unwrap();
    let old = daemon.node().unwrap();
    let blocker = old.proposer.lock().await;
    let invite = daemon.invite();
    tokio::pin!(invite);
    assert!(futures_util::poll!(&mut invite).is_pending());
    // The caller need not poll the cancelled invite for leave to finish.
    daemon.leave(false).await.unwrap();
    daemon.init(None).await.unwrap();
    let new = daemon.node().unwrap();
    assert_ne!(old.cluster_id, new.cluster_id);
    drop(blocker);
    assert!(invite.await.unwrap_err().to_string().contains("stopping"));
    assert!(
        old.handle(old.me, SVC_FETCH, postcard::to_stdvec(&0u64).unwrap())
            .await
            .is_err()
    );
    daemon.invite().await.unwrap();
    let saved = StoredAcceptor::open(daemon.files.acceptor()).unwrap();
    assert_eq!(
        daemon.files.load_cluster().unwrap().unwrap().cluster_id,
        new.cluster_id
    );
    assert_eq!(
        saved.acceptor().learned().unwrap().state().cluster_id,
        Some(new.cluster_id)
    );
    daemon.shutdown().await;
}

#[tokio::test]
async fn departed_nodes_and_stopped_daemons_release_their_owners() {
    let (daemon, _dir) = testing::daemon("ownership", RelayMode::Never).await;
    for _ in 0..3 {
        daemon.init(None).await.unwrap();
        let old = Arc::downgrade(&daemon.node().unwrap());
        daemon.leave(false).await.unwrap();
        assert!(old.upgrade().is_none());
    }
    let weak = Arc::downgrade(&daemon);
    daemon.shutdown().await;
    drop(daemon);
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn startup_rejects_a_cluster_header_from_another_membership() {
    let h = testing::harness(RelayMode::Never, &[]).await;
    let n = &h.node;
    let result = Node::start(
        n.opts.clone(),
        ClusterId([9; 32]),
        n.identity.clone(),
        n.wg_private,
        n.net.clone(),
        n.files.clone(),
    );
    assert!(result.err().unwrap().to_string().contains("does not match"));
}

#[tokio::test]
async fn oversized_or_duplicate_discovery_entries_cannot_poison_admission() {
    let h = testing::harness(RelayMode::Never, &[false, false]).await;
    for p in &h.peers {
        for count in [2, 25_000] {
            let signed = p.identity.seal(
                cheesecloth_core::Domain::SoftState,
                &SoftState {
                    node: p.id(),
                    seq: 1,
                    connected: vec![h.node.me; count],
                    ..Default::default()
                },
            );
            let body = postcard::to_stdvec(&vec![signed]).unwrap();
            assert!(body.len() < (1 << 20));
            h.node.merge_soft(p.id(), &body);
            assert!(h.node.soft.lock().get(&p.id()).is_none());
        }
    }
    let reply = h
        .node
        .join_request(
            h.node.me,
            JoinMessage::Status {
                proposal: Default::default(),
            },
        )
        .await
        .unwrap();
    assert!(postcard::to_stdvec(&reply).unwrap().len() < cheesecloth_net::MAX_PAYLOAD);
}

#[tokio::test]
async fn a_successful_fetch_without_verified_progress_backs_off_the_source() {
    let (daemon, _dir) = testing::daemon("fetch-progress", RelayMode::Never).await;
    daemon.init(None).await.unwrap();
    let node = daemon.node().unwrap();
    node.lifetime.stop_tasks().await;
    assert!(node.soft.lock().merge(
        node.identity.seal(
            cheesecloth_core::Domain::SoftState,
            &SoftState {
                node: node.me,
                seq: u64::MAX,
                version: u64::MAX,
                ..Default::default()
            }
        ),
        |_| true
    ));
    node.fetch_from(node.me, u64::MAX);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while node.fetching.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        node.soft
            .lock()
            .fetch_source(
                &std::collections::BTreeSet::from([node.me]),
                node.agreed().value.version,
                &mut rand::rng()
            )
            .is_none()
    );
    daemon.shutdown().await;
}
