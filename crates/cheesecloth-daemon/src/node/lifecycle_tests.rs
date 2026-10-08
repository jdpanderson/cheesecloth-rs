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
    let saved = saved(&daemon.files);
    assert_eq!(
        daemon.files.load_cluster().unwrap().unwrap().cluster_id,
        new.cluster_id
    );
    assert_eq!(
        saved.learned().unwrap().state().cluster_id,
        Some(new.cluster_id)
    );
    daemon.shutdown().await;
}

/// Starts a second node on the state directory of `h`'s node, as after a
/// restart.
fn restart(h: &testing::Harness) -> Result<Arc<Node>> {
    let n = &h.node;
    Node::start(
        n.opts.clone(),
        n.cluster_id,
        n.identity.clone(),
        n.wg_private,
        n.net.clone(),
        n.files.clone(),
    )
}

type Acceptor = pnyx::Acceptor<NodeId, ClusterState, proof::Certificate>;

/// The acceptor state saved in the pnyx store, which must exist.
fn saved(files: &Files) -> Acceptor {
    StoredAcceptor::open_existing(files.acceptor())
        .unwrap()
        .expect("an acceptor state")
        .acceptor()
        .clone()
}

/// Writes `acceptor` to `acceptor.bin`, as cheesecloth 0.1.0 did.
fn write_legacy(files: &Files, acceptor: &Acceptor) {
    std::fs::write(
        files.legacy_acceptor(),
        postcard::to_stdvec(acceptor).unwrap(),
    )
    .unwrap();
}

/// `acceptor.bin` as cheesecloth 0.1.0 wrote it. Made by 0.1.0's own code: a
/// test there started `testing::harness(RelayMode::Never, &[false])`, had the
/// node agree on `CreateInvite` with the invite ID of `[1; 32]`, and copied
/// the file. The other tests here write `acceptor.bin` with the current types,
/// so only this one shows that real files from 0.1.0 still decode.
const ACCEPTOR_0_1_0: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/acceptor-0.1.0.bin"
));

#[test]
fn an_acceptor_file_from_0_1_0_is_moved_without_loss() {
    let dir = tempfile::tempdir().unwrap();
    let files = Files::new(dir.path()).unwrap();
    std::fs::write(files.legacy_acceptor(), ACCEPTOR_0_1_0).unwrap();
    let stored = open_acceptor(&files).unwrap().expect("the moved state");
    assert!(!files.legacy_acceptor().exists());
    // Every field survived: the state encodes to the same bytes.
    assert_eq!(
        postcard::to_stdvec(stored.acceptor()).unwrap(),
        ACCEPTOR_0_1_0
    );
    // It's the state of a node that agreed on the change, with its proof.
    let learned = stored.acceptor().learned().unwrap().clone();
    let cert = stored.acceptor().proof().unwrap();
    assert!(cert.proves(&learned));
    cert.check_config(&cert.header.config, false).unwrap();
    assert_eq!(learned.state().cluster_id, Some(cert.header.cluster_id));
    let invite = cheesecloth_core::state::invite_id(&[1; 32]);
    assert!(learned.state().invites.contains_key(&invite));
    // The next start opens the new store.
    drop(stored);
    let again = open_acceptor(&files).unwrap().expect("the moved state");
    assert_eq!(again.acceptor().learned(), Some(&learned));
}

#[tokio::test]
async fn an_old_acceptor_file_is_moved_to_the_new_files() {
    let h = testing::harness(RelayMode::Never, &[]).await;
    let files = &h.node.files;
    write_legacy(files, &saved(files));
    pnyx::store::remove(&files.acceptor()).unwrap();
    let node = restart(&h).unwrap();
    assert_eq!(node.agreed(), h.node.agreed());
    assert!(!files.legacy_acceptor().exists());
    assert_eq!(saved(files).learned(), Some(&*h.node.agreed()));
}

#[tokio::test]
async fn a_node_without_acceptor_state_does_not_start_and_creates_none() {
    let h = testing::harness(RelayMode::Never, &[]).await;
    let files = &h.node.files;
    pnyx::store::remove(&files.acceptor()).unwrap();
    let e = format!("{:#}", restart(&h).err().expect("there is no state"));
    assert!(e.contains("older version of cheesecloth"), "{e}");
    assert!(!testing::has_acceptor(files));
}

#[tokio::test]
async fn a_move_that_was_cut_short_is_done_again() {
    let h = testing::harness(RelayMode::Never, &[]).await;
    let files = &h.node.files;
    // The new store was written, but `acceptor.bin` not yet deleted.
    write_legacy(files, &saved(files));
    let node = restart(&h).unwrap();
    assert_eq!(node.agreed(), h.node.agreed());
    assert!(!files.legacy_acceptor().exists());
    assert_eq!(saved(files).learned(), Some(&*h.node.agreed()));
}

#[tokio::test]
async fn after_a_downgrade_the_old_acceptor_file_holds_the_newest_state() {
    let h = testing::harness(RelayMode::Never, &[]).await;
    let files = &h.node.files;
    let older = saved(files);
    h.node
        .submit(cheesecloth_core::state::Command::CreateInvite {
            invite_id: cheesecloth_core::state::invite_id(&[1; 32]),
        })
        .await
        .unwrap();
    // The older version saved the newer state in `acceptor.bin`, and left
    // the new files as they were.
    write_legacy(files, &saved(files));
    StoredAcceptor::create(files.acceptor(), older.clone()).unwrap();
    assert_ne!(saved(files).learned(), Some(&*h.node.agreed()));
    let node = restart(&h).unwrap();
    assert_eq!(node.agreed(), h.node.agreed());
    assert!(!files.legacy_acceptor().exists());
}

#[tokio::test]
async fn init_ignores_an_old_acceptor_file_left_behind() {
    let (daemon, _dir) = testing::daemon("legacy-init", RelayMode::Never).await;
    daemon.init(None).await.unwrap();
    let old = saved(&daemon.files);
    daemon.leave(false).await.unwrap();
    write_legacy(&daemon.files, &old);
    daemon.init(None).await.unwrap();
    let cluster_id = daemon.node().unwrap().cluster_id;
    let mut opts = (*daemon.opts).clone();
    opts.listen_port = 0;
    daemon.shutdown().await;
    drop(daemon);
    let restarted = crate::Daemon::start(opts).await.unwrap();
    let node = restarted.node().unwrap();
    assert_eq!(node.cluster_id, cluster_id);
    assert_eq!(node.agreed().state().cluster_id, Some(cluster_id));
    restarted.shutdown().await;
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
