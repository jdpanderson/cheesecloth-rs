use super::*;
use crate::testing::daemon;
use cheesecloth_core::ProposalId;

fn pending(d: &Arc<Daemon>, cluster: ClusterId) -> Arc<PendingJoin> {
    d.finish_join(
        cluster,
        JoinReply::Pending {
            proposal: ProposalId([7; 32]),
        },
        &[],
    )
    .unwrap();
    match &*d.phase.read() {
        Phase::Pending { pending, .. } => pending.clone(),
        _ => panic!("not pending"),
    }
}

/// A complete, valid admission containing this daemon's identity, saved
/// before it locally leaves. Tests can deliver it after cancellation.
async fn admission(d: &Arc<Daemon>) -> (ClusterId, JoinReply) {
    d.init(None).await.unwrap();
    let node = d.node().unwrap();
    let bytes = node
        .handle(
            node.me,
            crate::proto::SVC_FETCH,
            postcard::to_stdvec(&0u64).unwrap(),
        )
        .await
        .unwrap();
    let proven: proof::Proven = postcard::from_bytes(&bytes).unwrap();
    let reply = JoinReply::Joined {
        cluster_id: node.cluster_id,
        state: Box::new(proven.chosen),
        cert: Box::new(proven.cert),
        soft: Vec::new(),
    };
    d.leave(false).await.unwrap();
    (node.cluster_id, reply)
}

fn rejected() -> JoinReply {
    JoinReply::Rejected {
        reason: "rejected".into(),
    }
}

#[tokio::test]
async fn cancellation_wins_over_an_approval_waiting_for_the_operation_lock() {
    let (d, _dir) = daemon("cancel-race", RelayMode::Never).await;
    let (cluster, reply) = admission(&d).await;
    let old = pending(&d, cluster);
    let op = d.op.lock().await;
    let cancel = d.leave(false);
    tokio::pin!(cancel);
    assert!(futures_util::poll!(&mut cancel).is_pending());
    let approval = d.pending_reply(cluster, &old, reply);
    tokio::pin!(approval);
    assert!(futures_util::poll!(&mut approval).is_pending());
    drop(op);
    assert!(matches!(
        cancel.await.unwrap(),
        LeaveView::JoinCancelled { .. }
    ));
    assert!(approval.await.unwrap());
    assert!(matches!(&*d.phase.read(), Phase::None));
    assert!(d.files.load_cluster().unwrap().is_none());
    assert!(d.pending_poll.lock().is_none());
    d.shutdown().await;
}

#[tokio::test]
async fn old_replies_cannot_finish_or_reject_a_new_attempt_at_the_same_proposal() {
    let (d, _dir) = daemon("cancel-retry", RelayMode::Never).await;
    let (cluster, reply) = admission(&d).await;
    let old = pending(&d, cluster);
    d.leave(false).await.unwrap();
    let current = pending(&d, cluster);
    assert_eq!(current.proposal, old.proposal);
    assert!(!Arc::ptr_eq(&current, &old));
    for stale in [reply.clone(), rejected()] {
        assert!(d.pending_reply(cluster, &old, stale).await.unwrap());
        assert!(d.is_pending(&current));
        assert_eq!(
            d.files
                .load_cluster()
                .unwrap()
                .unwrap()
                .pending
                .unwrap()
                .proposal,
            current.proposal
        );
    }
    // A reply for the current attempt still admits the node. Admission
    // winning first means `leave` follows the member path.
    assert!(d.pending_reply(cluster, &current, reply).await.unwrap());
    assert!(d.node().is_some());
    assert!(matches!(
        d.leave(false).await.unwrap(),
        LeaveView::Left { .. }
    ));
    d.shutdown().await;
}

#[tokio::test]
async fn old_replies_cannot_replace_or_delete_a_new_cluster() {
    let (d, _dir) = daemon("cancel-init", RelayMode::Never).await;
    let (cluster, reply) = admission(&d).await;
    let old = pending(&d, cluster);
    d.leave(false).await.unwrap();
    d.init(None).await.unwrap();
    let current = d.node().unwrap();
    assert_ne!(current.cluster_id, cluster);
    for stale in [reply, rejected()] {
        assert!(d.pending_reply(cluster, &old, stale).await.unwrap());
        assert!(Arc::ptr_eq(&d.node().unwrap(), &current));
        assert_eq!(
            d.files.load_cluster().unwrap().unwrap().cluster_id,
            current.cluster_id
        );
    }
    d.shutdown().await;
}

#[tokio::test]
async fn failed_cancellation_preserves_the_attempt_and_can_be_retried() {
    let (d, _dir) = daemon("cancel-io", RelayMode::Never).await;
    let cluster = ClusterId([8; 32]);
    let attempt = pending(&d, cluster);
    let keys = (
        std::fs::read(d.files.identity()).unwrap(),
        std::fs::read(d.files.wg_key()).unwrap(),
    );
    // Earlier cleanup can succeed; the pending record must still exist
    // when a later file cannot be removed.
    StoredAcceptor::create(d.files.acceptor(), pnyx::Acceptor::default()).unwrap();
    std::fs::create_dir(d.files.transitions()).unwrap();
    for force in [false, true] {
        let error = d.leave(force).await.unwrap_err();
        assert!(format!("{error:#}").contains("cancelling the pending join"));
        assert!(d.is_pending(&attempt));
        assert!(d.files.load_cluster().unwrap().unwrap().pending.is_some());
        assert!(!d.pending_poll.lock().as_ref().unwrap().is_finished());
    }
    std::fs::remove_dir(d.files.transitions()).unwrap();
    assert!(matches!(
        d.leave(false).await.unwrap(),
        LeaveView::JoinCancelled { .. }
    ));
    assert!(d.files.load_cluster().unwrap().is_none());
    assert_eq!(std::fs::read(d.files.identity()).unwrap(), keys.0);
    assert_eq!(std::fs::read(d.files.wg_key()).unwrap(), keys.1);
    d.shutdown().await;
}

#[tokio::test]
async fn invalid_or_unsaved_admission_keeps_the_join_pending_for_retry() {
    let (d, _dir) = daemon("admission-io", RelayMode::Never).await;
    let (cluster, reply) = admission(&d).await;
    let attempt = pending(&d, cluster);
    let mut invalid = reply.clone();
    if let JoinReply::Joined { cluster_id, .. } = &mut invalid {
        *cluster_id = ClusterId([9; 32]);
    }
    assert!(d.pending_reply(cluster, &attempt, invalid).await.is_err());
    assert!(d.is_pending(&attempt));
    // Failing admission must not delete the saved pending attempt first. A
    // directory in place of the transitions file makes admission fail.
    std::fs::create_dir(d.files.transitions()).unwrap();
    assert!(
        d.pending_reply(cluster, &attempt, reply.clone())
            .await
            .is_err()
    );
    assert!(d.is_pending(&attempt));
    assert!(d.files.load_cluster().unwrap().unwrap().pending.is_some());
    std::fs::remove_dir(d.files.transitions()).unwrap();
    assert!(d.pending_reply(cluster, &attempt, reply).await.unwrap());
    assert!(d.node().is_some());
    d.shutdown().await;
}

#[tokio::test]
async fn joining_requires_acceptance_in_a_valid_configuration() {
    let (d, _dir) = daemon("admission-proof", RelayMode::Never).await;
    let (cluster, reply) = admission(&d).await;
    let attempt = pending(&d, cluster);
    for invalid_config in [false, true] {
        let mut invalid = reply.clone();
        let JoinReply::Joined { state, cert, .. } = &mut invalid else {
            unreachable!();
        };
        let ballot = state.ballot.clone().unwrap();
        let expected = if invalid_config {
            // Three valid signatures still cannot create a protected
            // configuration with fewer than four voters.
            let others = [
                cheesecloth_core::Identity::generate(),
                cheesecloth_core::Identity::generate(),
            ];
            state.value.config.protected = true;
            state
                .value
                .config
                .acceptors
                .extend(others.iter().map(|id| id.node_id()));
            let header = proof::Header::of(cluster, &state.value);
            **cert = proof::Certificate::sign(&d.identity, header.clone(), ballot.clone());
            for id in &others {
                cert.sigs
                    .extend(proof::Certificate::sign(id, header.clone(), ballot.clone()).sigs);
            }
            "invalid voter configuration"
        } else {
            // Verification alone does not prove that a value was accepted.
            **cert = proof::Certificate::sign_verified(
                &d.identity,
                proof::Header::of(cluster, &state.value),
                ballot,
            );
            "certificate phase or configuration mismatch"
        };
        let error = d
            .pending_reply(cluster, &attempt, invalid)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
        assert!(d.is_pending(&attempt));
        assert!(d.files.load_cluster().unwrap().unwrap().pending.is_some());
        assert!(!crate::testing::has_acceptor(&d.files));
    }
    assert!(d.pending_reply(cluster, &attempt, reply).await.unwrap());
    assert!(d.node().is_some());
    d.shutdown().await;
}

#[tokio::test]
async fn shutdown_stops_polling_but_restart_resumes_the_saved_attempt() {
    let (d, _dir) = daemon("pending-stop", RelayMode::Never).await;
    let cluster = ClusterId([8; 32]);
    let attempt = pending(&d, cluster);
    let mut opts = (*d.opts).clone();
    opts.listen_port = 0;
    d.shutdown().await;
    assert!(d.pending_poll.lock().is_none());
    assert!(d.files.load_cluster().unwrap().unwrap().pending.is_some());
    assert!(
        d.pending_reply(cluster, &attempt, rejected())
            .await
            .unwrap()
    );
    assert!(d.files.load_cluster().unwrap().is_some());
    let restarted = Daemon::start(opts).await.unwrap();
    assert_eq!(
        restarted.status().await.unwrap().pending_proposal,
        Some(attempt.proposal)
    );
    assert!(restarted.pending_poll.lock().is_some());
    assert!(matches!(
        restarted.leave(true).await.unwrap(),
        LeaveView::JoinCancelled { .. }
    ));
    restarted.shutdown().await;
}
