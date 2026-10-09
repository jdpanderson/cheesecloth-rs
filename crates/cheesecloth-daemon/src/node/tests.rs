//! Node tests on a single node (see `crate::testing`).

use std::{collections::BTreeSet, net::SocketAddr, sync::atomic::Ordering};

use cheesecloth_core::{
    Domain, Identity, NodeId, WgKey,
    state::{ClusterState, Command, CommandError, MemberInfo, Outcome, SettingChange, invite_id},
};
use pnyx::{Ballot, Request, store::Stored};

use crate::{
    RelayMode,
    files::Files,
    node::{Chosen, consensus::Refused},
    proto::*,
    soft::{Observed, SoftState},
    testing::{harness, harness_with, signed},
};

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

// ------------------------------------------------------------------- views

#[tokio::test]
async fn what_this_node_knows_about_the_members() {
    let h = harness(RelayMode::Never, &[true, false, false]).await;
    let n = &h.node;
    let (r, p, q) = (h.peers[0].id(), h.peers[1].id(), h.peers[2].id());
    assert_eq!(n.agreed().state().members.len(), 4);
    assert!(n.is_member(&p) && !n.is_member(&NodeId([1; 32])));
    assert_eq!(n.agreed().state().members[&p].info.name, "peer1");
    assert_eq!(n.relays(), vec![r]);
    assert!(!n.is_relay(&n.me));
    let nets: Vec<String> = n.overlay_nets().iter().map(|n| n.to_string()).collect();
    assert!(nets.contains(&"100.64.0.0/24".to_string()), "{nets:?}");
    assert_eq!(n.wg_keepalive(), cheesecloth_core::NAT_KEEPALIVE_SECS);

    // Addresses: our own from our facts, others' from soft state if they
    // published any, else from their records.
    assert_eq!(n.control_addrs_of(&n.me), n.facts.lock().control_addrs);
    assert_eq!(n.control_addrs_of(&p), h.peers[1].info.control_addrs);
    h.soft(
        1,
        SoftState {
            control_addrs: vec![sa("10.1.0.7:51821")],
            ..Default::default()
        },
    );
    assert_eq!(n.control_addrs_of(&p), vec![sa("10.1.0.7:51821")]);

    // A member advertises its current relay role separately from reachability.
    h.soft(
        2,
        SoftState {
            public: true,
            relay: true,
            public_ip: Some("203.0.113.3".parse().unwrap()),
            ..Default::default()
        },
    );
    assert!(n.is_relay(&q));
    assert_eq!(n.public_ip_of(&q), Some("203.0.113.3".parse().unwrap()));

    // Relays are dialled; NATed members only on the same LAN behind the
    // same NAT; non-members never.
    assert!(n.dial_addrs(&NodeId([1; 32])).is_empty());
    assert_eq!(n.dial_addrs(&r), h.peers[0].info.control_addrs);
    assert!(n.dial_addrs(&p).is_empty(), "different site");
    let observe = |mine: &str, theirs: &str| {
        h.soft(
            0,
            SoftState {
                public: true,
                relay: true,
                connected: vec![p],
                observed: vec![
                    Observed {
                        node: n.me,
                        endpoint: sa(mine),
                    },
                    Observed {
                        node: p,
                        endpoint: sa(theirs),
                    },
                ],
                ..Default::default()
            },
        )
    };
    observe("198.51.100.1:1000", "198.51.100.1:1001");
    assert!(n.dial_addrs(&p).is_empty(), "same NAT, not on our LAN");
    h.interfaces.lock().nets = vec!["10.1.0.0/24".parse().unwrap()];
    n.refresh_facts();
    assert_eq!(n.dial_addrs(&p), vec![sa("10.1.0.7:51821")]);
    assert_eq!(n.public_ip_of(&p), Some("198.51.100.1".parse().unwrap()));

    // Relays connected to the destination are tried first.
    assert_eq!(n.forwarders(&p), vec![r, q]);
    assert_eq!(n.forwarders(&r), vec![q]);
}

#[tokio::test]
async fn signed_relay_roles_override_records_without_using_public_reachability() {
    let h = harness(RelayMode::Never, &[true, false]).await;
    let (old_relay, public_peer) = (h.peers[0].id(), h.peers[1].id());
    assert!(
        h.node.is_relay(&old_relay),
        "record is the bootstrap fallback"
    );
    let public = SoftState {
        public: true,
        relay: false,
        public_ip: Some("203.0.113.9".parse().unwrap()),
        ..Default::default()
    };
    h.soft(1, public.clone());
    assert!(!h.node.is_relay(&public_peer));
    assert_eq!(h.node.public_ip_of(&public_peer), public.public_ip);
    assert_eq!(h.node.forwarders(&public_peer), vec![old_relay]);
    assert!(h.node.warnings().is_empty());

    h.soft(0, public.clone());
    assert!(h.node.agreed().state().members[&old_relay].info.relay);
    assert!(
        !h.node.is_relay(&old_relay),
        "explicit refusal overrides the record"
    );
    assert!(!h.node.have_relays());
    assert!(h.node.forwarders(&public_peer).is_empty());
    assert!(h.node.warnings().iter().any(|w| w.contains("no relay")));

    h.soft(
        1,
        SoftState {
            relay: true,
            ..public.clone()
        },
    );
    assert!(!h.node.agreed().state().members[&public_peer].info.relay);
    assert_eq!(
        h.node.relays(),
        vec![public_peer],
        "role changes need no consensus round"
    );
    assert!(h.node.warnings().is_empty());
    h.soft(1, public);
    assert!(!h.node.have_relays());
    assert!(h.node.warnings().iter().any(|w| w.contains("no relay")));
}

#[tokio::test]
async fn a_public_node_knows_its_own_address() {
    let h = harness(RelayMode::Always, &[]).await;
    let n = &h.node;
    {
        let mut f = n.facts.lock();
        f.public = true;
        f.public_ip = Some("203.0.113.1".parse().unwrap());
    }
    assert!(n.is_relay(&n.me));
    assert_eq!(n.public_ip_of(&n.me), Some("203.0.113.1".parse().unwrap()));
    assert_eq!(n.wg_keepalive(), 0);
    // In a cluster without relays, everyone is dialled directly.
    let h = harness(RelayMode::Never, &[false]).await;
    assert!(!h.node.have_relays());
    assert_eq!(
        h.node.dial_addrs(&h.peers[0].id()),
        h.peers[0].info.control_addrs
    );
}

// -------------------------------------------------------------- soft state

#[tokio::test]
async fn soft_state_is_merged_and_our_own_newer_echo_raises_our_sequence_number() {
    let h = harness(RelayMode::Never, &[false]).await;
    let n = &h.node;
    let p = &h.peers[0];

    n.merge_soft(p.id(), b"garbage");
    assert!(n.soft.lock().get(&p.id()).is_none());

    let entry = p.identity.seal(
        Domain::SoftState,
        &SoftState {
            node: p.id(),
            seq: 5,
            ..Default::default()
        },
    );
    n.merge_soft(p.id(), &postcard::to_stdvec(&vec![entry]).unwrap());
    assert_eq!(n.soft.lock().get(&p.id()).unwrap().seq, 5);

    // Our own entry, from before a restart, with a later sequence number.
    *n.published.lock() = Some(n.my_soft_state());
    let mine = n.identity.seal(
        Domain::SoftState,
        &SoftState {
            node: n.me,
            seq: u64::MAX / 2,
            ..Default::default()
        },
    );
    n.merge_soft(p.id(), &postcard::to_stdvec(&vec![mine]).unwrap());
    assert_eq!(n.soft_seq.load(Ordering::Relaxed), u64::MAX / 2);
    assert!(n.published.lock().is_none(), "republish with a higher seq");
    // Echoes of older entries change nothing.
    let old = n.identity.seal(
        Domain::SoftState,
        &SoftState {
            node: n.me,
            seq: 1,
            ..Default::default()
        },
    );
    *n.published.lock() = Some(n.my_soft_state());
    n.merge_soft(p.id(), &postcard::to_stdvec(&vec![old]).unwrap());
    assert!(n.published.lock().is_some());

    let s = n.my_soft_state();
    assert_eq!(s.node, n.me);
    assert_eq!(s.control_addrs, n.facts.lock().control_addrs);
    assert!(s.connected.is_empty());
    // Nobody is connected, so there's no one to send to; this mustn't fail.
    n.on_connected(p.id());
    n.spread(n.soft.lock().signed(), None);
}

// ------------------------------------------------------ requests and joins

#[tokio::test]
async fn requests_are_dispatched_by_service() {
    let h = harness(RelayMode::Never, &[false]).await;
    let (n, p) = (&h.node, h.peers[0].id());
    let e = n.handle(p, 99, vec![]).await.unwrap_err();
    assert!(e.contains("unknown service"), "{e}");
    assert!(n.handle(p, SVC_PAXOS, vec![0xff]).await.is_err());
    assert!(n.handle(p, SVC_STATE, vec![0xff]).await.is_err());
    let go = postcard::to_stdvec(&PunchMessage::Go { id: 1 }).unwrap();
    let reply = n.handle(p, SVC_PUNCH, go).await.unwrap();
    assert!(matches!(
        postcard::from_bytes::<PunchReply>(&reply).unwrap(),
        PunchReply::Refused(_)
    ));
    assert!(n.handle_join(p, vec![0xff]).await.is_err());

    // Any member may fetch the agreed state, with its proof.
    let from = postcard::to_stdvec(&0u64).unwrap();
    let bytes = n.handle(p, SVC_FETCH, from).await.unwrap();
    let proven: crate::node::proof::Proven = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(proven.chosen, *n.agreed());
    assert!(proven.cert.proves(&proven.chosen));

    // A CASPaxos request must come from the node its ballot names.
    let prepare = |node| {
        let req: Request<NodeId, cheesecloth_core::state::ClusterState> = Request::Prepare {
            config: 0,
            ballot: Ballot { counter: 7, node },
            have: None,
        };
        postcard::to_stdvec(&super::round::WireRequest {
            request: req,
            proof: None,
            base: None,
        })
        .unwrap()
    };
    let e = n.handle(p, SVC_PAXOS, prepare(n.me)).await.unwrap_err();
    assert!(e.contains("uses another node's ballot"), "{e}");
    assert!(n.handle(p, SVC_PAXOS, prepare(p)).await.is_ok());
}

type PaxosRequest = Request<NodeId, ClusterState>;

#[tokio::test]
async fn acceptors_answer_only_for_their_configurations() {
    let h = harness(RelayMode::Never, &[false, false]).await;
    let (n, p, q) = (&h.node, h.peers[0].id(), h.peers[1].id());
    let prepare = |config| {
        let req: PaxosRequest = Request::Prepare {
            config,
            ballot: Ballot {
                counter: 7,
                node: p,
            },
            have: None,
        };
        postcard::to_stdvec(&super::round::WireRequest {
            request: req,
            proof: None,
            base: None,
        })
        .unwrap()
    };
    // Configuration 0 is this node's: answered.
    assert!(n.handle(p, SVC_PAXOS, prepare(0)).await.is_ok());
    // Too far past the latest configuration this node knows.
    let e = n.handle(p, SVC_PAXOS, prepare(9)).await.unwrap_err();
    assert!(e.contains("too far"), "{e}");

    // A value closes configuration 0, naming q alone for configuration 1.
    let mut closing = n.agreed().value.clone();
    closing.version += 1;
    closing.next = Some(closing.config.successor(BTreeSet::from([q]), false));
    h.learn(Chosen {
        value: closing,
        ballot: Some(Ballot {
            counter: 8,
            node: n.me,
        }),
    })
    .await
    .unwrap();
    let e = n.handle(p, SVC_PAXOS, prepare(1)).await.unwrap_err();
    assert!(e.contains("not an acceptor of configuration 1"), "{e}");
    // Configurations this node doesn't know the acceptors of are answered.
    assert!(n.handle(p, SVC_PAXOS, prepare(2)).await.is_ok());
}

#[tokio::test]
async fn a_commit_notice_must_come_from_the_ballots_proposer() {
    let h = harness(RelayMode::Never, &[false, false]).await;
    let (n, p, q) = (&h.node, h.peers[0].id(), h.peers[1].id());
    // p has this node accept a new value at p's ballot.
    let ballot = Ballot {
        counter: 7,
        node: p,
    };
    let mut value = n.agreed().value.clone();
    value.version += 1;
    value.value.record_step(n.agreed().state(), None);
    let accept: PaxosRequest = Request::Accept {
        config: 0,
        ballot: ballot.clone(),
        value: value.clone(),
    };
    checked_accept(n, p, accept).await.unwrap();

    // The notice carries the proof: this node's signature, as the only
    // acceptor.
    let cert = h.certify(&Chosen {
        value: value.clone(),
        ballot: Some(ballot.clone()),
    });
    let notice = postcard::to_stdvec(&cert).unwrap();
    let e = n.handle(q, SVC_COMMIT, notice.clone()).await.unwrap_err();
    assert!(e.contains("another node's ballot"), "{e}");
    assert_ne!(n.agreed().value, value);

    n.handle(p, SVC_COMMIT, notice).await.unwrap();
    assert_eq!(n.agreed().value, value);
}

#[tokio::test]
async fn an_acceptor_accepts_only_valid_changes() {
    let h = harness(RelayMode::Never, &[false, false]).await;
    let (n, p, q) = (&h.node, h.peers[0].id(), h.peers[1].id());
    let base = n.agreed().value.clone();
    let counter = std::cell::Cell::new(6);
    let accept = |value: crate::node::Agreed| {
        counter.set(counter.get() + 1);
        let req: PaxosRequest = Request::Accept {
            config: 0,
            ballot: Ballot {
                counter: counter.get(),
                node: p,
            },
            value,
        };
        req
    };
    let next = |step: Option<cheesecloth_core::state::Request>| {
        let mut v = base.clone();
        v.version += 1;
        if let Some(req) = &step {
            let _ = v.value.apply(req);
        }
        v.value.record_step(&base.value, step);
        v
    };

    // p drops q, although no command does that.
    let mut dropped = next(None);
    dropped.value.members.remove(&q);
    let e = checked_accept(n, p, accept(dropped)).await.unwrap_err();
    assert!(e.contains("what the step makes"), "{e}");
    // A change that doesn't say how it was made.
    let mut unrecorded = base.clone();
    unrecorded.version += 1;
    unrecorded.value.now_ms += 1;
    let e = checked_accept(n, p, accept(unrecorded)).await.unwrap_err();
    assert!(e.contains("doesn't record"), "{e}");
    // p names itself the only acceptor: three members need three.
    let mut alone = next(None);
    alone.next = Some(alone.config.successor(BTreeSet::from([p]), false));
    let e = checked_accept(n, p, accept(alone)).await.unwrap_err();
    assert!(e.contains("omits available voters"), "{e}");
    // A change made from a state this node doesn't hold.
    let mut ahead = next(None);
    ahead.version += 1;
    let e = checked_accept(n, p, accept(ahead)).await.unwrap_err();
    assert!(e.contains("invalid successor"), "{e}");

    // p's own signed command is a valid change.
    let request = cheesecloth_core::state::Request {
        at_ms: cheesecloth_core::now_ms().max(base.value.now_ms),
        command: signed(
            &h.peers[0].identity,
            Some(n.cluster_id),
            Command::CreateInvite { invite_id: [5; 32] },
        ),
    };
    assert!(
        checked_accept(n, p, accept(next(Some(request))))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_guessed_invite_costs_no_change() {
    let h = harness(RelayMode::Never, &[]).await;
    let n = &h.node;
    let version = n.agreed().value.version;
    let joiner = Identity::generate();
    let info = joiner.seal(Domain::MemberInfo, &info_of(&joiner));
    let cmd = signed(
        &n.identity,
        Some(n.cluster_id),
        Command::RedeemInvite {
            secret: [1; 32],
            joiner: info,
        },
    );
    assert_eq!(
        n.write(cmd).await.unwrap(),
        Err(CommandError::InviteUnknown)
    );
    assert_eq!(n.agreed().value.version, version);

    // Any command that changes the state makes a new version, on disk too.
    n.submit(Command::CreateInvite {
        invite_id: invite_id(&[1; 32]),
    })
    .await
    .unwrap();
    assert_eq!(n.agreed().value.version, version + 1);
    let files = Files::new(&h.dir.path().join("state")).unwrap();
    let saved =
        Stored::<NodeId, ClusterState, super::proof::Certificate>::open(files.acceptor()).unwrap();
    assert_eq!(saved.acceptor().learned(), Some(&*n.agreed()));

    // The same signed command again is refused as a replay.
    let once = signed(
        &n.identity,
        Some(n.cluster_id),
        Command::CreateInvite {
            invite_id: invite_id(&[2; 32]),
        },
    );
    assert!(n.write(once.clone()).await.unwrap().is_ok());
    assert_eq!(n.write(once).await.unwrap(), Err(CommandError::Replay));
}

#[tokio::test]
async fn only_newer_states_of_this_cluster_are_learned() {
    let h = harness(RelayMode::Never, &[false]).await;
    let n = &h.node;
    let current = (*n.agreed()).clone();

    let mut newer = current.clone();
    newer.value.version += 1;
    newer.value.value.now_ms += 1;
    h.learn(newer.clone()).await.unwrap();
    assert_eq!(*n.agreed(), newer);
    h.learn(current.clone()).await.unwrap();
    assert_eq!(*n.agreed(), newer, "older states are ignored");

    let mut other = newer.clone();
    other.value.version += 1;
    other.value.value.cluster_id = Some(cheesecloth_core::ClusterId([9; 32]));
    let e = h.learn(other.clone()).await.unwrap_err();
    assert!(format!("{e:#}").contains("another cluster"), "{e:#}");
    assert_eq!(*n.agreed(), newer, "other clusters are ignored");
    assert!(n.take_state(h.proven(other)).await.is_err());

    // A state another member sends is answered with the version held.
    assert_eq!(
        n.take_state(h.proven(current)).await.unwrap(),
        newer.value.version
    );
    let mut removal = newer.clone();
    removal.value.version += 1;
    removal.value.value.members.remove(&n.me);
    assert_eq!(
        n.take_state(h.proven(removal.clone())).await.unwrap(),
        removal.value.version
    );
    assert!(!n.is_member(&n.me));
}

#[tokio::test]
async fn a_state_without_a_majoritys_proof_is_refused() {
    let h = harness(RelayMode::Never, &[false, false]).await;
    let (n, p, q) = (&h.node, h.peers[0].id(), h.peers[1].id());
    let before = n.agreed();
    // p drops q and sends the result as if it were agreed. This node is the
    // only acceptor, and didn't sign it.
    let mut made_up = (*before).clone();
    made_up.value.version += 1;
    made_up.value.value.members.remove(&q);
    let ballot = Ballot {
        counter: 9,
        node: p,
    };
    made_up.ballot = Some(ballot.clone());
    let header = crate::node::proof::Header::of(n.cluster_id, &made_up.value);
    let cert = crate::node::proof::Certificate::sign(&h.peers[0].identity, header, ballot);
    let pushed = crate::node::proof::Proven {
        chosen: made_up,
        cert: cert.clone(),
        transitions: Vec::new(),
    };
    let e = n.take_state(pushed).await.unwrap_err();
    assert!(e.contains("0 valid acceptor signatures, 1 needed"), "{e}");
    // Nor as a commit notice.
    let notice = postcard::to_stdvec(&cert).unwrap();
    n.handle(p, SVC_COMMIT, notice).await.unwrap();
    assert_eq!(n.agreed(), before);
}

#[tokio::test]
async fn a_state_after_changes_of_acceptors_is_checked_through_the_transitions() {
    let h = harness(RelayMode::Never, &[false, false]).await;
    let (n, p, q) = (&h.node, h.peers[0].id(), h.peers[1].id());
    let start = (*n.agreed()).clone();
    let at = |version: u64, number: u64, acceptors: &[NodeId], next: Option<&[NodeId]>| {
        let mut v = start.clone();
        v.value.version = start.value.version + version;
        v.value.config.number = number;
        v.value.config.acceptors = acceptors.iter().copied().collect();
        v.value.next = next.map(|n| v.value.config.successor(n.iter().copied().collect(), false));
        v.ballot = Some(Ballot {
            counter: 1,
            node: acceptors[0],
        });
        v
    };
    // This node closes configuration 0, naming p; p closes configuration 1,
    // naming q; q agrees a state in configuration 2.
    let t0 = h.certify(&at(1, 0, &[n.me], Some(&[p])));
    let t1 = h.certify(&at(3, 1, &[p], Some(&[q])));
    let later = at(4, 2, &[q], None);
    let proven = |transitions: Vec<_>| crate::node::proof::Proven {
        chosen: later.clone(),
        cert: h.certify(&later),
        transitions,
    };

    let e = n.take_state(proven(vec![])).await.unwrap_err();
    assert!(e.contains("can't check configuration 2 yet"), "{e}");
    // A gap in the chain.
    assert!(n.take_state(proven(vec![t1.clone()])).await.is_err());
    assert_eq!(*n.agreed(), start);

    let version = n
        .take_state(proven(vec![t1.clone(), t0.clone()]))
        .await
        .unwrap();
    assert_eq!(version, later.value.version);
    // This node keeps the transitions, for nodes that are behind.
    let bytes = postcard::to_stdvec(&0u64).unwrap();
    let served: crate::node::proof::Proven =
        postcard::from_bytes(&n.handle(p, SVC_FETCH, bytes).await.unwrap()).unwrap();
    assert_eq!(served.transitions, vec![t0, t1]);
    assert_eq!(served.chosen, later);
}

#[tokio::test]
async fn an_acceptor_gives_up_its_role_before_it_leaves() {
    let h = harness(RelayMode::Never, &[false, false]).await;
    let n = &h.node;
    let q = h.peers[1].id();
    assert_eq!(n.agreed().value.acceptors(), &BTreeSet::from([n.me]));
    let version = n.agreed().value.version;

    // Leaving in one change could leave the only copy of it on this node.
    let e = n.submit(Command::Leave).await.unwrap_err();
    assert_eq!(e.downcast_ref(), Some(&Refused::Acceptor));
    assert_eq!(n.agreed().value.version, version);

    // Nobody else is present to take over the role.
    let e = n.give_up_acceptor_role().await.unwrap_err();
    assert_eq!(e.downcast_ref(), Some(&Refused::NoPresentMajority));
    assert_eq!(n.agreed().value.version, version);

    // p says it's connected to q, but this node isn't connected to p, so
    // nothing shows that p is alive: q isn't present either. (Handing the
    // role over is tested in the cluster tests, which have real
    // connections.)
    h.soft(
        0,
        SoftState {
            connected: vec![q],
            ..Default::default()
        },
    );
    let e = n.give_up_acceptor_role().await.unwrap_err();
    assert_eq!(e.downcast_ref(), Some(&Refused::NoPresentMajority));
}

fn info_of(id: &Identity) -> MemberInfo {
    MemberInfo {
        node_id: id.node_id(),
        wg_key: WgKey(id.node_id().0),
        name: "joiner".into(),
        control_addrs: vec![],
        wg_port: 51820,
        relay: false,
    }
}

#[tokio::test]
async fn join_requests_are_checked() {
    let h = harness(RelayMode::Never, &[]).await;
    let n = &h.node;
    let (a, b) = (Identity::generate(), Identity::generate());
    let msg = JoinMessage::Redeem {
        secret: [1; 32],
        info: b.seal(Domain::MemberInfo, &info_of(&b)),
    };
    let e = n.join_request(a.node_id(), msg).await.unwrap_err();
    assert!(
        e.to_string().contains("signed by the connecting key"),
        "{e:#}"
    );
}

#[tokio::test]
async fn a_waiting_joiner_is_told_how_its_join_stands() {
    let h = harness(RelayMode::Always, &[false]).await;
    let n = &h.node;
    let p = &h.peers[0];
    n.submit(Command::ProposeSetting {
        change: SettingChange::ApprovalsRequired(1),
    })
    .await
    .unwrap();

    // A join through this node now waits for p's approval.
    let j = Identity::generate();
    let redeem = |secret| JoinMessage::Redeem {
        secret,
        info: j.seal(Domain::MemberInfo, &info_of(&j)),
    };
    let invite = |secret| {
        n.submit(Command::CreateInvite {
            invite_id: invite_id(&secret),
        })
    };
    invite([10; 32]).await.unwrap();
    let JoinReply::Pending { proposal } =
        n.join_request(j.node_id(), redeem([10; 32])).await.unwrap()
    else {
        panic!("expected pending");
    };
    let status = |proposal| n.join_request(j.node_id(), JoinMessage::Status { proposal });
    assert!(matches!(
        status(proposal).await.unwrap(),
        JoinReply::Pending { .. }
    ));
    // A proposal this node hasn't seen yet: don't give up on it.
    assert!(matches!(
        status(cheesecloth_core::ProposalId([255; 32]))
            .await
            .unwrap(),
        JoinReply::Pending { .. }
    ));
    // Redeeming again (a lost answer) is answered like the first time,
    // whether with the same token or a new one.
    for secret in [[10; 32], [11; 32]] {
        if secret == [11; 32] {
            invite(secret).await.unwrap();
        }
        let reply = n.join_request(j.node_id(), redeem(secret)).await.unwrap();
        assert!(
            matches!(reply, JoinReply::Pending { proposal: q } if q == proposal),
            "{reply:?}"
        );
    }
    // A guessed secret is refused without a change.
    let e = n.join_request(j.node_id(), redeem([99; 32])).await;
    assert!(e.is_ok(), "a waiting joiner is told it's waiting: {e:?}");
    let stranger = Identity::generate();
    let e = n
        .join_request(
            stranger.node_id(),
            JoinMessage::Redeem {
                secret: [99; 32],
                info: stranger.seal(Domain::MemberInfo, &info_of(&stranger)),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        e.downcast_ref::<CommandError>(),
        Some(&CommandError::InviteUnknown)
    );

    // p rejects it; the joiner is told.
    let out = n
        .write(signed(
            &p.identity,
            Some(n.cluster_id),
            Command::Reject { proposal },
        ))
        .await
        .unwrap();
    assert_eq!(out, Ok(Outcome::Rejected { proposal }));
    assert!(matches!(
        status(proposal).await.unwrap(),
        JoinReply::Rejected { .. }
    ));
}

// ------------------------------------------------------------ reachability

#[tokio::test]
async fn a_lone_node_with_a_public_address_counts_as_public() {
    let h = harness_with(RelayMode::Auto, &[], |o| {
        o.advertise = vec!["203.0.113.9".parse().unwrap()];
    })
    .await;
    let n = &h.node;
    {
        let f = n.facts.lock();
        assert!(!f.public, "not until checked");
        assert!(
            f.candidates.contains(&sa("203.0.113.9:0")),
            "{:?}",
            f.candidates
        );
    }
    n.maybe_probe().await.unwrap();
    {
        let f = n.facts.lock();
        assert!(f.public && f.relay);
        assert_eq!(f.public_ip, Some("203.0.113.9".parse().unwrap()));
        assert!(f.wg_public.contains(&sa("203.0.113.9:51999")));
    }
    assert!(n.my_info().relay);
    assert!(n.my_soft_state().relay);
    // Checked recently: not again.
    n.maybe_probe().await.unwrap();
    assert!(n.facts.lock().public);
}

#[tokio::test]
async fn nobody_to_confirm_means_not_public_yet() {
    let h = harness_with(RelayMode::Auto, &[false], |o| {
        o.advertise = vec!["203.0.113.9".parse().unwrap()];
    })
    .await;
    // The only other member isn't connected, so it can't dial us back.
    h.node.maybe_probe().await.unwrap();
    let f = h.node.facts.lock();
    assert!(!f.public && !f.relay);
    assert!(f.wg_public.is_empty());
}

#[tokio::test]
async fn members_on_our_network_cannot_confirm_reachability() {
    let h = harness(RelayMode::Auto, &[true, true]).await;
    let (p, q) = (h.peers[0].id(), h.peers[1].id());
    // Like a VPS: a public address, and a VPN address in a private range
    // that every site reuses.
    h.soft(
        0,
        SoftState {
            control_addrs: vec![sa("198.51.100.7:51821"), sa("172.17.12.2:51821")],
            ..Default::default()
        },
    );
    // Like a LAN neighbour: a global IPv6 address in our prefix.
    h.soft(
        1,
        SoftState {
            control_addrs: vec![sa("[2600:1:2:3::5]:51821")],
            ..Default::default()
        },
    );
    // With no interfaces of ours, nobody is on our network.
    assert!(!h.node.on_our_network(&q, None));
    // Our LAN, a Docker bridge, and the IPv6 prefix the router hands out.
    h.interfaces.lock().nets = vec![
        "10.0.0.0/24".parse().unwrap(),
        "172.17.0.0/16".parse().unwrap(),
        "2600:1:2:3::/64".parse().unwrap(),
    ];
    h.node.refresh_facts();
    // p's private address is inside our bridge's range, but that proves
    // nothing: we are connected to p at its public address.
    assert!(!h.node.on_our_network(&p, None));
    assert!(!h.node.on_our_network(&p, Some(sa("198.51.100.7:51821"))));
    // A connection at an address inside our networks goes over our own
    // interface (also in IPv4-mapped form).
    assert!(h.node.on_our_network(&p, Some(sa("10.0.0.9:51821"))));
    assert!(
        h.node
            .on_our_network(&p, Some(sa("[::ffff:10.0.0.9]:51821")))
    );
    // q's global address is in our prefix, wherever we're connected to it.
    assert!(h.node.on_our_network(&q, None));
    assert!(h.node.on_our_network(&q, Some(sa("198.51.100.8:51821"))));
}

#[tokio::test]
async fn an_unchecked_reachability_is_a_warning() {
    let h = harness(RelayMode::Auto, &[true]).await;
    let warning = "reachability not checked: no member outside our network is connected";
    assert!(!h.node.warnings().iter().any(|w| w == warning));
    // Nobody is connected: normal after starting, so no warning.
    h.node.maybe_probe().await.unwrap();
    assert!(!h.node.facts.lock().only_local_vias);
    h.node.facts.lock().only_local_vias = true;
    assert!(h.node.warnings().iter().any(|w| w == warning));
}

#[tokio::test]
async fn a_restarted_relay_stays_one_until_checked() {
    // Our member record says relay (as `Always` would publish); we now run
    // in `Auto`, like a public node restarting.
    let h = harness_with(RelayMode::Always, &[false], |o| {
        o.relay = RelayMode::Auto;
        o.advertise = vec!["203.0.113.9".parse().unwrap()];
    })
    .await;
    // Nobody is connected yet to dial us back: no result, so still a relay.
    h.node.maybe_probe().await.unwrap();
    h.node.refresh_facts();
    {
        let f = h.node.facts.lock();
        assert!(f.public && f.relay);
        assert!(!f.wg_public.is_empty());
    }
    assert!(h.node.my_info().relay);
}

#[tokio::test]
async fn relay_modes_override_the_check() {
    let h = harness_with(RelayMode::Always, &[false], |o| {
        o.advertise = vec!["203.0.113.9".parse().unwrap()];
    })
    .await;
    h.node.maybe_probe().await.unwrap();
    assert!(h.node.facts.lock().relay);
    assert!(h.node.my_soft_state().relay);
    // A previous run advertised a relay; `never` must override that record.
    let h = harness_with(RelayMode::Always, &[], |o| {
        o.relay = RelayMode::Never;
        o.advertise = vec!["203.0.113.9".parse().unwrap()];
    })
    .await;
    h.node.maybe_probe().await.unwrap();
    assert!(h.node.facts.lock().public);
    assert!(!h.node.facts.lock().relay);
    assert!(h.node.agreed().state().members[&h.node.me].info.relay);
    assert!(!h.node.is_relay(&h.node.me));
    assert!(!h.node.my_info().relay);
    let soft = h.node.my_soft_state();
    assert!(soft.public);
    assert!(!soft.relay);
    assert!(soft.wg_public.contains(&sa("203.0.113.9:51999")));
    assert!(h.node.warnings().is_empty(), "a lone member needs no relay");
}

#[tokio::test]
async fn the_member_record_follows_the_facts() {
    let h = harness(RelayMode::Always, &[]).await;
    let n = &h.node;
    let record = |n: &crate::node::Node| n.agreed().state().members[&n.me].info.clone();
    assert!(record(n).relay);
    n.update_member_record().await.unwrap();
    n.facts.lock().relay = false;
    n.facts.lock().control_addrs = vec![sa("192.0.2.9:51821")];
    n.update_member_record().await.unwrap();
    let info = record(n);
    assert!(!info.relay);
    assert_eq!(info.control_addrs, vec![sa("192.0.2.9:51821")]);
}

#[test]
fn a_change_may_not_make_the_state_too_large() {
    use super::consensus::check_size;
    let small = ClusterState::default();
    let mut large = small.clone();
    for i in 0..10u8 {
        large.invites.insert(
            [i; 32],
            cheesecloth_core::state::Invite {
                creator: NodeId([1; 32]),
                created_at_ms: 0,
                expires_at_ms: 1,
            },
        );
    }
    let max = postcard::to_stdvec(&large).unwrap().len() - 1;
    let e = check_size(&small, &large, max).unwrap_err();
    assert!(matches!(e, Refused::TooLarge { .. }), "{e}");
    // Under the limit, or not growing: allowed.
    assert!(check_size(&small, &large, max + 1).is_ok());
    let mut smaller = large.clone();
    smaller.invites.pop_first();
    assert!(check_size(&large, &smaller, max).is_ok());
    assert!(check_size(&large, &large, max).is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hand_off_leaves_the_state_on_the_new_acceptors() {
    let (a, _a_dir) = crate::testing::daemon("a", RelayMode::Always).await;
    let (b, b_dir) = crate::testing::daemon("b", RelayMode::Auto).await;
    a.init(None).await.unwrap();
    b.join(&a.invite().await.unwrap().token).await.unwrap();
    let (na, nb) = (a.node().unwrap(), b.node().unwrap());
    for _ in 0..150 {
        if na.live().contains(&nb.me) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    // Step 1: a gives the role to b. a was the only acceptor, so no commit
    // notice tells b; b would only learn it by fetching, a second or so later.
    na.give_up_acceptor_role().await.unwrap();
    let version = na.agreed().value.version;
    // Step 2: once the hand-off returns, b has the state, on disk too.
    na.hand_off().await.unwrap();
    assert!(nb.agreed().value.version >= version);
    assert_eq!(nb.agreed().value.acceptors(), &BTreeSet::from([nb.me]));
    let files = Files::new(b_dir.path()).unwrap();
    let saved =
        Stored::<NodeId, ClusterState, super::proof::Certificate>::open(files.acceptor()).unwrap();
    assert!(saved.acceptor().learned().unwrap().value.version >= version);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leave_finishes_a_leave_whose_answer_was_lost() {
    let (a, _a_dir) = crate::testing::daemon("a", RelayMode::Always).await;
    let (b, _b_dir) = crate::testing::daemon("b", RelayMode::Auto).await;
    a.init(None).await.unwrap();
    a.config_set("acceptors", "1").await.unwrap();
    b.join(&a.invite().await.unwrap().token).await.unwrap();
    let (na, nb) = (a.node().unwrap(), b.node().unwrap());
    for _ in 0..150 {
        if na.live().contains(&nb.me) && nb.live().contains(&na.me) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    // b's Leave is accepted by a, the only acceptor, but the answer never
    // reaches b's node: a separate proposer, with b's ID and key, writes it.
    let leave = nb.identity.seal(
        Domain::Command,
        &cheesecloth_core::state::CommandBody {
            cluster_id: Some(nb.cluster_id),
            issued_at_ms: cheesecloth_core::now_ms(),
            command: Command::Leave,
        },
    );
    let mut proposer = pnyx::Proposer::new(nb.me, (*nb.agreed()).clone());
    let transport = super::round::Acceptors::new(&nb);
    let options = pnyx::Options::default();
    pnyx::propose(&mut proposer, &transport, &options, |agreed| {
        let mut next = agreed.value.clone();
        let request = cheesecloth_core::state::Request {
            at_ms: cheesecloth_core::now_ms().max(next.now_ms),
            command: leave.clone(),
        };
        next.apply(&request).unwrap();
        next.record_step(&agreed.value, Some(request));
        (pnyx::Change::Set(next), ())
    })
    .await
    .unwrap();
    // Nobody has learned it: both still count b as a member.
    assert!(na.is_member(&nb.me) && nb.is_member(&nb.me));

    // Running leave again finds the change, and succeeds.
    let v = b.leave(false).await.unwrap();
    assert!(
        matches!(v, crate::api::LeaveView::Left { ref problems, .. } if problems.is_empty()),
        "{v:?}"
    );
    assert!(b.node().is_none(), "b stopped");
    for _ in 0..50 {
        if !na.is_member(&nb.me) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(!na.is_member(&nb.me), "a learned it");
}

#[tokio::test]
async fn a_retried_round_returns_the_answer_stored_in_the_state_it_read() {
    let h = harness(RelayMode::Never, &[]).await;
    let n = &h.node;
    let command = signed(
        &n.identity,
        Some(n.cluster_id),
        Command::CreateInvite {
            invite_id: invite_id(&[7; 32]),
        },
    );
    let first = n.agreed().value.clone();

    // Round 1 applies the command; its answer is lost with the round.
    let mut proposed = false;
    let (change, answer1) = n.write_round(&command, &first, &mut proposed);
    assert!(matches!(change, pnyx::Change::Set(_)));
    assert!(proposed);

    // Another round applied it at another time, and that one was agreed: its
    // answer (the invite's expiry) differs.
    let mut agreed = first.clone();
    agreed.version += 1;
    let at = agreed.value.now_ms.max(cheesecloth_core::now_ms()) + 5_000;
    let stored = agreed.value.apply(&cheesecloth_core::state::Request {
        at_ms: at,
        command: command.clone(),
    });
    assert!(stored.is_ok());
    assert_ne!(answer1, Ok(stored.clone()));

    // A later round of the same write finds it applied, and returns the
    // answer stored in the state it read.
    let (change, answer) = n.write_round(&command, &agreed, &mut proposed);
    assert_eq!(change, pnyx::Change::Keep);
    assert_eq!(answer, Ok(stored));

    // A separate write of the same command is a replay.
    let mut fresh = false;
    let (_, answer) = n.write_round(&command, &agreed, &mut fresh);
    assert_eq!(answer, Ok(Err(CommandError::Replay)));
}

#[test]
fn leave_starts_over_only_when_made_an_acceptor_again() {
    use super::consensus::{LEAVE_ATTEMPTS, start_over};
    let again: anyhow::Result<()> = Err(Refused::Acceptor.into());
    assert!(start_over(&again, true, 1));
    assert!(!start_over(&again, true, LEAVE_ATTEMPTS), "last attempt");
    assert!(!start_over(&again, false, 1), "step 1 didn't move the role");
    let other: anyhow::Result<()> = Err(anyhow::anyhow!("timed out"));
    assert!(!start_over(&other, true, 1));
    assert!(!start_over(&Ok(()), true, 1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_leaving_node_made_an_acceptor_again_is_refused_then_leaves() {
    let (a, _a_dir) = crate::testing::daemon("a", RelayMode::Always).await;
    let (b, _b_dir) = crate::testing::daemon("b", RelayMode::Auto).await;
    let (c, _c_dir) = crate::testing::daemon("c", RelayMode::Auto).await;
    a.init(None).await.unwrap();
    b.join(&a.invite().await.unwrap().token).await.unwrap();
    c.join(&a.invite().await.unwrap().token).await.unwrap();
    let nodes = [a.node().unwrap(), b.node().unwrap(), c.node().unwrap()];
    let ids: BTreeSet<NodeId> = nodes.iter().map(|n| n.me).collect();
    for _ in 0..150 {
        if nodes.iter().all(|n| n.live().is_superset(&ids)) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    // a's check (run now, not in 10 s) makes all three acceptors.
    nodes[0].check_acceptors().await.unwrap();
    assert_eq!(nodes[0].agreed().value.acceptors(), &ids, "3 acceptors");

    // Control the order of the handoff and re-selection below. Background
    // maintenance could otherwise re-add a before the test asks it to.
    // Network handlers stay active, so every step still uses real requests.
    for n in &nodes {
        n.lifetime.stop_tasks().await;
    }
    let na = &nodes[0];

    // Step 1: a gives up its role. Two members remain, so one acceptor.
    na.give_up_acceptor_role().await.unwrap();
    let gave_up = na.agreed();
    let acceptors = gave_up.value.acceptors().clone();
    assert!(!acceptors.contains(&na.me));
    let new = nodes
        .iter()
        .filter(|n| acceptors.contains(&n.me))
        .min_by_key(|n| n.me)
        .unwrap();

    // Step 2: the replacement must learn the handoff before its check.
    // Otherwise it may still see the old three-acceptor set and do nothing.
    na.hand_off().await.unwrap();

    // Before step 3, that acceptor's check sees three members and a target
    // of three, and adds a back.
    new.check_acceptors().await.unwrap();
    let restored = new.agreed();
    assert!(restored.value.active_config().number > gave_up.value.active_config().number);
    assert_eq!(
        restored.value.acceptors(),
        &ids,
        "a was made an acceptor again"
    );

    // Step 3: the removal is refused, and leave would start over.
    let removed = na.submit(Command::Leave).await.map(drop);
    let e = removed.as_ref().unwrap_err();
    assert_eq!(e.downcast_ref(), Some(&Refused::Acceptor), "{e:#}");
    assert!(super::consensus::start_over(&removed, true, 1));

    // Starting over, a leaves.
    let v = a.leave(false).await.unwrap();
    assert!(
        matches!(v, crate::api::LeaveView::Left { ref problems, .. } if problems.is_empty()),
        "{v:?}"
    );
    assert!(a.node().is_none());
}

#[tokio::test]
async fn a_node_that_learned_its_removal_has_left_even_if_a_step_failed() {
    let h = harness(RelayMode::Never, &[false]).await;
    let n = &h.node;
    // Another member got this node's removal agreed and told it.
    let mut removed = (*n.agreed()).clone();
    removed.value.version += 1;
    removed.value.value.members.remove(&n.me);
    h.learn(removed).await.unwrap();
    assert!(!n.is_member(&n.me));
    // Its own steps fail (nobody is present to take the acceptor role), but
    // it has left.
    assert!(n.give_up_acceptor_role().await.is_err());
    assert_eq!(n.leave(false).await.unwrap(), Vec::<String>::new());
}

#[tokio::test]
async fn a_state_saved_by_a_dropped_learn_is_taken_in_when_learned_again() {
    let h = harness(RelayMode::Never, &[false]).await;
    let n = &h.node;
    let mut next = (*n.agreed()).clone();
    next.value.version += 1;
    // A `learn` that was dropped after its save: the acceptor holds `next`,
    // but the node doesn't have it as its agreed state.
    let p = h.proven(next.clone());
    let saved = n.acceptor.lock().await.learn(next.clone(), p.cert).unwrap();
    assert!(saved);
    assert_ne!(*n.agreed(), next);
    h.learn(next.clone()).await.unwrap();
    assert_eq!(*n.agreed(), next);
}

/// The harness node's agreed value, with this node and all four peers as
/// acceptors. The `acceptors` setting is 3, and no peer is present.
fn five_acceptors(h: &crate::testing::Harness) -> super::Agreed {
    let mut v = h.node.agreed().value.clone();
    v.config.acceptors = std::iter::once(h.node.me)
        .chain(h.peers.iter().map(|p| p.id()))
        .collect();
    v
}

#[tokio::test]
async fn removing_an_acceptor_is_refused_without_a_present_majority() {
    let h = harness(RelayMode::Never, &[false; 4]).await;
    let agreed = five_acceptors(&h);
    // Removing peer 0 leaves four members, so three acceptors: this node
    // and two peers that aren't present.
    let mut next = agreed.value.clone();
    next.members.remove(&h.peers[0].id());
    let e = h.node.change_to(&agreed, next).unwrap_err();
    assert_eq!(e, Refused::NoPresentMajority);
}

#[tokio::test]
async fn giving_up_the_role_is_refused_without_a_present_majority() {
    let h = harness(RelayMode::Never, &[false; 4]).await;
    let agreed = five_acceptors(&h);
    // Without this node: four members, three acceptors, none present.
    let (change, result) = h.node.give_up_round(&agreed);
    assert_eq!(change, pnyx::Change::Keep);
    assert_eq!(result, Err(Refused::NoPresentMajority));
}

#[tokio::test]
async fn the_acceptors_check_waits_for_a_present_majority() {
    let h = harness(RelayMode::Never, &[false; 4]).await;
    let n = &h.node;
    // Five acceptors, but the setting is three: the check would shrink the
    // set to this node and two peers that aren't present.
    let mut chosen = (*n.agreed()).clone();
    chosen.value.next = Some(
        chosen
            .value
            .config
            .successor(five_acceptors(&h).config.acceptors, false),
    );
    chosen.value.version += 1;
    h.learn(chosen).await.unwrap();
    let e = n.check_acceptors().await.unwrap_err();
    assert!(
        e.to_string().contains("current quorum unavailable"),
        "{e:#}"
    );
    // Nothing was proposed.
    assert_eq!(n.agreed().value.acceptors().len(), 5);
}

/// Exercise the real verification phase before acceptance in single-voter fixtures.
async fn checked_accept(
    n: &super::Node,
    from: NodeId,
    request: PaxosRequest,
) -> Result<crate::proto::PaxosAnswer, String> {
    let Request::Accept {
        config,
        ballot,
        value,
    } = &request
    else {
        panic!("accept expected")
    };
    let answer = n
        .handle_paxos(
            from,
            Request::Prepare {
                config: *config,
                ballot: ballot.clone(),
                have: None,
            },
        )
        .await
        .map_err(|e| e.to_string())?;
    let v = super::round::Verification {
        ballot: ballot.clone(),
        value: value.clone(),
        promises: vec![answer.promise.unwrap()],
        base: Some(n.proven(*config).await),
    };
    let proof = n.verify_round(from, v).await?;
    n.handle_paxos_proven(from, request, Some(proof))
        .await
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn protected_acceptor_requires_evidence_and_rejects_conflicting_recovery() {
    use super::{
        proof::{Certificate, Header, Proven},
        round::{Promise, Verification},
    };
    let h = harness(RelayMode::Never, &[false; 3]).await;
    let n = &h.node;
    let mut closing = (*n.agreed()).clone();
    closing.value.version += 1;
    closing.value.next = Some(
        closing.value.config.successor(
            std::iter::once(n.me)
                .chain(h.peers.iter().map(|p| p.id()))
                .collect(),
            true,
        ),
    );
    h.learn(closing.clone()).await.unwrap();
    let opening = Proven {
        chosen: Chosen {
            value: closing.value.open().unwrap(),
            ballot: None,
        },
        cert: n.cert.lock().clone(),
        transitions: Vec::new(),
    };
    let proposer = h.peers[0].id();
    let ballot = Ballot {
        counter: 7,
        node: proposer,
    };
    let mut value = opening.chosen.value.clone();
    value.version += 1;
    let request = cheesecloth_core::state::Request {
        at_ms: cheesecloth_core::now_ms(),
        command: signed(
            &h.peers[0].identity,
            Some(n.cluster_id),
            Command::CreateInvite {
                invite_id: [17; 32],
            },
        ),
    };
    value.value.apply(&request).unwrap();
    value
        .value
        .record_step(opening.chosen.state(), Some(request));
    let accept = Request::Accept {
        config: value.config.number,
        ballot: ballot.clone(),
        value: value.clone(),
    };
    assert!(
        n.handle_paxos(proposer, accept.clone())
            .await
            .unwrap_err()
            .to_string()
            .contains("requires a verification certificate")
    );
    let promise = Promise {
        cluster: n.cluster_id,
        config: value.config.number,
        ballot: ballot.clone(),
        accepted: None,
    };
    let evidence: Vec<_> = std::iter::once(&*n.identity)
        .chain(h.peers.iter().take(2).map(|p| &p.identity))
        .map(|id| id.seal(Domain::Promise, &promise))
        .collect();
    let v = Verification {
        ballot: ballot.clone(),
        value: value.clone(),
        promises: evidence,
        base: Some(opening.clone()),
    };
    let mut no_evidence = v.clone();
    no_evidence.promises.clear();
    assert!(
        n.verify_round(proposer, no_evidence)
            .await
            .unwrap_err()
            .contains("insufficient prepare quorum")
    );
    let mut proof = n.verify_round(proposer, v.clone()).await.unwrap();
    // The two other endorsements make a verification certificate. An
    // honest voter that endorsed the first value will not endorse a fork.
    let mut fork = v.clone();
    fork.value.value.now_ms += 1;
    assert!(n.verify_round(proposer, fork).await.is_err());
    for p in &h.peers[..2] {
        proof.sigs.extend(
            Certificate::sign_verified(
                &p.identity,
                Header::of(n.cluster_id, &value),
                ballot.clone(),
            )
            .sigs,
        );
    }
    n.handle_paxos_proven(proposer, accept, Some(proof))
        .await
        .unwrap();
    let later = Ballot {
        counter: 8,
        node: proposer,
    };
    let answer = n
        .handle_paxos(
            proposer,
            Request::Prepare {
                config: value.config.number,
                ballot: later.clone(),
                have: None,
            },
        )
        .await
        .unwrap();
    let mut new_promises = vec![answer.promise.unwrap()];
    let empty = Promise {
        ballot: later.clone(),
        ..promise
    };
    new_promises.extend(
        h.peers[..2]
            .iter()
            .map(|p| p.identity.seal(Domain::Promise, &empty)),
    );
    let mut wrong = v;
    wrong.ballot = later.clone();
    wrong.promises = new_promises.clone();
    wrong.value.value.now_ms += 1;
    assert!(
        n.verify_round(proposer, wrong)
            .await
            .unwrap_err()
            .contains("ignores highest accepted value")
    );
    // An exact write-back is recoverable even when only one voter accepted
    // it and nobody has an acceptance quorum certificate yet.
    n.verify_round(
        proposer,
        Verification {
            ballot: later,
            value,
            promises: new_promises,
            base: None,
        },
    )
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn certified_shrinks_can_progress_from_four_to_three_to_two_and_grow_again() {
    let mut daemons = Vec::new();
    let mut dirs = Vec::new();
    for name in ["stage-a", "stage-b", "stage-c", "stage-d"] {
        let (daemon, dir) = crate::testing::daemon(name, RelayMode::Always).await;
        daemons.push(daemon);
        dirs.push(dir);
    }
    daemons[0].init(None).await.unwrap();
    for daemon in &daemons[1..] {
        daemon
            .join(&daemons[0].invite().await.unwrap().token)
            .await
            .unwrap();
    }
    let nodes: Vec<_> = daemons.iter().map(|d| d.node().unwrap()).collect();
    let ids: BTreeSet<_> = nodes.iter().map(|n| n.me).collect();
    for _ in 0..200 {
        if nodes.iter().all(|n| n.live().is_superset(&ids)) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(nodes.iter().all(|n| n.live().is_superset(&ids)));
    // Stop maintenance to control the order. RPC handlers remain active.
    for n in &nodes {
        n.lifetime.stop_tasks().await;
    }
    // A deterministic signed view of reachability lets this test advance the
    // ten-minute absence grace without wall-clock sleeps. Real consensus RPCs
    // still have to obtain the installed quorum at every transition.
    async fn view(nodes: &[std::sync::Arc<super::Node>], reachable: &BTreeSet<NodeId>, seq: u64) {
        for observer in nodes {
            *observer.soft.lock() = crate::soft::SoftTable::default();
            for peer in nodes {
                let state = SoftState {
                    node: peer.me,
                    seq,
                    relay: peer.facts.lock().relay,
                    connected: if reachable.contains(&peer.me) {
                        reachable.iter().copied().collect()
                    } else {
                        Vec::new()
                    },
                    ..Default::default()
                };
                observer
                    .soft
                    .lock()
                    .merge(peer.identity.seal(Domain::SoftState, &state), |_| true);
            }
            for peer in nodes {
                if !reachable.contains(&peer.me) {
                    observer.absent.lock().insert(
                        peer.me,
                        std::time::Instant::now() - std::time::Duration::from_secs(601),
                    );
                }
            }
        }
    }
    async fn share(nodes: &[std::sync::Arc<super::Node>]) {
        let newest = nodes
            .iter()
            .max_by_key(|n| n.agreed().value.version)
            .unwrap();
        let p = newest.proven(0).await;
        for node in nodes {
            node.take_state(p.clone()).await.unwrap();
        }
    }
    share(&nodes).await;
    let initial = nodes[0].agreed().value.acceptors().clone();
    let leader = nodes
        .iter()
        .find(|n| Some(&n.me) == initial.first())
        .unwrap();
    leader.check_acceptors().await.unwrap();
    share(&nodes).await;
    assert_eq!(nodes[0].agreed().value.acceptors().len(), 4);
    assert!(
        nodes[0]
            .agreed()
            .value
            .next
            .as_ref()
            .unwrap_or(&nodes[0].agreed().value.config)
            .protected
    );
    // For this test, mark the last voters as absent in each verifier's local
    // failure detector while leaving transport available to complete the
    // transition. The separate quorum-loss test covers unavailable transport.
    for count in [3, 2] {
        let reachable: BTreeSet<_> = nodes[..count].iter().map(|n| n.me).collect();
        view(&nodes, &reachable, count as u64).await;
        // Call the proposal directly so check_acceptors cannot refresh the
        // deliberately advanced detector from still-open test connections.
        let base = nodes[0].agreed().value.clone();
        nodes[0]
            .propose_change(|agreed| {
                let config =
                    super::acceptors::configuration(agreed, &agreed.value, reachable.clone())
                        .unwrap();
                let mut next = agreed.value.clone();
                next.record_step(&agreed.value, None);
                (pnyx::Change::Close(next, config), ())
            })
            .await
            .unwrap();
        share(&nodes).await;
        let chosen = nodes[0].agreed();
        let installed = chosen.value.next.as_ref().unwrap();
        assert!(chosen.value.version > base.version);
        assert_eq!(
            (
                installed.acceptors.len(),
                installed.quorum(),
                installed.protected
            ),
            (count, 2, false)
        );
    }
    for node in &nodes {
        node.absent.lock().clear();
    }
    nodes[0]
        .propose_change(|agreed| {
            let config =
                super::acceptors::configuration(agreed, &agreed.value, ids.clone()).unwrap();
            let mut next = agreed.value.clone();
            next.record_step(&agreed.value, None);
            (pnyx::Change::Close(next, config), ())
        })
        .await
        .unwrap();
    share(&nodes).await;
    assert!(nodes[0].agreed().value.next.as_ref().unwrap().protected);
    for daemon in &daemons {
        daemon.shutdown().await;
    }
}
