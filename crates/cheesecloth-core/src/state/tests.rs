//! State machine tests.

use super::*;
use crate::Identity;

struct Node {
    id: Identity,
}

impl Node {
    fn new() -> Self {
        Self {
            id: Identity::generate(),
        }
    }

    fn nid(&self) -> NodeId {
        self.id.node_id()
    }

    fn info(&self) -> Signed<MemberInfo> {
        self.id.seal(
            Domain::MemberInfo,
            &MemberInfo {
                node_id: self.nid(),
                wg_key: WgKey(self.nid().0),
                name: "n".into(),
                control_addrs: vec![],
                wg_port: 51820,
                relay: false,
            },
        )
    }

    fn cmd(&self, cluster_id: Option<ClusterId>, at: u64, command: Command) -> Request {
        Request {
            at_ms: at,
            command: self.id.seal(
                Domain::Command,
                &CommandBody {
                    cluster_id,
                    issued_at_ms: at,
                    command,
                },
            ),
        }
    }
}

fn genesis(founder: &Node) -> ClusterState {
    let mut st = ClusterState::default();
    let out = st.apply(&founder.cmd(
        st.cluster_id,
        1000,
        Command::Genesis {
            nonce: [0; 16],
            settings: Settings::new("100.64.7.0/24".parse().unwrap()),
            founder: founder.info(),
        },
    ));
    assert!(matches!(out, Ok(Outcome::Genesis { .. })), "{out:?}");
    st
}

fn invite(st: &mut ClusterState, by: &Node, at: u64, secret: [u8; 32]) {
    let out = st.apply(&by.cmd(
        st.cluster_id,
        at,
        Command::CreateInvite {
            invite_id: invite_id(&secret),
        },
    ));
    assert!(matches!(out, Ok(Outcome::InviteCreated { .. })), "{out:?}");
}

fn redeem(st: &mut ClusterState, by: &Node, joiner: &Node, at: u64, secret: [u8; 32]) -> Response {
    st.apply(&by.cmd(
        st.cluster_id,
        at,
        Command::RedeemInvite {
            secret,
            joiner: joiner.info(),
        },
    ))
}

#[test]
fn genesis_founder_is_first_member() {
    let a = Node::new();
    let st = genesis(&a);
    assert!(st.is_member(&a.nid()));
    assert_eq!(
        st.members[&a.nid()].ipv4,
        "100.64.7.1".parse::<Ipv4Addr>().unwrap()
    );
    let mut st2 = st.clone();
    let again = st2.apply(&a.cmd(
        None,
        2000,
        Command::Genesis {
            nonce: [1; 16],
            settings: Settings::new("100.64.8.0/24".parse().unwrap()),
            founder: a.info(),
        },
    ));
    assert_eq!(again, Err(CommandError::AlreadyInitialized));
}

#[test]
fn invite_is_single_use_and_burnt_on_failure() {
    let (a, b, c) = (Node::new(), Node::new(), Node::new());
    let mut st = genesis(&a);
    invite(&mut st, &a, 2000, [5; 32]);
    let out = redeem(&mut st, &a, &b, 3000, [5; 32]);
    assert!(matches!(out, Ok(Outcome::Joined { .. })), "{out:?}");
    assert_eq!(
        st.members[&b.nid()].ipv4,
        "100.64.7.2".parse::<Ipv4Addr>().unwrap()
    );
    // Used up.
    assert_eq!(
        redeem(&mut st, &b, &c, 4000, [5; 32]),
        Err(CommandError::InviteUnknown)
    );

    // A failed redemption (already a member) still burns the token.
    invite(&mut st, &a, 5000, [6; 32]);
    assert_eq!(
        redeem(&mut st, &a, &b, 6000, [6; 32]),
        Err(CommandError::AlreadyMember)
    );
    assert_eq!(
        redeem(&mut st, &a, &c, 7000, [6; 32]),
        Err(CommandError::InviteUnknown)
    );
}

#[test]
fn invite_expires_after_ttl() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = genesis(&a);
    invite(&mut st, &a, 2000, [5; 32]);
    let late = 2000 + ms(INVITE_TTL) + 1;
    assert_eq!(
        redeem(&mut st, &a, &b, late, [5; 32]),
        Err(CommandError::InviteUnknown)
    );
}

#[test]
fn non_members_and_replays_are_refused() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = genesis(&a);
    let out = st.apply(&b.cmd(
        st.cluster_id,
        2000,
        Command::CreateInvite { invite_id: [1; 32] },
    ));
    assert_eq!(out, Err(CommandError::NotMember));

    let req = a.cmd(
        st.cluster_id,
        3000,
        Command::CreateInvite { invite_id: [1; 32] },
    );
    let first = st.apply(&req);
    assert!(first.is_ok());
    assert_eq!(st.apply(&req), Err(CommandError::Replay));
    // The first answer is kept with the command, refusals too.
    assert_eq!(st.applied(&req.command), Some(&first));
    let refused = a.cmd(
        st.cluster_id,
        3100,
        Command::Approve {
            proposal: crate::ProposalId([9; 32]),
        },
    );
    assert_eq!(st.apply(&refused), Err(CommandError::NoSuchProposal));
    assert_eq!(
        st.applied(&refused.command),
        Some(&Err(CommandError::NoSuchProposal))
    );

    let mut stale = a.cmd(
        st.cluster_id,
        3000,
        Command::CreateInvite { invite_id: [2; 32] },
    );
    stale.at_ms = 3000 + ms(REPLAY_WINDOW) + 1;
    assert_eq!(st.apply(&stale), Err(CommandError::Stale));
    // Refused before the replay check: not recorded, so it can be sent
    // again at a better time.
    assert_eq!(st.applied(&stale.command), None);
}

#[test]
fn approvals_gate_joins_and_removals_but_not_leaving() {
    let (a, b, c, d) = (Node::new(), Node::new(), Node::new(), Node::new());
    let mut st = genesis(&a);
    for (i, n) in [&b, &c].into_iter().enumerate() {
        let s = [10 + i as u8; 32];
        invite(&mut st, &a, 2000, s);
        redeem(&mut st, &a, n, 2100, s).unwrap();
    }
    // Raise the threshold to 1 (needs 0 approvals right now).
    let out = st.apply(&a.cmd(
        st.cluster_id,
        3000,
        Command::ProposeSetting {
            change: SettingChange::ApprovalsRequired(1),
        },
    ));
    assert_eq!(out, Ok(Outcome::SettingChanged));

    // Join now needs one approval from someone other than the proposer.
    invite(&mut st, &a, 4000, [20; 32]);
    let Ok(Outcome::Pending { proposal }) = redeem(&mut st, &a, &d, 4100, [20; 32]) else {
        panic!("expected pending");
    };
    assert!(!st.is_member(&d.nid()));
    assert!(st.invites.is_empty(), "the invite is burnt while pending");
    assert_eq!(
        st.apply(&a.cmd(st.cluster_id, 4200, Command::Approve { proposal })),
        Err(CommandError::OwnProposal)
    );
    let out = st.apply(&b.cmd(st.cluster_id, 4300, Command::Approve { proposal }));
    assert!(matches!(out, Ok(Outcome::Joined { .. })), "{out:?}");
    assert!(st.is_member(&d.nid()));

    // Lowering the threshold needs the current threshold.
    let out = st.apply(&a.cmd(
        st.cluster_id,
        5000,
        Command::ProposeSetting {
            change: SettingChange::ApprovalsRequired(0),
        },
    ));
    assert!(matches!(out, Ok(Outcome::Pending { .. })), "{out:?}");

    // Removal needs approval, and the target can't approve or reject.
    let Ok(Outcome::Pending { proposal }) = st.apply(&a.cmd(
        st.cluster_id,
        6000,
        Command::ProposeRemove { target: c.nid() },
    )) else {
        panic!("expected pending");
    };
    assert_eq!(
        st.apply(&c.cmd(st.cluster_id, 6100, Command::Approve { proposal })),
        Err(CommandError::OwnRemoval)
    );
    assert_eq!(
        st.apply(&c.cmd(st.cluster_id, 6150, Command::Reject { proposal })),
        Err(CommandError::OwnRemoval)
    );
    assert_eq!(
        st.apply(&b.cmd(st.cluster_id, 6200, Command::Approve { proposal })),
        Ok(Outcome::Removed { node: c.nid() })
    );

    // Leaving skips approvals.
    assert_eq!(
        st.apply(&d.cmd(st.cluster_id, 7000, Command::Leave)),
        Ok(Outcome::Left { node: d.nid() })
    );
    assert!(!st.is_member(&d.nid()));
}

#[test]
fn rejection_drops_a_pending_join() {
    let (a, b, c) = (Node::new(), Node::new(), Node::new());
    let mut st = genesis(&a);
    invite(&mut st, &a, 2000, [1; 32]);
    redeem(&mut st, &a, &b, 2100, [1; 32]).unwrap();
    st.apply(&a.cmd(
        st.cluster_id,
        3000,
        Command::ProposeSetting {
            change: SettingChange::ApprovalsRequired(1),
        },
    ))
    .unwrap();
    invite(&mut st, &a, 4000, [2; 32]);
    let Ok(Outcome::Pending { proposal }) = redeem(&mut st, &a, &c, 4100, [2; 32]) else {
        panic!()
    };
    assert_eq!(
        st.apply(&b.cmd(st.cluster_id, 4200, Command::Reject { proposal })),
        Ok(Outcome::Rejected { proposal })
    );
    assert!(st.proposals.is_empty());
    assert!(!st.is_member(&c.nid()));
}

#[test]
fn threshold_cannot_exceed_possible_approvers() {
    let a = Node::new();
    let mut st = genesis(&a);
    let out = st.apply(&a.cmd(
        st.cluster_id,
        2000,
        Command::ProposeSetting {
            change: SettingChange::ApprovalsRequired(1),
        },
    ));
    assert!(
        matches!(out, Err(CommandError::InvalidSetting(_))),
        "{out:?}"
    );
}

#[test]
fn ipv4_addresses_are_reused_after_removal() {
    let (a, b, c) = (Node::new(), Node::new(), Node::new());
    let mut st = genesis(&a);
    invite(&mut st, &a, 2000, [1; 32]);
    redeem(&mut st, &a, &b, 2100, [1; 32]).unwrap();
    st.apply(&b.cmd(st.cluster_id, 3000, Command::Leave))
        .unwrap();
    invite(&mut st, &a, 4000, [2; 32]);
    let out = redeem(&mut st, &a, &c, 4100, [2; 32]).unwrap();
    assert_eq!(
        out,
        Outcome::Joined {
            node: c.nid(),
            ipv4: "100.64.7.2".parse().unwrap()
        }
    );
}

#[test]
fn wireguard_keys_are_unique() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = genesis(&a);
    invite(&mut st, &a, 2000, [1; 32]);
    let mut info = b.info().open(Domain::MemberInfo).unwrap();
    info.wg_key = WgKey(a.nid().0);
    let out = st.apply(&a.cmd(
        st.cluster_id,
        2100,
        Command::RedeemInvite {
            secret: [1; 32],
            joiner: b.id.seal(Domain::MemberInfo, &info),
        },
    ));
    assert!(
        matches!(out, Err(CommandError::InvalidMember(_))),
        "{out:?}"
    );
    assert!(!st.is_member(&b.nid()));
}

#[test]
fn tampered_member_records_are_detected() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = genesis(&a);
    invite(&mut st, &a, 2000, [1; 32]);
    redeem(&mut st, &a, &b, 2100, [1; 32]).unwrap();
    assert!(st.verify_members().is_ok());
    // Swapping b's WireGuard key without b's signature is caught.
    st.members.get_mut(&b.nid()).unwrap().info.wg_key = WgKey([1; 32]);
    assert!(st.verify_members().is_err());
}

#[test]
fn members_update_only_themselves() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = genesis(&a);
    invite(&mut st, &a, 2000, [1; 32]);
    redeem(&mut st, &a, &b, 2100, [1; 32]).unwrap();
    let out = st.apply(&a.cmd(st.cluster_id, 3000, Command::UpdateSelf { info: b.info() }));
    assert!(
        matches!(out, Err(CommandError::InvalidMember(_))),
        "{out:?}"
    );
    let mut info = a.info().open(Domain::MemberInfo).unwrap();
    info.relay = true;
    let signed = a.id.seal(Domain::MemberInfo, &info);
    assert_eq!(
        st.apply(&a.cmd(st.cluster_id, 3100, Command::UpdateSelf { info: signed })),
        Ok(Outcome::Updated)
    );
    assert!(st.members[&a.nid()].info.relay);
}

#[test]
fn member_records_have_size_limits() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = genesis(&a);
    let update = |st: &mut ClusterState, at, change: &dyn Fn(&mut MemberInfo)| {
        let mut info = a.info().open(Domain::MemberInfo).unwrap();
        change(&mut info);
        let signed = a.id.seal(Domain::MemberInfo, &info);
        st.apply(&a.cmd(st.cluster_id, at, Command::UpdateSelf { info: signed }))
    };
    let invalid = |out: &Response| matches!(out, Err(CommandError::InvalidMember(_)));

    assert!(update(&mut st, 3000, &|i| i.name = "n".repeat(MAX_NAME_LEN)).is_ok());
    assert!(invalid(&update(&mut st, 3001, &|i| {
        i.name = "n".repeat(MAX_NAME_LEN + 1)
    })));
    let addrs = |n: usize| -> Vec<SocketAddr> {
        (0..n)
            .map(|i| SocketAddr::from(([10, 0, 0, i as u8], 51821)))
            .collect()
    };
    assert!(
        update(&mut st, 3002, &|i| i.control_addrs =
            addrs(MAX_CONTROL_ADDRS))
        .is_ok()
    );
    assert!(invalid(&update(&mut st, 3003, &|i| {
        i.control_addrs = addrs(MAX_CONTROL_ADDRS + 1)
    })));

    // Joining with a record that breaks them is refused too.
    invite(&mut st, &a, 4000, [1; 32]);
    let mut info = b.info().open(Domain::MemberInfo).unwrap();
    info.name = "n".repeat(MAX_NAME_LEN + 1);
    let joiner = b.id.seal(Domain::MemberInfo, &info);
    let out = st.apply(&a.cmd(
        st.cluster_id,
        4100,
        Command::RedeemInvite {
            secret: [1; 32],
            joiner,
        },
    ));
    assert!(invalid(&out), "{out:?}");
}

/// A cluster of `a` plus `others`, all admitted without approvals.
fn cluster(a: &Node, others: &[&Node]) -> ClusterState {
    let mut st = genesis(a);
    for (i, n) in others.iter().enumerate() {
        let s = [100 + i as u8; 32];
        invite(&mut st, a, 1500, s);
        redeem(&mut st, a, n, 1600, s).unwrap();
    }
    st
}

fn set(st: &mut ClusterState, by: &Node, at: u64, change: SettingChange) -> Response {
    st.apply(&by.cmd(st.cluster_id, at, Command::ProposeSetting { change }))
}

#[test]
fn commands_before_genesis_are_refused() {
    let a = Node::new();
    let mut st = ClusterState::default();
    assert_eq!(
        st.apply(&a.cmd(st.cluster_id, 1000, Command::Leave)),
        Err(CommandError::NotInitialized)
    );
    assert!(genesis(&a).cluster_id.is_some());
}

#[test]
fn genesis_needs_the_founders_own_record() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = ClusterState::default();
    let out = st.apply(&a.cmd(
        st.cluster_id,
        1000,
        Command::Genesis {
            nonce: [0; 16],
            settings: Settings::new("100.64.7.0/24".parse().unwrap()),
            founder: b.info(),
        },
    ));
    assert!(
        matches!(out, Err(CommandError::InvalidMember(_))),
        "{out:?}"
    );

    // A record naming someone other than its signer.
    let mut info = b.info().open(Domain::MemberInfo).unwrap();
    info.node_id = a.nid();
    let out = st.apply(&a.cmd(
        st.cluster_id,
        1000,
        Command::Genesis {
            nonce: [1; 16],
            settings: Settings::new("100.64.7.0/24".parse().unwrap()),
            founder: b.id.seal(Domain::MemberInfo, &info),
        },
    ));
    assert!(
        matches!(out, Err(CommandError::InvalidMember(_))),
        "{out:?}"
    );

    // A forged signature.
    let mut forged = a.cmd(st.cluster_id, 1000, Command::Leave);
    forged.command.body.push(0);
    assert_eq!(st.apply(&forged), Err(CommandError::BadSignature));
    assert!(st.cluster_id.is_none());
}

#[test]
fn a_joiner_can_only_be_waiting_once() {
    let (a, b, c) = (Node::new(), Node::new(), Node::new());
    let mut st = cluster(&a, &[&b]);
    set(&mut st, &a, 2000, SettingChange::ApprovalsRequired(1)).unwrap();
    invite(&mut st, &a, 3000, [1; 32]);
    assert!(matches!(
        redeem(&mut st, &a, &c, 3100, [1; 32]),
        Ok(Outcome::Pending { .. })
    ));
    invite(&mut st, &b, 3200, [2; 32]);
    assert_eq!(
        redeem(&mut st, &b, &c, 3300, [2; 32]),
        Err(CommandError::AlreadyPending)
    );
}

#[test]
fn removals_of_self_and_strangers() {
    let (a, b, c) = (Node::new(), Node::new(), Node::new());
    let mut st = cluster(&a, &[&b]);
    assert_eq!(
        st.apply(&a.cmd(
            st.cluster_id,
            2000,
            Command::ProposeRemove { target: c.nid() }
        )),
        Err(CommandError::NoSuchMember)
    );
    // Removing yourself is leaving, even when removals need approval.
    set(&mut st, &a, 2100, SettingChange::ApprovalsRequired(1)).unwrap();
    assert_eq!(
        st.apply(&b.cmd(
            st.cluster_id,
            2200,
            Command::ProposeRemove { target: b.nid() }
        )),
        Ok(Outcome::Left { node: b.nid() })
    );
}

#[test]
fn approvals_count_once_per_member() {
    let (a, b, c, d) = (Node::new(), Node::new(), Node::new(), Node::new());
    let mut st = cluster(&a, &[&b, &c, &d]);
    set(&mut st, &a, 2000, SettingChange::ApprovalsRequired(2)).unwrap();
    let Ok(Outcome::Pending { proposal }) = set(&mut st, &a, 2100, SettingChange::Acceptors(5))
    else {
        panic!("expected pending");
    };
    assert_eq!(
        st.apply(&b.cmd(st.cluster_id, 2200, Command::Approve { proposal })),
        Ok(Outcome::Approved {
            proposal,
            remaining: 1
        })
    );
    assert_eq!(
        st.apply(&b.cmd(st.cluster_id, 2300, Command::Approve { proposal })),
        Err(CommandError::AlreadyApproved)
    );
    assert_eq!(
        st.apply(&c.cmd(st.cluster_id, 2400, Command::Approve { proposal })),
        Ok(Outcome::SettingChanged)
    );
    assert_eq!(st.settings().unwrap().acceptors, 5);
    assert_eq!(
        st.apply(&d.cmd(st.cluster_id, 2500, Command::Approve { proposal })),
        Err(CommandError::NoSuchProposal)
    );
    assert_eq!(
        st.apply(&d.cmd(st.cluster_id, 2600, Command::Reject { proposal })),
        Err(CommandError::NoSuchProposal)
    );
}

#[test]
fn a_departing_member_takes_its_proposals_and_approvals_along() {
    let (a, b, c, d) = (Node::new(), Node::new(), Node::new(), Node::new());
    let mut st = cluster(&a, &[&b, &c, &d]);
    set(&mut st, &a, 2000, SettingChange::ApprovalsRequired(2)).unwrap();
    invite(&mut st, &b, 2050, [9; 32]);
    let Ok(Outcome::Pending { proposal: by_b }) =
        set(&mut st, &b, 2100, SettingChange::Acceptors(5))
    else {
        panic!("expected pending");
    };
    let Ok(Outcome::Pending { proposal: by_a }) =
        set(&mut st, &a, 2200, SettingChange::Acceptors(1))
    else {
        panic!("expected pending");
    };
    st.apply(&b.cmd(st.cluster_id, 2300, Command::Approve { proposal: by_a }))
        .unwrap();
    st.apply(&b.cmd(st.cluster_id, 2400, Command::Leave))
        .unwrap();
    assert!(
        !st.proposals.contains_key(&by_b),
        "b's own proposal is gone"
    );
    assert!(
        st.proposals[&by_a].approvals.is_empty(),
        "b's approval is gone"
    );
    assert!(st.invites.is_empty(), "b's invite is gone");
}

#[test]
fn settings_are_validated() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = cluster(&a, &[&b]);
    for v in [0, 8, 9] {
        let out = set(&mut st, &a, 2000 + v as u64, SettingChange::Acceptors(v));
        assert!(
            matches!(out, Err(CommandError::InvalidSetting(_))),
            "{v}: {out:?}"
        );
    }
    assert_eq!(
        set(&mut st, &a, 2100, SettingChange::Acceptors(3)),
        Ok(Outcome::SettingChanged)
    );
    assert_eq!(st.settings().unwrap().acceptors, 3);
}

#[test]
fn the_wireguard_key_is_fixed_for_life() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = cluster(&a, &[&b]);
    let mut info = a.info().open(Domain::MemberInfo).unwrap();
    info.wg_key = WgKey([42; 32]);
    let out = st.apply(&a.cmd(
        st.cluster_id,
        2000,
        Command::UpdateSelf {
            info: a.id.seal(Domain::MemberInfo, &info),
        },
    ));
    assert!(
        matches!(out, Err(CommandError::InvalidMember(_))),
        "{out:?}"
    );
}

#[test]
fn a_full_range_refuses_joins() {
    let (a, b, c) = (Node::new(), Node::new(), Node::new());
    let mut st = ClusterState::default();
    st.apply(&a.cmd(
        st.cluster_id,
        1000,
        Command::Genesis {
            nonce: [0; 16],
            settings: Settings::new("100.64.7.0/30".parse().unwrap()),
            founder: a.info(),
        },
    ))
    .unwrap();
    invite(&mut st, &a, 2000, [1; 32]);
    redeem(&mut st, &a, &b, 2100, [1; 32]).unwrap();
    invite(&mut st, &a, 2200, [2; 32]);
    let out = redeem(&mut st, &a, &c, 2300, [2; 32]);
    assert!(matches!(out, Err(CommandError::RangeFull(_))), "{out:?}");
}

#[test]
fn a_record_filed_under_the_wrong_node_is_detected() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = cluster(&a, &[&b]);
    let m = st.members.remove(&b.nid()).unwrap();
    st.members.insert(NodeId([1; 32]), m);
    assert!(st.verify_members().is_err());
}

#[test]
fn warnings_explain_what_the_cluster_cant_do() {
    let (a, b, c) = (Node::new(), Node::new(), Node::new());
    let mut st = genesis(&a);
    assert!(st.warnings().is_empty());

    let mut st2 = cluster(&a, &[&b]);
    // With 2 members and 1 approval, removals are stuck.
    set(&mut st2, &a, 2100, SettingChange::ApprovalsRequired(1)).unwrap();
    let w = st2.warnings();
    assert_eq!(w.len(), 1, "{w:?}");
    assert!(w[0].contains("removals can no longer be approved"), "{w:?}");

    // When a member leaves, joins can't be approved either.
    st2.apply(&b.cmd(st2.cluster_id, 2200, Command::Leave))
        .unwrap();
    let w = st2.warnings();
    assert!(w[0].contains("joins can no longer be approved"), "{w:?}");

    // Enough members: no warnings.
    invite(&mut st, &a, 3000, [1; 32]);
    redeem(&mut st, &a, &b, 3100, [1; 32]).unwrap();
    invite(&mut st, &a, 3200, [2; 32]);
    redeem(&mut st, &a, &c, 3300, [2; 32]).unwrap();
    set(&mut st, &a, 3500, SettingChange::ApprovalsRequired(1)).unwrap();
    assert!(st.warnings().is_empty(), "{:?}", st.warnings());
}

/// `base` with `req` applied, and the step recorded.
fn stepped(base: &ClusterState, req: Option<Request>) -> ClusterState {
    let mut next = base.clone();
    if let Some(req) = &req {
        let _ = next.apply(req);
    }
    next.record_step(base, req);
    next
}

#[test]
fn a_recorded_step_checks_out() {
    let (a, b) = (Node::new(), Node::new());
    let base = cluster(&a, &[&b]);
    let latest = base.now_ms + 30_000;
    let next = stepped(
        &base,
        Some(a.cmd(
            base.cluster_id,
            base.now_ms + 5,
            Command::CreateInvite { invite_id: [7; 32] },
        )),
    );
    assert_eq!(base.check_step(&next, latest), Ok(()));
    // A refused command is a valid step too.
    let refused = stepped(
        &base,
        Some(b.cmd(
            base.cluster_id,
            base.now_ms + 5,
            Command::ProposeRemove {
                target: NodeId([9; 32]),
            },
        )),
    );
    assert_eq!(base.check_step(&refused, latest), Ok(()));
    // So is a step with no command, which leaves the rest as it was.
    assert_eq!(base.check_step(&stepped(&base, None), latest), Ok(()));
}

#[test]
fn a_made_up_step_is_refused() {
    let (a, b) = (Node::new(), Node::new());
    let base = cluster(&a, &[&b]);
    let latest = base.now_ms + 30_000;
    let invite = |at| {
        Some(a.cmd(
            base.cluster_id,
            at,
            Command::CreateInvite { invite_id: [7; 32] },
        ))
    };

    let mut missing = base.clone();
    missing.now_ms += 1;
    assert_eq!(base.check_step(&missing, latest), Err(StepError::Missing));

    // A member dropped with no command that drops it.
    let mut dropped = stepped(&base, None);
    dropped.members.remove(&b.nid());
    assert_eq!(base.check_step(&dropped, latest), Err(StepError::Different));

    // A valid step, but from another state.
    let mut other = base.clone();
    other.next_proposal += 1;
    let from_other = stepped(&other, invite(base.now_ms + 5));
    assert_eq!(
        base.check_step(&from_other, latest),
        Err(StepError::OtherBase)
    );

    // Times before the state's, or past the latest allowed.
    let early = stepped(&base, invite(base.now_ms - 1));
    assert!(matches!(
        base.check_step(&early, latest),
        Err(StepError::Time { .. })
    ));
    let late = stepped(&base, invite(latest + 1));
    assert!(matches!(
        base.check_step(&late, latest),
        Err(StepError::Time { .. })
    ));
    // A state whose time is already past the latest allows its own time.
    let at_base = stepped(&base, invite(base.now_ms));
    assert_eq!(base.check_step(&at_base, base.now_ms - 10), Ok(()));
}

#[test]
fn approvals_bind_the_action_and_creation_history() {
    let (a, b, c, d) = (Node::new(), Node::new(), Node::new(), Node::new());
    let mut original = cluster(&a, &[&b]);
    set(&mut original, &a, 3000, SettingChange::ApprovalsRequired(1)).unwrap();
    invite(&mut original, &a, 4000, [42; 32]);
    let mut left = original.clone();
    let mut right = original.clone();
    let Ok(Outcome::Pending { proposal: l }) = redeem(&mut left, &a, &c, 4100, [42; 32]) else {
        panic!()
    };
    let Ok(Outcome::Pending { proposal: r }) = redeem(&mut right, &a, &d, 4100, [42; 32]) else {
        panic!()
    };
    assert_eq!(l.sequence(), r.sequence());
    assert_ne!(l, r, "same sequence must not authorize another join");
    let approval = b.cmd(left.cluster_id, 4200, Command::Approve { proposal: l });
    assert_eq!(right.apply(&approval), Err(CommandError::NoSuchProposal));
    assert!(!right.is_member(&d.nid()));
    assert!(left.apply(&approval).is_ok());
    assert!(left.is_member(&c.nid()));
    // A different creation history also yields a different token for the
    // same action and sequence, without depending on later votes.
    let mut changed_history = original;
    invite(&mut changed_history, &a, 4050, [43; 32]);
    let Ok(Outcome::Pending { proposal: other }) =
        redeem(&mut changed_history, &a, &c, 4100, [42; 32])
    else {
        panic!()
    };
    assert_ne!(other, l);
}

#[test]
fn signed_commands_cannot_cross_clusters() {
    let a = Node::new();
    let first = genesis(&a);
    let mut other = ClusterState::default();
    other
        .apply(&a.cmd(
            None,
            1000,
            Command::Genesis {
                nonce: [1; 16],
                settings: Settings::new("100.64.7.0/24".parse().unwrap()),
                founder: a.info(),
            },
        ))
        .unwrap();
    assert_ne!(first.cluster_id, other.cluster_id);
    let request = a.cmd(
        first.cluster_id,
        2000,
        Command::CreateInvite { invite_id: [7; 32] },
    );
    assert_eq!(other.apply(&request), Err(CommandError::WrongCluster));
    assert!(other.invites.is_empty());
}
