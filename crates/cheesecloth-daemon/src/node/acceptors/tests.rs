use super::*;
use cheesecloth_core::state::{Member, Settings};

fn id(n: u8) -> NodeId {
    NodeId([n; 32])
}

fn set(v: &[u8]) -> BTreeSet<NodeId> {
    v.iter().map(|n| id(*n)).collect()
}

/// A state with members 1..=n and the given `acceptors` setting. Only
/// the member IDs matter to `choose`.
fn state(n: u8, setting: u8) -> ClusterState {
    let mut st = ClusterState::default();
    let mut settings = Settings::new("100.64.0.0/24".parse().unwrap());
    settings.acceptors = setting;
    st.settings = Some(settings);
    for i in 1..=n {
        st.members.insert(id(i), member(i));
    }
    st
}

fn member(i: u8) -> Member {
    member_of(id(i))
}

fn member_of(node: NodeId) -> Member {
    let identity = cheesecloth_core::Identity::generate();
    let i = node.0[0];
    let info = cheesecloth_core::state::MemberInfo {
        node_id: node,
        wg_key: cheesecloth_core::WgKey(node.0),
        name: format!("m{i}"),
        control_addrs: vec![],
        wg_port: 51820,
        relay: false,
    };
    Member {
        signed_info: identity.seal(cheesecloth_core::Domain::MemberInfo, &info),
        info,
        ipv4: std::net::Ipv4Addr::new(100, 64, 0, i),
        added_at_ms: 0,
        added_by: id(1),
        approved_by: vec![],
    }
}

const PRESENT: Candidate = Candidate {
    relay: false,
    present: true,
    absent: false,
};

#[test]
fn grows_to_the_target_including_two() {
    let st = state(3, 3);
    assert_eq!(choose(&set(&[1]), &st, |_| PRESENT), set(&[1, 2, 3]));
    // A member that isn't present fills the set too; a majority is.
    let f = |n: &NodeId| Candidate {
        present: *n != id(3),
        ..PRESENT
    };
    assert_eq!(choose(&set(&[1]), &st, f), set(&[1, 2, 3]));
    assert!(present_majority(&set(&[1, 2, 3]), f));
    // Two members: one acceptor.
    assert_eq!(choose(&set(&[1]), &state(2, 3), |_| PRESENT), set(&[1, 2]));
}

#[test]
fn relays_are_added_first() {
    let st = state(5, 3);
    let f = |n: &NodeId| Candidate {
        relay: *n == id(4) || *n == id(5),
        ..PRESENT
    };
    assert_eq!(choose(&set(&[1]), &st, f), set(&[1, 4, 5]));
}

#[test]
fn removed_and_absent_acceptors_are_replaced() {
    // 3 was removed from the members.
    let mut st = state(4, 3);
    st.members.remove(&id(3));
    assert_eq!(choose(&set(&[1, 2, 3]), &st, |_| PRESENT), set(&[1, 2, 4]));

    // 2 is absent; 4 isn't present, but isn't absent either, so it
    // takes 2's place.
    let st = state(4, 3);
    let f = |n: &NodeId| Candidate {
        absent: *n == id(2),
        present: *n != id(2) && *n != id(4),
        ..PRESENT
    };
    assert_eq!(choose(&set(&[1, 2, 3]), &st, f), set(&[1, 3, 4]));

    // No other member: 2 stays, although it's absent.
    let st = state(3, 3);
    assert_eq!(choose(&set(&[1, 2, 3]), &st, f), set(&[1, 3]));
}

#[test]
fn a_lower_setting_shrinks_the_set() {
    let st = state(5, 1);
    let f = |n: &NodeId| Candidate {
        relay: *n == id(3),
        ..PRESENT
    };
    assert_eq!(choose(&set(&[1, 2, 3]), &st, f), set(&[3]));
}

#[test]
fn nobody_left_keeps_the_set() {
    let mut st = state(1, 3);
    st.members.remove(&id(1));
    assert_eq!(choose(&set(&[1]), &st, |_| PRESENT), set(&[1]));
}

/// Present unless in `down`; never absent (not yet down for long).
fn down(down: &'static [u8]) -> impl Fn(&NodeId) -> Candidate {
    move |n| Candidate {
        present: !down.iter().any(|d| id(*d) == *n),
        ..PRESENT
    }
}

#[test]
fn a_shrinking_set_keeps_present_acceptors() {
    // 1, 2 and 3 are acceptors; 1 leaves while 2 is down (not yet
    // absent). With two members left, one acceptor: 3, which is up.
    let mut after = state(3, 3);
    after.members.remove(&id(1));
    assert_eq!(choose(&set(&[1, 2, 3]), &after, down(&[2])), set(&[2, 3]));

    // The setting goes from 5 to 3 while 1 and 2 are down: the three
    // present ones stay.
    let st = state(5, 3);
    let current = set(&[1, 2, 3, 4, 5]);
    assert_eq!(choose(&current, &st, down(&[1, 2])), set(&[3, 4, 5]));
}

#[test]
fn a_relay_that_is_down_loses_to_a_present_member() {
    let st = state(3, 1);
    let f = |n: &NodeId| Candidate {
        relay: *n == id(1),
        present: *n != id(1),
        absent: false,
    };
    assert_eq!(choose(&set(&[1, 2, 3]), &st, f), set(&[2]));
}

#[test]
fn a_majority_must_be_present() {
    let three = set(&[1, 2, 3]);
    assert!(present_majority(&three, down(&[])));
    assert!(present_majority(&three, down(&[3])));
    assert!(!present_majority(&three, down(&[2, 3])));
    assert!(present_majority(&set(&[1]), down(&[])));
    assert!(!present_majority(&set(&[1]), down(&[1])));
    // Not enough present members to fill a set: the chosen set may lack
    // a present majority, and the callers then refuse the change.
    let st = state(3, 3);
    let desired = choose(&three, &st, down(&[2, 3]));
    assert!(!present_majority(&desired, down(&[2, 3])));
}

#[test]
fn configuration_policy_and_strict_latch() {
    let mut st = state(7, 7);
    let mut base = super::super::Chosen::genesis(id(1), st.clone()).value;
    for (n, protected, votes) in [
        (1, false, 1),
        (2, false, 2),
        (3, false, 2),
        (4, true, 3),
        (5, true, 4),
        (6, true, 4),
        (7, true, 5),
    ] {
        let c = configuration(&base, &st, (1..=n).map(id).collect()).unwrap();
        assert_eq!((c.protected, c.quorum()), (protected, votes));
        check_set(&c, &base, &st).unwrap();
    }
    st.settings.as_mut().unwrap().strict_security = true;
    assert!(
        !configuration(&base, &st, set(&[1, 2, 3]))
            .unwrap()
            .protected
    );
    base.config = configuration(&base, &st, set(&[1, 2, 3, 4])).unwrap();
    assert!(configuration(&base, &st, set(&[1, 2, 3])).is_err());
    st.settings.as_mut().unwrap().strict_security = false;
    assert!(
        !configuration(&base, &st, set(&[1, 2, 3]))
            .unwrap()
            .protected
    );
    let mut forged = base.config.successor(set(&[1, 2, 3, 4]), false);
    assert!(check_set(&forged, &base, &st).is_err());
    forged.acceptors = set(&[9]);
    assert!(check_set(&forged, &base, &st).is_err());
}

#[test]
fn shrink_requires_the_installed_quorum_at_each_step() {
    let st = state(4, 7);
    let mut base = super::super::Chosen::genesis(id(1), st.clone()).value;
    base.config = configuration(&base, &st, set(&[1, 2, 3, 4])).unwrap();
    assert_eq!(base.config.quorum(), 3);
    assert!(2 < base.config.quorum(), "four directly to two must pause");
    let three = configuration(&base, &st, set(&[1, 2, 3])).unwrap();
    assert!(3 >= base.config.quorum());
    assert_eq!((three.protected, three.quorum()), (false, 2));
    base.config = three;
    let two = configuration(&base, &st, set(&[1, 2])).unwrap();
    assert!(2 >= base.config.quorum());
    assert_eq!((two.protected, two.quorum()), (false, 2));
    assert!(1 < two.quorum(), "two directly to one must pause");
}

#[test]
fn buffer_absorbs_two_outages_without_changing_five_voters() {
    let mut st = state(5, 7);
    st.settings.as_mut().unwrap().buffer_nodes = 2;
    let base = super::super::Chosen::genesis(id(1), st.clone()).value;
    let current = set(&[1, 2, 3, 4, 5]);
    let config = configuration(&base, &st, current.clone()).unwrap();
    assert!(!config.protected);
    assert_eq!(config.quorum(), 3);
    assert_eq!(
        choose(&current, &st, |n| Candidate {
            present: n.0[0] <= 3,
            absent: n.0[0] > 3,
            ..PRESENT
        }),
        current
    );
}
