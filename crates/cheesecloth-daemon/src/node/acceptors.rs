//! Adaptive voter selection. Every transition is certified by the installed
//! configuration. Reachability never changes voting authority by itself.

use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use cheesecloth_core::{
    Domain, NodeId,
    state::{ClusterState, Command},
};
use cheesecloth_paxos::Change;
use tracing::info;

use super::{
    Node,
    consensus::{Refused, short},
};

/// An acceptor that no member has seen for this long is replaced.
const ABSENT_AFTER: Duration = Duration::from_secs(600);
/// How often the acceptor set is checked. Checking sends nothing.
const CHECK_EVERY: Duration = Duration::from_secs(10);

/// Desired size; absence only proposes a change, never installs a quorum.
fn size(st: &ClusterState, available: usize) -> usize {
    st.settings()
        .map_or(7, |s| s.acceptors as usize)
        .min(available)
        .max(1)
}

pub(super) fn check_policy(base: &super::Agreed, st: &ClusterState) -> Result<(), String> {
    if base.config.protected
        && st
            .settings()
            .is_some_and(|s| s.strict_security && s.acceptors < 4)
    {
        return Err("disable strict_security before reducing the voter cap below four".into());
    }
    Ok(())
}

pub fn configuration(
    base: &super::Agreed,
    st: &ClusterState,
    acceptors: BTreeSet<NodeId>,
) -> Result<cheesecloth_paxos::Config<NodeId>, String> {
    let settings = st.settings().ok_or("cluster has no settings")?;
    let n = acceptors.len();
    let latched = settings.strict_security && base.config.protected;
    let protected = n >= 4
        && (latched || n - cheesecloth_paxos::quorum(n, true) >= settings.buffer_nodes as usize);
    if latched && !protected {
        return Err("strict security forbids reducing the protected configuration".into());
    }
    Ok(base.config.successor(acceptors, protected))
}

pub fn check_set(
    next: &cheesecloth_paxos::Config<NodeId>,
    base: &super::Agreed,
    st: &ClusterState,
) -> Result<(), String> {
    if next.acceptors.is_empty() || next.acceptors.len() > size(st, st.members.len()) {
        return Err("invalid acceptor count".into());
    }
    if next.acceptors.iter().any(|id| !st.is_member(id)) {
        return Err("acceptor is not a member".into());
    }
    if *next != configuration(base, st, next.acceptors.clone())? {
        return Err("invalid configuration policy or sequence".into());
    }
    Ok(())
}

/// What is known about a member when choosing acceptors.
#[derive(Clone, Copy, Debug, Default)]
pub struct Candidate {
    pub relay: bool,
    /// Known to be alive now (see `SoftTable::live`).
    pub present: bool,
    /// Not seen for `ABSENT_AFTER`.
    pub absent: bool,
}

/// Keep eligible voters, preferring present members and relays. Fill up to
/// the configured cap with members not absent for the grace period. A buffer
/// absorbs absences without changing the installed group.
pub fn choose(
    current: &BTreeSet<NodeId>,
    st: &ClusterState,
    facts: impl Fn(&NodeId) -> Candidate,
) -> BTreeSet<NodeId> {
    let available = st.members.keys().filter(|id| !facts(id).absent).count();
    let buffer = st.settings().map_or(0, |s| s.buffer_nodes as usize);
    let absent = current.iter().filter(|id| facts(id).absent).count();
    if absent > 0
        && absent <= buffer
        && current.len() <= size(st, st.members.len())
        && current.iter().all(|id| st.is_member(id))
        && available <= current.len()
    {
        return current.clone();
    }
    let target = size(st, available);
    let key = |id: &NodeId| {
        let f = facts(id);
        (f.absent, !f.present, !f.relay, *id)
    };
    let mut keep: Vec<NodeId> = current
        .iter()
        .filter(|a| st.is_member(a) && !facts(a).absent)
        .copied()
        .collect();
    keep.sort_by_key(key);
    keep.truncate(target);
    let mut spare: Vec<NodeId> = st
        .members
        .keys()
        .filter(|m| !keep.contains(m) && !facts(m).absent)
        .copied()
        .collect();
    spare.sort_by_key(key);
    let missing = target - keep.len();
    keep.extend(spare.into_iter().take(missing));
    if keep.is_empty() {
        return current.clone();
    }
    keep.into_iter().collect()
}

/// Whether a majority of `set` is present, so that acceptors `set` could
/// agree on changes now. A change to a set without one would stop the
/// cluster until enough of them come back.
#[cfg(test)]
fn present_majority(set: &BTreeSet<NodeId>, facts: impl Fn(&NodeId) -> Candidate) -> bool {
    set.iter().filter(|a| facts(a).present).count() > set.len() / 2
}

impl Node {
    /// Availability is an input to a proposed transition, never authority to
    /// install one. Each honest verifier checks its own observations.
    pub(super) fn check_reconfiguration(
        &self,
        base: &super::Agreed,
        value: &super::Agreed,
    ) -> Result<()> {
        let Some(next) = &value.next else {
            return Ok(());
        };
        let mut eligible = value.value.clone();
        if let Some(request) = eligible.step.as_ref().and_then(|s| s.command.as_ref()) {
            let body = request.command.open(Domain::Command)?;
            if body.command == Command::GiveUpAcceptor {
                eligible.members.remove(&request.command.signer);
                ensure!(
                    !next.acceptors.contains(&request.command.signer),
                    "giving-up member remains an acceptor"
                );
            }
        }
        let live = self.live();
        let expected = choose(base.acceptors(), &eligible, |id| self.candidate(id, &live));
        ensure!(
            next.acceptors.len() >= expected.len(),
            "configuration omits available voters"
        );
        ensure!(
            next.acceptors.intersection(&live).count() >= next.quorum(),
            "new configuration has no reachable quorum"
        );
        Ok(())
    }

    /// The nodes known to be alive now (see `SoftTable::live`).
    pub fn live(&self) -> BTreeSet<NodeId> {
        let direct: Vec<NodeId> = self.net.connections().iter().map(|c| c.node).collect();
        self.soft.lock().live(self.me, direct)
    }

    /// What `choose` needs to know about `node`, given the live nodes.
    pub(super) fn candidate(&self, node: &NodeId, live: &BTreeSet<NodeId>) -> Candidate {
        let absent = self
            .absent
            .lock()
            .get(node)
            .is_some_and(|t| t.elapsed() >= ABSENT_AFTER);
        Candidate {
            relay: self.is_relay(node),
            present: live.contains(node),
            absent,
        }
    }

    pub(super) async fn acceptors_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(CHECK_EVERY);
        loop {
            tick.tick().await;
            self.acceptors_problem.record(self.check_acceptors().await);
        }
    }

    pub(super) async fn check_acceptors(&self) -> Result<()> {
        let agreed = self.agreed();
        let current = agreed.value.acceptors().clone();
        let live = self.live();
        for a in agreed.state().members.keys() {
            let mut absent = self.absent.lock();
            if live.contains(a) {
                absent.remove(a);
            } else {
                absent.entry(*a).or_insert_with(Instant::now);
            }
        }
        self.absent
            .lock()
            .retain(|n, _| agreed.state().is_member(n));
        if !current.contains(&self.me) {
            return Ok(());
        }
        let installed = agreed.value.active_config();
        // The present acceptor with the lowest node ID acts. Two acting at
        // once is still safe: one of them finds the change made.
        if current.iter().find(|a| live.contains(a)) != Some(&self.me) {
            return Ok(());
        }
        let facts = |n: &NodeId| self.candidate(n, &live);
        let desired = choose(&current, agreed.state(), facts);
        let wanted = configuration(&agreed.value, agreed.state(), desired.clone())
            .map_err(anyhow::Error::msg)?;
        if desired == current && wanted.protected == installed.protected {
            return Ok(());
        }
        if current.iter().filter(|a| facts(a).present).count() < installed.quorum() {
            anyhow::bail!("current quorum unavailable; configuration changes paused");
        }
        if desired.iter().filter(|a| facts(a).present).count() < wanted.quorum() {
            return Err(Refused::NoPresentMajority.into());
        }
        self.propose_change(|agreed| {
            let current = agreed.acceptors();
            let desired = choose(current, &agreed.value, facts);
            let config = match configuration(agreed, &agreed.value, desired.clone()) {
                Ok(c) => c,
                Err(e) => return (Change::Keep, Err(Refused::Security(e))),
            };
            if desired == *current && config.protected == agreed.config.protected {
                return (Change::Keep, Ok(()));
            }
            if desired.iter().filter(|a| facts(a).present).count() < config.quorum() {
                return (Change::Keep, Err(Refused::NoPresentMajority));
            }
            info!(acceptors = ?short(&desired), "changing the acceptors");
            let mut next = agreed.value.clone();
            next.record_step(&agreed.value, None);
            (Change::Close(next, config), Ok(()))
        })
        .await??;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
}
