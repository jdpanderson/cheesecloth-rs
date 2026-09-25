//! The acceptor: stores promises and accepted values, one slot for each
//! configuration.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Agreed, Ballot, Chosen, Reply, Request};

/// What an acceptor stores for one configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound(deserialize = "N: Ord + Deserialize<'de>, V: Deserialize<'de>"))]
struct Slot<N, V> {
    promised: Option<Ballot<N>>,
    accepted: Option<(Ballot<N>, Agreed<N, V>)>,
}

impl<N, V> Default for Slot<N, V> {
    fn default() -> Self {
        Slot {
            promised: None,
            accepted: None,
        }
    }
}

/// An acceptor's state. It must be on disk before a reply is sent (see
/// [`crate::store::Stored`]).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
///
/// `P` is the proof that the learned value was agreed, which the caller
/// keeps with it, so that both are saved together. This crate doesn't look
/// at it.
#[serde(bound(
    deserialize = "N: Ord + Deserialize<'de>, V: Deserialize<'de>, P: Deserialize<'de>"
))]
pub struct Acceptor<N, V, P = ()> {
    slots: BTreeMap<u64, Slot<N, V>>,
    /// Last verification endorsement in each configuration, saved before signing.
    verified: BTreeMap<u64, (Ballot<N>, Agreed<N, V>)>,
    /// Evidence authorizing the accepted value, saved atomically with that vote.
    accepted_proofs: BTreeMap<u64, P>,
    /// The latest agreed value this acceptor has learned, with its proof.
    /// Slots of earlier configurations are dropped, and requests for them get
    /// this value.
    learned: Option<(Chosen<N, V>, P)>,
}

impl<N, V, P> Default for Acceptor<N, V, P> {
    fn default() -> Self {
        Acceptor {
            slots: BTreeMap::new(),
            verified: BTreeMap::new(),
            accepted_proofs: BTreeMap::new(),
            learned: None,
        }
    }
}

/// How far above its promise in a configuration an acceptor lets a ballot
/// counter go. Proposers add one for each round, so they stay far below this.
/// It stops a faulty member from using up all the counters with one request:
/// with 64-bit counters, that takes about 2^44 requests.
pub const MAX_COUNTER_STEP: u64 = 1 << 20;

/// A request that no proposer following the protocol sends.
#[derive(Debug, thiserror::Error)]
#[error("invalid request: {0}")]
pub struct InvalidRequest(&'static str);

impl<N: Clone + Ord, V: Clone + PartialEq, P: Clone> Acceptor<N, V, P> {
    /// The only acceptor of a new cluster, holding its first value.
    pub fn genesis(first: Chosen<N, V>, proof: P) -> Self {
        let ballot = first.ballot.clone().expect("genesis has a ballot");
        let slot = Slot {
            promised: Some(ballot.clone()),
            accepted: Some((ballot, first.value.clone())),
        };
        Acceptor {
            verified: BTreeMap::new(),
            accepted_proofs: BTreeMap::from([(first.value.config.number, proof.clone())]),
            slots: BTreeMap::from([(first.value.config.number, slot)]),
            learned: Some((first, proof)),
        }
    }

    /// An acceptor that has promised nothing and knows the agreed value
    /// `chosen`, such as that of a node joining a cluster. It answers requests
    /// for older configurations as stale: the node may have been an acceptor
    /// in one of them before, and lost that state when it left.
    pub fn with_learned(chosen: Chosen<N, V>, proof: P) -> Self {
        Acceptor {
            slots: BTreeMap::new(),
            verified: BTreeMap::new(),
            accepted_proofs: BTreeMap::new(),
            learned: Some((chosen, proof)),
        }
    }

    /// The latest agreed value this acceptor has learned.
    pub fn learned(&self) -> Option<&Chosen<N, V>> {
        self.learned.as_ref().map(|(c, _)| c)
    }

    /// The proof of the learned value.
    pub fn proof(&self) -> Option<&P> {
        self.learned.as_ref().map(|(_, p)| p)
    }

    pub fn accepted_proof(&self, config: u64) -> Option<&P> {
        self.accepted_proofs.get(&config)
    }

    /// Records an endorsement after the caller checks the round's evidence.
    /// A higher ballot can recover abandoned candidates; a timeout cannot erase votes.
    pub fn endorse(
        &mut self,
        ballot: Ballot<N>,
        value: Agreed<N, V>,
    ) -> Result<(), InvalidRequest> {
        let config = value.config.number;
        if self
            .learned()
            .is_some_and(|c| c.value.config.number > config)
        {
            return Err(InvalidRequest("verification in a retired configuration"));
        }
        let slot = self.slots.entry(config).or_default();
        if slot.promised.as_ref().is_some_and(|p| p > &ballot) {
            return Err(InvalidRequest("verification below the promise"));
        }
        if ballot.counter
            > slot
                .promised
                .as_ref()
                .map_or(0, |p| p.counter)
                .saturating_add(MAX_COUNTER_STEP)
        {
            return Err(InvalidRequest("verification ballot too high"));
        }
        if self
            .verified
            .get(&config)
            .is_some_and(|(b, v)| b == &ballot && v != &value)
            || slot
                .accepted
                .as_ref()
                .is_some_and(|(b, v)| b == &ballot && v != &value)
        {
            return Err(InvalidRequest("conflicting verification at one ballot"));
        }
        slot.promised = Some(ballot.clone());
        self.verified.insert(config, (ballot, value));
        Ok(())
    }

    pub fn handle_proven(
        &mut self,
        req: Request<N, V>,
        proof: P,
    ) -> Result<(Reply<N, V>, bool), InvalidRequest> {
        let (reply, changed) = self.handle(req)?;
        if let Reply::Accepted { config, .. } = &reply {
            self.accepted_proofs.insert(*config, proof);
            return Ok((reply, true));
        }
        Ok((reply, changed))
    }

    /// The value this acceptor accepted in `config` at `ballot`, if any. A
    /// proposer that has had it agreed says so, and the acceptor can then
    /// learn it without fetching it.
    pub fn accepted(&self, config: u64, ballot: &Ballot<N>) -> Option<&Agreed<N, V>> {
        match &self.slots.get(&config)?.accepted {
            Some((b, v)) if b == ballot => Some(v),
            _ => None,
        }
    }

    /// The values this acceptor has accepted, one at most for each
    /// configuration it keeps.
    pub fn accepted_values(&self) -> impl Iterator<Item = &Agreed<N, V>> {
        self.slots
            .values()
            .filter_map(|s| s.accepted.as_ref().map(|(_, v)| v))
    }

    /// Answers a request. The second value is true if the state changed, and
    /// must then be stored before the reply is sent.
    pub fn handle(&mut self, req: Request<N, V>) -> Result<(Reply<N, V>, bool), InvalidRequest> {
        let config = match &req {
            Request::Prepare { config, .. } | Request::Accept { config, .. } => *config,
        };
        if let Some((learned, _)) = &self.learned
            && learned.value.config.number > config
        {
            let learned = learned.clone();
            return Ok((Reply::Stale { learned }, false));
        }
        let ballot = match &req {
            Request::Prepare { ballot, .. } | Request::Accept { ballot, .. } => ballot,
        };
        let promised = self.slots.get(&config).and_then(|s| s.promised.as_ref());
        let limit = promised
            .map_or(0, |p| p.counter)
            .saturating_add(MAX_COUNTER_STEP);
        if ballot.counter > limit {
            let ballot = ballot.clone();
            return Ok((
                Reply::TooHigh {
                    config,
                    ballot,
                    limit,
                },
                false,
            ));
        }
        let slot = self.slots.entry(config).or_default();
        let fresh = slot.promised.is_none();
        match req {
            Request::Prepare { ballot, have, .. } => {
                // Each ballot is promised at most once, so at most one round
                // with a ballot reaches a majority, even if a proposer that
                // restarted uses the ballot again.
                if let Some(promised) = &slot.promised
                    && ballot <= *promised
                {
                    let promised = promised.clone();
                    return Ok((reject(config, ballot, promised), false));
                }
                slot.promised = Some(ballot.clone());
                let accepted = slot.accepted.as_ref().map(|(b, v)| {
                    let value = (have.as_ref() != Some(b)).then(|| v.clone());
                    (b.clone(), value)
                });
                let reply = Reply::Promise {
                    config,
                    ballot,
                    accepted,
                };
                Ok((reply, true))
            }
            Request::Accept { ballot, value, .. } => {
                if value.config.number != config {
                    if fresh {
                        self.slots.remove(&config);
                    }
                    return Err(InvalidRequest("value is from another configuration"));
                }
                if let Some(promised) = &slot.promised
                    && ballot < *promised
                {
                    let promised = promised.clone();
                    return Ok((reject(config, ballot, promised), false));
                }
                let changed = match &slot.accepted {
                    Some((b, v)) if *b == ballot => {
                        if *v != value {
                            return Err(InvalidRequest("another value at an accepted ballot"));
                        }
                        false
                    }
                    _ => true,
                };
                slot.promised = Some(ballot.clone());
                slot.accepted = Some((ballot.clone(), value));
                Ok((Reply::Accepted { config, ballot }, changed))
            }
        }
    }

    /// Records an agreed value, and drops the slots of earlier
    /// configurations. Returns true if the state changed.
    pub fn learn(&mut self, chosen: Chosen<N, V>, proof: P) -> bool {
        if let Some((learned, _)) = &self.learned
            && learned.value.version >= chosen.value.version
        {
            return false;
        }
        let config = chosen.value.config.number;
        self.slots = self.slots.split_off(&config);
        self.verified = self.verified.split_off(&config);
        self.accepted_proofs = self.accepted_proofs.split_off(&config);
        self.learned = Some((chosen, proof));
        true
    }
}

fn reject<N, V>(config: u64, ballot: Ballot<N>, mut promised: Ballot<N>) -> Reply<N, V> {
    // A bounded lower bound lets a restarted proposer catch up over several
    // rounds without accepting an arbitrarily large counter from one reply.
    promised.counter = promised
        .counter
        .min(ballot.counter.saturating_add(MAX_COUNTER_STEP));
    Reply::Rejected {
        config,
        ballot,
        promised,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::Config;

    type A = Acceptor<u8, &'static str>;

    fn b(counter: u64, node: u8) -> Ballot<u8> {
        Ballot { counter, node }
    }

    fn value(version: u64, config: u64, v: &'static str) -> Agreed<u8, &'static str> {
        Agreed {
            version,
            config: Config {
                protected: false,
                number: config,
                acceptors: BTreeSet::from([1, 2, 3]),
            },
            next: None,
            value: v,
        }
    }

    fn prepare(config: u64, ballot: Ballot<u8>) -> Request<u8, &'static str> {
        Request::Prepare {
            config,
            ballot,
            have: None,
        }
    }

    #[test]
    fn promises_each_ballot_once() {
        let mut a = A::default();
        let (reply, changed) = a.handle(prepare(0, b(2, 1))).unwrap();
        assert!(changed);
        assert!(matches!(reply, Reply::Promise { accepted: None, .. }));

        // The same ballot again, as from a proposer that restarted.
        let (reply, changed) = a.handle(prepare(0, b(2, 1))).unwrap();
        assert!(!changed);
        assert_eq!(
            reply,
            Reply::Rejected {
                config: 0,
                ballot: b(2, 1),
                promised: b(2, 1)
            }
        );

        let (reply, changed) = a.handle(prepare(0, b(1, 9))).unwrap();
        assert!(!changed);
        assert_eq!(
            reply,
            Reply::Rejected {
                config: 0,
                ballot: b(1, 9),
                promised: b(2, 1)
            }
        );
        let accept = Request::Accept {
            config: 0,
            ballot: b(1, 9),
            value: value(1, 0, "x"),
        };
        assert!(matches!(
            a.handle(accept).unwrap().0,
            Reply::Rejected { .. }
        ));
    }

    #[test]
    fn refuses_counters_far_above_its_promise() {
        let mut a = A::default();
        let too_high = |ballot, limit| Reply::TooHigh {
            config: 0,
            ballot,
            limit,
        };
        // Nothing promised yet: the limit counts from zero.
        let far = b(MAX_COUNTER_STEP + 1, 1);
        assert_eq!(
            a.handle(prepare(0, far.clone())).unwrap(),
            (too_high(far, MAX_COUNTER_STEP), false)
        );
        assert_eq!(a, A::default());
        let (reply, _) = a.handle(prepare(0, b(MAX_COUNTER_STEP, 1))).unwrap();
        assert!(matches!(reply, Reply::Promise { .. }));

        // After a promise, the limit counts from it, for accepts too.
        let far = b(2 * MAX_COUNTER_STEP + 1, 2);
        let accept = Request::Accept {
            config: 0,
            ballot: far.clone(),
            value: value(1, 0, "x"),
        };
        assert_eq!(
            a.handle(accept).unwrap(),
            (too_high(far, 2 * MAX_COUNTER_STEP), false)
        );
        let (reply, _) = a.handle(prepare(0, b(2 * MAX_COUNTER_STEP, 2))).unwrap();
        assert!(matches!(reply, Reply::Promise { .. }));
    }

    #[test]
    fn the_counter_limit_stops_at_the_highest_counter() {
        let mut a = A::default();
        a.slots.insert(
            0,
            Slot {
                promised: Some(b(u64::MAX - 1, 1)),
                accepted: None,
            },
        );
        let (reply, _) = a.handle(prepare(0, b(u64::MAX, 1))).unwrap();
        assert!(matches!(reply, Reply::Promise { .. }));
    }

    #[test]
    fn accepts_and_reports_the_value() {
        let mut a = A::default();
        let accept = Request::Accept {
            config: 0,
            ballot: b(1, 1),
            value: value(1, 0, "x"),
        };
        let (reply, changed) = a.handle(accept).unwrap();
        assert!(changed);
        assert_eq!(
            reply,
            Reply::Accepted {
                config: 0,
                ballot: b(1, 1)
            }
        );

        let (reply, _) = a.handle(prepare(0, b(2, 2))).unwrap();
        let Reply::Promise { accepted, .. } = reply else {
            panic!("{reply:?}")
        };
        assert_eq!(accepted, Some((b(1, 1), Some(value(1, 0, "x")))));

        // A proposer that has the value doesn't get it again.
        let have = Request::Prepare {
            config: 0,
            ballot: b(3, 2),
            have: Some(b(1, 1)),
        };
        let Reply::Promise { accepted, .. } = a.handle(have).unwrap().0 else {
            panic!()
        };
        assert_eq!(accepted, Some((b(1, 1), None)));

        assert_eq!(a.accepted(0, &b(1, 1)), Some(&value(1, 0, "x")));
        assert_eq!(a.accepted(0, &b(2, 1)), None);
        assert_eq!(a.accepted(1, &b(1, 1)), None);
    }

    #[test]
    fn accepts_one_value_for_each_ballot() {
        let mut a = A::default();
        let accept = |v| Request::Accept {
            config: 0,
            ballot: b(1, 1),
            value: value(1, 0, v),
        };
        a.handle(accept("x")).unwrap();
        // The same accept again changes nothing.
        let (reply, changed) = a.handle(accept("x")).unwrap();
        assert!(!changed);
        assert!(matches!(reply, Reply::Accepted { .. }));
        let before = a.clone();
        assert!(a.handle(accept("y")).is_err());
        assert_eq!(a, before);
    }

    #[test]
    fn keeps_configurations_apart() {
        let mut a = A::default();
        a.handle(prepare(0, b(5, 1))).unwrap();
        // A lower ballot is fine in another configuration.
        let (reply, _) = a.handle(prepare(1, b(1, 1))).unwrap();
        assert!(matches!(reply, Reply::Promise { accepted: None, .. }));
    }

    #[test]
    fn refuses_a_value_from_another_configuration() {
        let mut a = A::default();
        let accept = Request::Accept {
            config: 1,
            ballot: b(1, 1),
            value: value(1, 0, "x"),
        };
        assert!(a.handle(accept).is_err());
        assert_eq!(a, A::default());
    }

    #[test]
    fn learning_drops_old_configurations() {
        let mut a = A::default();
        a.handle(prepare(0, b(1, 1))).unwrap();
        a.handle(prepare(1, b(1, 1))).unwrap();
        let learned = Chosen {
            value: value(4, 1, "y"),
            ballot: Some(b(1, 1)),
        };
        assert!(a.learn(learned.clone(), ()));
        assert!(!a.learn(learned.clone(), ()));
        assert_eq!(a.slots.keys().collect::<Vec<_>>(), [&1]);

        let (reply, changed) = a.handle(prepare(0, b(9, 9))).unwrap();
        assert!(!changed);
        assert_eq!(reply, Reply::Stale { learned });
        assert!(matches!(
            a.handle(prepare(1, b(2, 1))).unwrap().0,
            Reply::Promise { .. }
        ));
    }

    #[test]
    fn a_new_acceptor_answers_for_older_configurations_as_stale() {
        let learned = Chosen {
            value: value(4, 1, "y"),
            ballot: None,
        };
        let mut a = A::with_learned(learned.clone(), ());
        assert_eq!(a.learned(), Some(&learned));
        let (reply, changed) = a.handle(prepare(0, b(5, 1))).unwrap();
        assert!(!changed);
        assert_eq!(reply, Reply::Stale { learned });
    }

    #[test]
    fn genesis_holds_the_first_value() {
        let first = Chosen::genesis(1u8, "g");
        let mut a = Acceptor::genesis(first.clone(), ());
        let Reply::Promise { accepted, .. } = a.handle(prepare(0, b(1, 2))).unwrap().0 else {
            panic!()
        };
        assert_eq!(accepted, Some((b(0, 1), Some(first.value))));
    }
}
