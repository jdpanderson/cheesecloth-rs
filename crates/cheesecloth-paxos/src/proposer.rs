//! The proposer: runs one change at a time as a state machine with no I/O.
//!
//! [`Proposer::begin`] starts a round and gives the requests to send. Each
//! reply goes to [`Proposer::receive`], which says what to do next with a
//! [`Step`]. When the current value has been read, the caller decides the
//! change with [`Proposer::decide`].

use std::collections::{BTreeMap, BTreeSet};

use crate::{Accepted, Agreed, Ballot, Chosen, Config, Reply, Request};

/// What to do with the value that was read.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Change<N, V> {
    /// Leave it as it is.
    Keep,
    /// Replace it.
    Set(V),
    /// Replace it and close the configuration, naming the acceptors of the
    /// next one.
    Close(V, Config<N>),
}

/// What the caller does next.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Step<N, V> {
    /// Wait for more replies.
    Wait,
    /// Send these requests.
    Send(Vec<(N, Request<N, V>)>),
    /// The current value has been read, and is agreed. Call
    /// [`Proposer::decide`].
    Read(Agreed<N, V>),
    /// The change is agreed.
    Done(Chosen<N, V>),
    /// The round failed, or only wrote back a value. Call
    /// [`Proposer::begin`] again: after a random wait if `wait` is true
    /// (another proposer is active), at once if not (a newer value was
    /// learned or written back).
    Retry { wait: bool },
    /// No new round can start: the ballot counter is at its highest. Only a
    /// faulty member can push counters this far (see
    /// [`crate::MAX_COUNTER_STEP`]).
    OutOfBallots,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Phase<N, V> {
    Idle,
    Prepare {
        config: Config<N>,
        ballot: Ballot<N>,
        /// The ballot of the value we hold for this configuration, if any.
        have: Option<Ballot<N>>,
        /// The value to use if no acceptor in the majority has accepted one.
        seed: Chosen<N, V>,
        promises: BTreeMap<N, Option<Accepted<N, V>>>,
        failed: BTreeSet<N>,
    },
    /// `value` is agreed.
    Read {
        config: Config<N>,
        ballot: Ballot<N>,
        value: Chosen<N, V>,
    },
    Accept {
        config: Config<N>,
        ballot: Ballot<N>,
        value: Agreed<N, V>,
        /// True if this round only writes back the value it read, which
        /// wasn't agreed yet. Once it is, the change goes on with a new round:
        /// at once in the next configuration if the value closes this one,
        /// or after [`Step::Retry`].
        write_back: bool,
        accepted: BTreeSet<N>,
        failed: BTreeSet<N>,
    },
}

/// A proposer. It holds the latest agreed value it knows.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Proposer<N, V> {
    me: N,
    /// The ballot counter of the last round, or a higher one seen since. The
    /// next round uses one more.
    counter: u64,
    known: Chosen<N, V>,
    phase: Phase<N, V>,
}

impl<N: Clone + Ord, V: Clone> Proposer<N, V> {
    pub fn new(me: N, known: Chosen<N, V>) -> Self {
        Proposer {
            me,
            counter: known.ballot.as_ref().map_or(0, |b| b.counter),
            known,
            phase: Phase::Idle,
        }
    }

    /// The latest agreed value this proposer knows.
    pub fn known(&self) -> &Chosen<N, V> {
        &self.known
    }

    /// Records an agreed value learned from elsewhere, if it's newer. A round
    /// in progress continues: its replies still say what's current.
    pub fn learn(&mut self, chosen: Chosen<N, V>) {
        if chosen.value.version > self.known.value.version {
            self.see(chosen.ballot.as_ref());
            self.known = chosen;
        }
    }

    /// Starts a round with a new ballot, in the configuration of the latest
    /// known value. Returns the prepare requests to send.
    pub fn begin(&mut self) -> Step<N, V> {
        let Some(counter) = self.counter.checked_add(1) else {
            return Step::OutOfBallots;
        };
        self.counter = counter;
        let ballot = Ballot {
            counter: self.counter,
            node: self.me.clone(),
        };
        let (seed, have) = match self.known.value.open() {
            Some(opened) => {
                let seed = Chosen {
                    value: opened,
                    ballot: None,
                };
                (seed, None)
            }
            None => (self.known.clone(), self.known.ballot.clone()),
        };
        let config = seed.value.config.clone();
        let requests = config
            .acceptors
            .iter()
            .map(|a| {
                let req = Request::Prepare {
                    config: config.number,
                    ballot: ballot.clone(),
                    have: have.clone(),
                };
                (a.clone(), req)
            })
            .collect();
        self.phase = Phase::Prepare {
            config,
            ballot,
            have,
            seed,
            promises: BTreeMap::new(),
            failed: BTreeSet::new(),
        };
        Step::Send(requests)
    }

    /// Stops the current round, for example after a timeout.
    pub fn abort(&mut self) {
        self.phase = Phase::Idle;
    }

    /// Handles a reply from acceptor `from`.
    pub fn receive(&mut self, from: N, reply: Reply<N, V>) -> Step<N, V> {
        match reply {
            Reply::Promise {
                config,
                ballot,
                accepted,
            } => {
                if !self.in_round(&from, config, &ballot) {
                    return Step::Wait;
                }
                if accepted.as_ref().is_some_and(|(b, _)| *b > ballot) {
                    return self.failed(from, config, &ballot);
                }
                self.see(accepted.as_ref().map(|(b, _)| b));
                let Phase::Prepare {
                    config: c,
                    ballot: b,
                    promises,
                    ..
                } = &mut self.phase
                else {
                    return Step::Wait;
                };
                if c.number != config || *b != ballot || !c.acceptors.contains(&from) {
                    return Step::Wait;
                }
                promises.insert(from, accepted);
                if promises.len() < c.quorum() {
                    return Step::Wait;
                }
                self.read()
            }
            Reply::Accepted { config, ballot } => {
                let Phase::Accept {
                    config: c,
                    ballot: b,
                    accepted,
                    ..
                } = &mut self.phase
                else {
                    return Step::Wait;
                };
                if c.number != config || *b != ballot || !c.acceptors.contains(&from) {
                    return Step::Wait;
                }
                accepted.insert(from);
                if accepted.len() < c.quorum() {
                    return Step::Wait;
                }
                let Phase::Accept {
                    ballot,
                    value,
                    write_back,
                    ..
                } = std::mem::replace(&mut self.phase, Phase::Idle)
                else {
                    unreachable!()
                };
                self.known = Chosen {
                    value,
                    ballot: Some(ballot),
                };
                if write_back && self.known.value.next.is_some() {
                    self.begin()
                } else if write_back {
                    Step::Retry { wait: false }
                } else {
                    Step::Done(self.known.clone())
                }
            }
            Reply::Rejected {
                config,
                ballot,
                promised,
            } => {
                if !self.in_round(&from, config, &ballot) {
                    return Step::Wait;
                }
                if promised >= ballot
                    && promised.counter <= ballot.counter.saturating_add(crate::MAX_COUNTER_STEP)
                {
                    self.see(Some(&promised));
                }
                self.failed(from, config, &ballot)
            }
            Reply::TooHigh {
                config,
                ballot,
                limit,
            } => {
                if !self.in_round(&from, config, &ballot) {
                    return Step::Wait;
                }
                if limit < crate::MAX_COUNTER_STEP || limit >= ballot.counter {
                    return self.failed(from, config, &ballot);
                }
                // Our counter is too far ahead of this acceptor's promise,
                // for example after many rounds that reached no one. Going
                // back is safe: a proposer that restarts does the same, and
                // an acceptor never promises a ballot twice.
                self.counter = self.counter.min(limit.saturating_sub(1));
                self.failed(from, config, &ballot)
            }
            Reply::Stale { learned } => {
                self.learn(learned);
                let current = match &self.phase {
                    Phase::Prepare { config, .. } | Phase::Accept { config, .. } => config.number,
                    _ => return Step::Wait,
                };
                if current >= self.known.value.config.number {
                    // A late answer to an earlier round.
                    return Step::Wait;
                }
                self.phase = Phase::Idle;
                Step::Retry { wait: false }
            }
        }
    }

    fn in_round(&self, from: &N, number: u64, b: &Ballot<N>) -> bool {
        match &self.phase {
            Phase::Prepare { config, ballot, .. } | Phase::Accept { config, ballot, .. } => {
                config.number == number && ballot == b && config.acceptors.contains(from)
            }
            _ => false,
        }
    }

    /// Records that a request to `from` in the current round got no answer.
    pub fn unreachable(&mut self, from: N) -> Step<N, V> {
        let (config, ballot) = match &self.phase {
            Phase::Prepare { config, ballot, .. } | Phase::Accept { config, ballot, .. } => {
                (config.number, ballot.clone())
            }
            _ => return Step::Wait,
        };
        self.failed(from, config, &ballot)
    }

    /// Decides the change, after [`Step::Read`].
    ///
    /// # Panics
    ///
    /// If no value has been read, or if `Change::Close` names no acceptors.
    pub fn decide(&mut self, change: Change<N, V>) -> Step<N, V> {
        let Phase::Read {
            config,
            ballot,
            value,
        } = std::mem::replace(&mut self.phase, Phase::Idle)
        else {
            panic!("decide() called before a value was read");
        };
        let next = match change {
            Change::Keep => {
                self.known = value;
                return Step::Done(self.known.clone());
            }
            Change::Set(v) => Agreed {
                version: value.value.version + 1,
                config: config.clone(),
                next: None,
                value: v,
            },
            Change::Close(v, next) => {
                assert!(
                    !next.acceptors.is_empty(),
                    "a configuration needs acceptors"
                );
                Agreed {
                    version: value.value.version + 1,
                    config: config.clone(),
                    next: Some(next),
                    value: v,
                }
            }
        };
        self.accept(config, ballot, next, false)
    }

    fn see(&mut self, ballot: Option<&Ballot<N>>) {
        if let Some(b) = ballot {
            self.counter = self.counter.max(b.counter);
        }
    }

    /// Counts a refusal or a missing answer. Gives up on the round once a
    /// majority can't be reached.
    fn failed(&mut self, from: N, config: u64, ballot: &Ballot<N>) -> Step<N, V> {
        let (Phase::Prepare {
            config: c,
            ballot: b,
            failed,
            ..
        }
        | Phase::Accept {
            config: c,
            ballot: b,
            failed,
            ..
        }) = &mut self.phase
        else {
            return Step::Wait;
        };
        if c.number != config || b != ballot || !c.acceptors.contains(&from) {
            return Step::Wait;
        }
        failed.insert(from);
        if failed.len() <= c.acceptors.len() - c.quorum() {
            return Step::Wait;
        }
        self.phase = Phase::Idle;
        Step::Retry { wait: true }
    }

    /// Takes the value with the highest ballot from a majority of promises.
    fn read(&mut self) -> Step<N, V> {
        let Phase::Prepare {
            config,
            ballot,
            have,
            seed,
            promises,
            ..
        } = std::mem::replace(&mut self.phase, Phase::Idle)
        else {
            unreachable!()
        };
        let highest = promises.values().flatten().max_by(|a, b| a.0.cmp(&b.0));
        let (value, agreed) = match highest {
            // Nothing accepted in this configuration: the seed is agreed,
            // either as our latest value or as the opening of this
            // configuration from an agreed closing value.
            None => (seed, true),
            Some((b, v)) => {
                let value = match v {
                    Some(v) => v.clone(),
                    // The value we said we have: the seed, which is the
                    // value at ballot `have`. `known` may be newer by now.
                    None if have.as_ref() == Some(b) => seed.value.clone(),
                    // The acceptor left out a value we don't have. No
                    // acceptor does this; start again.
                    None => return Step::Retry { wait: false },
                };
                // Accepted by a majority at one ballot: already agreed. Or
                // the value this proposer had agreed at that ballot (only
                // one value is accepted at a ballot).
                let agreed = promises
                    .values()
                    .all(|p| p.as_ref().map(|(pb, _)| pb) == Some(b))
                    || (self.known.ballot.as_ref() == Some(b)
                        && self.known.value.config.number == config.number);
                let value = Chosen {
                    value,
                    ballot: Some(b.clone()),
                };
                (value, agreed)
            }
        };
        if !agreed {
            // A change builds only on an agreed value, so that acceptors
            // hold the value it builds on and can check the change (see
            // *Authenticated round* in CONSENSUS-SAFETY.md). Write this one
            // back first.
            return self.accept(config, ballot, value.value, true);
        }
        if value.value.next.is_some() {
            // The configuration is closed: continue in the next one.
            self.known = value;
            return self.begin();
        }
        let read = value.value.clone();
        self.phase = Phase::Read {
            config,
            ballot,
            value,
        };
        Step::Read(read)
    }

    fn accept(
        &mut self,
        config: Config<N>,
        ballot: Ballot<N>,
        value: Agreed<N, V>,
        write_back: bool,
    ) -> Step<N, V> {
        let requests = config
            .acceptors
            .iter()
            .map(|a| {
                let req = Request::Accept {
                    config: config.number,
                    ballot: ballot.clone(),
                    value: value.clone(),
                };
                (a.clone(), req)
            })
            .collect();
        self.phase = Phase::Accept {
            config,
            ballot,
            value,
            write_back,
            accepted: BTreeSet::new(),
            failed: BTreeSet::new(),
        };
        Step::Send(requests)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type P = Proposer<u8, &'static str>;

    fn b(counter: u64, node: u8) -> Ballot<u8> {
        Ballot { counter, node }
    }

    fn genesis() -> Chosen<u8, &'static str> {
        let mut first = Chosen::genesis(1, "g");
        first.value.config.acceptors = [1, 2, 3].into();
        first
    }

    fn with(value: &str, version: u64) -> Agreed<u8, &str> {
        let mut v = genesis().value;
        v.version = version;
        v.value = value;
        v
    }

    fn promise(
        ballot: &Ballot<u8>,
        accepted: Option<(Ballot<u8>, Agreed<u8, &'static str>)>,
    ) -> Reply<u8, &'static str> {
        Reply::Promise {
            config: 0,
            ballot: ballot.clone(),
            accepted: accepted.map(|(b, v)| (b, Some(v))),
        }
    }

    fn accepted(ballot: &Ballot<u8>) -> Reply<u8, &'static str> {
        Reply::Accepted {
            config: 0,
            ballot: ballot.clone(),
        }
    }

    /// Starts a round and returns its requests.
    fn begin(p: &mut P) -> Vec<(u8, Request<u8, &'static str>)> {
        let Step::Send(requests) = p.begin() else {
            panic!("no requests")
        };
        requests
    }

    fn ballot_of(requests: &[(u8, Request<u8, &'static str>)]) -> Ballot<u8> {
        match &requests[0].1 {
            Request::Prepare { ballot, .. } | Request::Accept { ballot, .. } => ballot.clone(),
        }
    }

    #[test]
    fn a_change_takes_two_round_trips() {
        let mut p = P::new(9, genesis());
        let reqs = begin(&mut p);
        assert_eq!(reqs.len(), 3);
        // The proposer has the genesis value, so acceptors may leave it out.
        let Request::Prepare { have, .. } = &reqs[0].1 else {
            panic!()
        };
        assert_eq!(have, &Some(b(0, 1)));
        let ballot = ballot_of(&reqs);

        let omitted = Reply::Promise {
            config: 0,
            ballot: ballot.clone(),
            accepted: Some((b(0, 1), None)),
        };
        assert_eq!(p.receive(1, omitted.clone()), Step::Wait);
        // A second answer from the same acceptor doesn't count twice.
        assert_eq!(p.receive(1, omitted.clone()), Step::Wait);
        assert_eq!(p.receive(2, omitted), Step::Read(genesis().value));

        let Step::Send(reqs) = p.decide(Change::Set("x")) else {
            panic!()
        };
        let Request::Accept { value, .. } = &reqs[0].1 else {
            panic!()
        };
        assert_eq!(value, &with("x", 1));
        assert_eq!(p.receive(3, accepted(&ballot)), Step::Wait);
        let done = Step::Done(Chosen {
            value: with("x", 1),
            ballot: Some(ballot),
        });
        assert_eq!(p.receive(1, accepted(&ballot_of(&reqs))), done);
        assert_eq!(p.known().value, with("x", 1));
    }

    #[test]
    fn an_omitted_value_is_the_one_the_round_began_with() {
        let mut p = P::new(9, genesis());
        let ballot = ballot_of(&begin(&mut p));
        // A late answer to an earlier round brings a newer value in the same
        // configuration: the round goes on.
        let newer = Chosen {
            value: with("newer", 5),
            ballot: Some(b(4, 2)),
        };
        assert_eq!(p.receive(3, Reply::Stale { learned: newer }), Step::Wait);
        // A majority leaves out the value the round said it has.
        let omitted = Reply::Promise {
            config: 0,
            ballot: ballot.clone(),
            accepted: Some((b(0, 1), None)),
        };
        p.receive(1, omitted.clone());
        assert_eq!(p.receive(2, omitted), Step::Read(genesis().value));
    }

    #[test]
    fn keeping_an_agreed_value_sends_nothing() {
        let mut p = P::new(9, genesis());
        let ballot = ballot_of(&begin(&mut p));
        let v = with("x", 1);
        p.receive(1, promise(&ballot, Some((b(1, 5), v.clone()))));
        assert_eq!(
            p.receive(2, promise(&ballot, Some((b(1, 5), v.clone())))),
            Step::Read(v.clone())
        );
        let done = Step::Done(Chosen {
            value: v,
            ballot: Some(b(1, 5)),
        });
        assert_eq!(p.decide(Change::Keep), done);
    }

    #[test]
    fn an_unagreed_value_is_written_back_before_a_change() {
        let mut p = P::new(9, genesis());
        let ballot = ballot_of(&begin(&mut p));
        let v = with("x", 1);
        p.receive(1, promise(&ballot, Some((b(1, 5), v.clone()))));
        // Acceptor 2 has an older value: "x" may be accepted by 1 only.
        let old = Some((b(0, 1), genesis().value));
        let Step::Send(reqs) = p.receive(2, promise(&ballot, old)) else {
            panic!()
        };
        let Request::Accept {
            value, ballot: at, ..
        } = &reqs[0].1
        else {
            panic!()
        };
        assert_eq!((value, at), (&v, &ballot));
        p.receive(1, accepted(&ballot));
        // Once it's agreed, a new round reads it.
        assert_eq!(p.receive(2, accepted(&ballot)), Step::Retry { wait: false });
        let next = ballot_of(&begin(&mut p));
        assert!(next > ballot);
        // Acceptor 3 missed the write-back, but "x" at `ballot` is the value
        // this proposer had agreed, so it's read as agreed.
        p.receive(1, promise(&next, Some((ballot.clone(), v.clone()))));
        let behind = Some((b(0, 1), genesis().value));
        assert_eq!(p.receive(3, promise(&next, behind)), Step::Read(v.clone()));
        let done = Step::Done(Chosen {
            value: v,
            ballot: Some(ballot),
        });
        assert_eq!(p.decide(Change::Keep), done);
    }

    #[test]
    fn a_closing_value_moves_to_the_next_configuration() {
        let mut p = P::new(9, genesis());
        let ballot = ballot_of(&begin(&mut p));
        let mut closing = with("x", 1);
        closing.next = Some(closing.config.successor([3, 4, 5].into(), false));
        p.receive(1, promise(&ballot, Some((b(1, 5), closing.clone()))));
        let Step::Send(reqs) = p.receive(2, promise(&ballot, None)) else {
            panic!()
        };
        // Not agreed yet: written back in configuration 0 first.
        assert!(matches!(reqs[0].1, Request::Accept { config: 0, .. }));
        p.receive(1, accepted(&ballot));
        let Step::Send(reqs) = p.receive(2, accepted(&ballot)) else {
            panic!()
        };
        let targets: Vec<u8> = reqs.iter().map(|(to, _)| *to).collect();
        assert_eq!(targets, [3, 4, 5]);
        assert!(matches!(
            reqs[0].1,
            Request::Prepare {
                config: 1,
                have: None,
                ..
            }
        ));

        // The new acceptors hold nothing: the value opened from the closing
        // one is agreed.
        let ballot = ballot_of(&reqs);
        let empty = |config| Reply::Promise {
            config,
            ballot: ballot.clone(),
            accepted: None,
        };
        // An answer from a node outside the configuration is ignored.
        assert_eq!(p.receive(1, empty(1)), Step::Wait);
        p.receive(3, empty(1));
        let opened = closing.open().unwrap();
        assert_eq!(p.receive(4, empty(1)), Step::Read(opened.clone()));
        assert_eq!(opened.config.number, 1);
        assert_eq!(opened.version, 2);
    }

    #[test]
    fn closing_the_configuration() {
        let mut p = P::new(9, genesis());
        let ballot = ballot_of(&begin(&mut p));
        let v = Some((b(0, 1), genesis().value));
        p.receive(1, promise(&ballot, v.clone()));
        p.receive(2, promise(&ballot, v));
        let Step::Send(reqs) = p.decide(Change::Close(
            "c",
            genesis().value.config.successor([2, 3, 4].into(), false),
        )) else {
            panic!()
        };
        let Request::Accept { value, .. } = &reqs[0].1 else {
            panic!()
        };
        assert_eq!(
            value.next,
            Some(value.config.successor([2, 3, 4].into(), false))
        );
        assert_eq!(value.acceptors(), &[2, 3, 4].into());
        p.receive(1, accepted(&ballot));
        // Done once the closing value is agreed; the next change opens the
        // new configuration.
        let Step::Done(chosen) = p.receive(2, accepted(&ballot)) else {
            panic!()
        };
        assert_eq!(chosen.value.config.number, 0);
        let reqs = begin(&mut p);
        assert!(matches!(reqs[0], (2, Request::Prepare { config: 1, .. })));
    }

    #[test]
    fn refusals_from_a_majority_end_the_round() {
        let mut p = P::new(9, genesis());
        let ballot = ballot_of(&begin(&mut p));
        let rejected = Reply::Rejected {
            config: 0,
            ballot: ballot.clone(),
            promised: b(7, 2),
        };
        assert_eq!(p.receive(1, rejected.clone()), Step::Wait);
        assert_eq!(p.unreachable(2), Step::Retry { wait: true });
        // The next ballot is above the one that was promised.
        assert_eq!(ballot_of(&begin(&mut p)), b(8, 9));
        // Answers to the old round are ignored.
        assert_eq!(p.receive(3, rejected), Step::Wait);
    }

    #[test]
    fn a_too_high_answer_takes_the_counter_back() {
        let mut p = P::new(9, genesis());
        // Another proposer's high ballot moves this one's counter up.
        let ballot = ballot_of(&begin(&mut p));
        let rejected = Reply::Rejected {
            config: 0,
            ballot,
            promised: b(crate::MAX_COUNTER_STEP, 2),
        };
        p.receive(1, rejected);
        assert_eq!(p.unreachable(2), Step::Retry { wait: true });
        let ballot = ballot_of(&begin(&mut p));
        assert_eq!(ballot, b(crate::MAX_COUNTER_STEP + 1, 9));

        // An acceptor that has not yet promised any ballot.
        let too_high = Reply::TooHigh {
            config: 0,
            ballot,
            limit: crate::MAX_COUNTER_STEP,
        };
        assert_eq!(p.receive(1, too_high), Step::Wait);
        assert_eq!(p.unreachable(2), Step::Retry { wait: true });
        assert_eq!(ballot_of(&begin(&mut p)), b(crate::MAX_COUNTER_STEP, 9));
    }

    #[test]
    fn an_implausible_rejection_does_not_exhaust_the_counter() {
        let mut p = P::new(9, genesis());
        let ballot = ballot_of(&begin(&mut p));
        let rejected = Reply::Rejected {
            config: 0,
            ballot,
            promised: b(u64::MAX, 2),
        };
        p.receive(1, rejected);
        assert_eq!(p.unreachable(2), Step::Retry { wait: true });
        assert_eq!(ballot_of(&begin(&mut p)), b(2, 9));
    }

    #[test]
    fn stale_foreign_and_malformed_feedback_cannot_change_the_counter() {
        for wrong in 0..4 {
            let mut p = P::new(9, genesis());
            let ballot = ballot_of(&begin(&mut p));
            let mut reply = Reply::Rejected {
                config: 0,
                ballot: ballot.clone(),
                promised: b(100, 1),
            };
            let mut from = 1;
            if let Reply::Rejected {
                config,
                ballot,
                promised,
            } = &mut reply
            {
                match wrong {
                    0 => *config = 9,
                    1 => ballot.counter += 1,
                    2 => from = 99,
                    _ => *promised = b(0, 1),
                }
            }
            p.receive(from, reply);
            p.abort();
            assert_eq!(ballot_of(&begin(&mut p)), b(2, 9));
        }
    }

    #[test]
    fn a_protected_quorum_keeps_working_after_one_maximum_rejection() {
        let mut first = genesis();
        first.value.config.acceptors = [1, 2, 3, 4].into();
        first.value.config.protected = true;
        let mut p = P::new(9, first.clone());
        let ballot = ballot_of(&begin(&mut p));
        p.receive(
            4,
            Reply::Rejected {
                config: 0,
                ballot: ballot.clone(),
                promised: b(u64::MAX, 4),
            },
        );
        for from in 1..=3 {
            let step = p.receive(
                from,
                promise(
                    &ballot,
                    Some((first.ballot.clone().unwrap(), first.value.clone())),
                ),
            );
            if from == 3 {
                assert!(matches!(step, Step::Read(_)));
            }
        }
        assert!(matches!(p.decide(Change::Keep), Step::Done(_)));
        assert_eq!(ballot_of(&begin(&mut p)), b(2, 9));
    }

    #[test]
    fn recovery_starts_above_a_previously_certified_ballot() {
        let mut known = genesis();
        known.ballot = Some(b(5 * crate::MAX_COUNTER_STEP, 2));
        let mut p = P::new(9, known);
        assert_eq!(
            ballot_of(&begin(&mut p)),
            b(5 * crate::MAX_COUNTER_STEP + 1, 9)
        );
    }

    #[test]
    fn a_stale_answer_restarts_with_the_learned_value() {
        let mut p = P::new(9, genesis());
        begin(&mut p);
        let mut later = with("y", 5);
        later.config.number = 2;
        later.config.acceptors = [4, 5, 6].into();
        let learned = Chosen {
            value: later,
            ballot: Some(b(3, 4)),
        };
        let stale = Reply::Stale {
            learned: learned.clone(),
        };
        assert_eq!(p.receive(1, stale.clone()), Step::Retry { wait: false });
        assert_eq!(p.known(), &learned);
        let reqs = begin(&mut p);
        assert!(matches!(reqs[0], (4, Request::Prepare { config: 2, .. })));
        // The same answer again, late, changes nothing.
        assert_eq!(p.receive(2, stale), Step::Wait);
    }

    #[test]
    #[should_panic(expected = "before a value was read")]
    fn decide_needs_a_read() {
        P::new(9, genesis()).decide(Change::Keep);
    }
}
