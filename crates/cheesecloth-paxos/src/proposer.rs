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
mod tests;
