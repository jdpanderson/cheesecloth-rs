//! Model check of the acceptor and the proposer with stateright.
//!
//! Proposers run a few operations each on a value that is a list of numbers:
//! append a number, read the list, or change the acceptor set. The network
//! delays and reorders messages, and a proposer's timeout can happen at any
//! time, so to the proposer any message may be lost. In some setups a node
//! can also stop and start again: an acceptor keeps what it saved, and a
//! proposer loses everything and runs its operations again. Acceptors learn
//! agreed values either whole or from commit notices, as in the daemon, and
//! an acceptor dropped from the set may join again, starting from the value
//! it joins with. The checker visits every reachable state and checks that:
//!
//! - the agreed values form one chain: one value for each version, and each
//!   value extends the ones before it;
//! - an operation sees every operation that finished before it started;
//! - an append is in the value it returns, and a change of acceptors too.
//!
//! It also checks three rules of the protocol at the moment they apply, so
//! that a broken rule shows up in small setups:
//!
//! - no two values are proposed at one ballot in one configuration;
//! - every value a proposer returns is agreed: a majority of its
//!   configuration's acceptors accepted it at one ballot;
//! - a proposer enters a configuration only after a value closing the one
//!   before it is agreed.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
};

use cheesecloth_paxos::{
    Acceptor, Agreed, Ballot, Change, Chosen, Config, Proposer, Reply, Request, Step,
};
use stateright::{
    Checker, Expectation, HasDiscoveries, Model, UniformChooser,
    actor::{Actor, ActorModel, Envelope, Id, Network, Out, model_timeout},
};

type Log = Vec<u8>;
type Value = Agreed<usize, Log>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Op {
    Append(u8),
    Read,
    /// Append a number and change the acceptor set, in one change.
    Close(u8, BTreeSet<usize>),
}

/// Requests and learned values carry the index of the proposer's operation,
/// only to record the operation in the history.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Msg {
    Req(usize, Request<usize, Log>),
    Rep(Reply<usize, Log>),
    Learn(usize, Chosen<usize, Log>),
    /// A commit notice, as the daemon sends: the value accepted in this
    /// configuration at this ballot is agreed.
    Commit(u64, Ballot<usize>),
    /// The acceptor's node was removed, and joins again with this agreed
    /// value, from a later configuration than the one it was removed in: it
    /// starts from `Acceptor::with_learned`.
    Rejoin(Chosen<usize, Log>),
}

/// How acceptors learn agreed values, which lets them drop old
/// configurations and tell proposers of the current one. Only needed when
/// the acceptors change; it adds many orders of delivery.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Learning {
    None,
    /// From the whole value, as from a fetch.
    Values,
    /// From commit notices, as the daemon's acceptors mostly do: a proposer
    /// tells the acceptors the ballot of a value it had agreed (its own
    /// ballots only), and they learn the value they accepted at it.
    Commits,
}

#[derive(Clone)]
enum Node {
    Acceptor {
        genesis: Option<Chosen<usize, Log>>,
    },
    Proposer {
        ops: Vec<Op>,
        genesis: Chosen<usize, Log>,
        /// How acceptors learn the values this proposer has had agreed. When
        /// they aren't sent the values, it sends each to itself, only to
        /// record it in the history.
        learning: Learning,
        /// The number of acceptor nodes (IDs 0 to `acceptors - 1`).
        acceptors: usize,
        /// After a change of acceptors, tell the acceptors it dropped to join
        /// again (see `Msg::Rejoin`).
        rejoin: bool,
        /// Rounds the proposer may start for one operation.
        max_rounds: u8,
    },
}

/// What a node keeps when it stops.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Saved {
    Acceptor(Box<Acceptor<usize, Log>>),
    /// How many times the proposer has started.
    Proposer(u8),
}

/// How many times a proposer may start. Each start runs its operations again
/// with a higher ballot, so without a limit the search would never end.
const MAX_STARTS: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum State {
    Acceptor(Acceptor<usize, Log>),
    Proposer {
        p: Box<Proposer<usize, Log>>,
        /// The current operation, or `ops.len()` when all have ended.
        op: usize,
        rounds: u8,
    },
}

impl Node {
    fn start_op(&self, p: &mut Proposer<usize, Log>, op: usize, o: &mut Out<Self>) {
        let Node::Proposer { ops, .. } = self else {
            unreachable!()
        };
        if op < ops.len() {
            send(op, requests(p.begin()), o);
            o.set_timer((), model_timeout());
        }
    }

    fn step(&self, id: Id, state: &mut Cow<State>, step: Step<usize, Log>, o: &mut Out<Self>) {
        let Node::Proposer {
            ops,
            learning,
            acceptors,
            rejoin,
            max_rounds,
            ..
        } = self
        else {
            unreachable!()
        };
        let State::Proposer { p, op, rounds } = state.to_mut() else {
            unreachable!()
        };
        let step = match step {
            Step::Read(value) => {
                let change = match &ops[*op] {
                    Op::Append(x) => {
                        let mut log = value.value.clone();
                        log.push(*x);
                        Change::Set(log)
                    }
                    Op::Read => Change::Keep,
                    Op::Close(x, set) => {
                        let mut log = value.value.clone();
                        log.push(*x);
                        Change::Close(log, value.config.successor(set.clone(), false))
                    }
                };
                p.decide(change)
            }
            step => step,
        };
        match step {
            Step::Wait => {}
            Step::Read(_) | Step::OutOfBallots => unreachable!(),
            Step::Send(requests) => send(*op, requests, o),
            Step::Done(chosen) => {
                // The first `Learn` sent records the value in the history.
                if *learning != Learning::Values {
                    o.send(id, Msg::Learn(*op, chosen.clone()));
                }
                let all = (0..*acceptors).map(Id::from);
                match (learning, &chosen.ballot) {
                    (Learning::Values, _) => {
                        for a in all.clone() {
                            o.send(a, Msg::Learn(*op, chosen.clone()));
                        }
                    }
                    (Learning::Commits, Some(b)) if b.node == usize::from(id) => {
                        let config = chosen.value.config.number;
                        for a in all.clone() {
                            o.send(a, Msg::Commit(config, b.clone()));
                        }
                    }
                    _ => {}
                }
                if *rejoin && matches!(ops[*op], Op::Close(..)) {
                    // A node joins with a value agreed after its removal. A
                    // closed configuration agrees nothing more, so that
                    // value is from a later one: at the earliest, the value
                    // that opens the next.
                    let joined = match chosen.value.open() {
                        Some(value) => Chosen {
                            value,
                            ballot: None,
                        },
                        None => chosen.clone(),
                    };
                    for a in all.filter(|a| !joined.value.acceptors().contains(&usize::from(*a))) {
                        o.send(a, Msg::Rejoin(joined.clone()));
                    }
                }
                *op += 1;
                *rounds = 1;
                self.start_op(p, *op, o);
            }
            Step::Retry { .. } => retry(p, op, rounds, *max_rounds, ops.len(), o),
        }
    }
}

/// The requests of a new round. Counters stay small in the model.
fn requests(step: Step<usize, Log>) -> Vec<(usize, Request<usize, Log>)> {
    let Step::Send(requests) = step else {
        panic!("a new round gave {step:?}")
    };
    requests
}

fn send(op: usize, requests: Vec<(usize, Request<usize, Log>)>, o: &mut Out<Node>) {
    for (to, req) in requests {
        o.send(to.into(), Msg::Req(op, req));
    }
}

/// Starts another round, or gives up on the operation after `max` rounds and
/// goes on to the next one.
fn retry(
    p: &mut Proposer<usize, Log>,
    op: &mut usize,
    rounds: &mut u8,
    max: u8,
    n: usize,
    o: &mut Out<Node>,
) {
    p.abort();
    if *rounds < max {
        *rounds += 1;
    } else {
        *op += 1;
        *rounds = 1;
    }
    if *op < n {
        send(*op, requests(p.begin()), o);
        o.set_timer((), model_timeout());
    }
}

impl Actor for Node {
    type Msg = Msg;
    type State = State;
    type Timer = ();
    type Random = ();
    type Storage = Saved;

    fn on_start(&self, id: Id, storage: &Option<Saved>, o: &mut Out<Self>) -> State {
        match self {
            Node::Acceptor { genesis } => State::Acceptor(match (storage, genesis) {
                (Some(Saved::Acceptor(s)), _) => (**s).clone(),
                (None, Some(g)) => Acceptor::genesis(g.clone(), ()),
                _ => Acceptor::default(),
            }),
            Node::Proposer { ops, genesis, .. } => {
                // Past the limit, the count stays the same, so the states
                // repeat.
                let starts = match storage {
                    Some(Saved::Proposer(n)) => (n + 1).min(MAX_STARTS + 1),
                    _ => 1,
                };
                o.save(Saved::Proposer(starts));
                let mut p = Proposer::new(usize::from(id), genesis.clone());
                let op = if starts <= MAX_STARTS { 0 } else { ops.len() };
                self.start_op(&mut p, op, o);
                State::Proposer {
                    p: Box::new(p),
                    op,
                    rounds: 1,
                }
            }
        }
    }

    fn on_msg(&self, id: Id, state: &mut Cow<State>, src: Id, msg: Msg, o: &mut Out<Self>) {
        match (msg, &**state) {
            (Msg::Req(_, req), State::Acceptor(_)) => {
                let State::Acceptor(a) = state.to_mut() else {
                    unreachable!()
                };
                let (reply, changed) = a.handle(req).expect("proposers send valid requests");
                if changed {
                    o.save(Saved::Acceptor(Box::new(a.clone())));
                }
                o.send(src, Msg::Rep(reply));
            }
            (Msg::Learn(_, chosen), State::Acceptor(a)) => {
                let mut a = a.clone();
                if a.learn(chosen, ()) {
                    o.save(Saved::Acceptor(Box::new(a.clone())));
                    *state.to_mut() = State::Acceptor(a);
                }
            }
            (Msg::Commit(config, ballot), State::Acceptor(a)) => {
                let Some(value) = a.accepted(config, &ballot).cloned() else {
                    return;
                };
                let mut a = a.clone();
                let chosen = Chosen {
                    value,
                    ballot: Some(ballot),
                };
                if a.learn(chosen, ()) {
                    o.save(Saved::Acceptor(Box::new(a.clone())));
                    *state.to_mut() = State::Acceptor(a);
                }
            }
            (Msg::Rejoin(chosen), State::Acceptor(_)) => {
                // Leaving deleted its state; joining starts from the value
                // it joins with.
                let a = Acceptor::with_learned(chosen, ());
                o.save(Saved::Acceptor(Box::new(a.clone())));
                *state.to_mut() = State::Acceptor(a);
            }
            (Msg::Rep(reply), State::Proposer { op, .. }) => {
                let Node::Proposer { ops, .. } = self else {
                    unreachable!()
                };
                if *op == ops.len() {
                    return;
                }
                let State::Proposer { p, .. } = state.to_mut() else {
                    unreachable!()
                };
                let step = p.receive(usize::from(src), reply);
                self.step(id, state, step, o);
            }
            _ => {}
        }
    }

    fn on_timeout(&self, _id: Id, state: &mut Cow<State>, _timer: &(), o: &mut Out<Self>) {
        let Node::Proposer {
            ops, max_rounds, ..
        } = self
        else {
            return;
        };
        let State::Proposer { op, .. } = &**state else {
            return;
        };
        if *op == ops.len() {
            return;
        }
        let State::Proposer { p, op, rounds } = state.to_mut() else {
            unreachable!()
        };
        retry(p, op, rounds, *max_rounds, ops.len(), o);
    }
}

/// What the properties need to know about the past, checked as each
/// message is sent.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct History {
    /// For each configuration and ballot: the value proposed, and the
    /// acceptors that have accepted it.
    accepts: BTreeMap<(u64, Ballot<usize>), (Value, BTreeSet<usize>)>,
    /// The values operations have returned.
    done: BTreeSet<Value>,
    /// For each operation that has started: the highest version returned
    /// before it started.
    started: BTreeMap<(Id, usize), Option<u64>>,
    finished: BTreeSet<(Id, usize)>,
    /// The properties that have failed.
    failed: BTreeSet<&'static str>,
}

struct Setup {
    acceptors: usize,
    initial: BTreeSet<usize>,
    proposers: Vec<Vec<Op>>,
    max_rounds: u8,
    learning: Learning,
    /// Whether acceptors dropped by a change of acceptors join again.
    rejoin: bool,
    /// How many nodes may be stopped at one time.
    crashes: usize,
}

impl Setup {
    fn genesis(&self) -> Chosen<usize, Log> {
        let first = *self.initial.first().unwrap();
        Chosen {
            value: Agreed {
                version: 0,
                config: Config {
                    protected: false,
                    number: 0,
                    acceptors: self.initial.clone(),
                },
                next: None,
                value: vec![],
            },
            ballot: Some(Ballot {
                counter: 0,
                node: first,
            }),
        }
    }

    fn op(&self, id: Id, op: usize) -> &Op {
        &self.proposers[usize::from(id) - self.acceptors][op]
    }

    fn model(self) -> ActorModel<Node, Setup, History> {
        let genesis = self.genesis();
        let mut nodes = vec![];
        for a in 0..self.acceptors {
            let genesis = self.initial.contains(&a).then(|| genesis.clone());
            nodes.push(Node::Acceptor { genesis });
        }
        for ops in &self.proposers {
            nodes.push(Node::Proposer {
                ops: ops.clone(),
                genesis: genesis.clone(),
                learning: self.learning,
                acceptors: self.acceptors,
                rejoin: self.rejoin,
                max_rounds: self.max_rounds,
            });
        }
        let history = History {
            accepts: BTreeMap::from([(
                (0, genesis.ballot.clone().unwrap()),
                (genesis.value.clone(), self.initial.clone()),
            )]),
            done: BTreeSet::new(),
            started: BTreeMap::new(),
            finished: BTreeSet::new(),
            failed: BTreeSet::new(),
        };
        let crashes = self.crashes;
        ActorModel::new(self, history)
            .actors(nodes)
            .max_crashes(crashes)
            .init_network(Network::new_unordered_nonduplicating([]))
            .record_msg_out(record)
            .property(Expectation::Always, CHAIN, |_, s| {
                !s.history.failed.contains(CHAIN)
            })
            .property(Expectation::Always, LINEARIZABLE, |_, s| {
                !s.history.failed.contains(LINEARIZABLE)
            })
            .property(Expectation::Always, TAKE_EFFECT, |_, s| {
                !s.history.failed.contains(TAKE_EFFECT)
            })
            .property(Expectation::Always, ONE_VALUE_PER_BALLOT, |_, s| {
                !s.history.failed.contains(ONE_VALUE_PER_BALLOT)
            })
            .property(Expectation::Always, RETURNS_AGREED, |_, s| {
                !s.history.failed.contains(RETURNS_AGREED)
            })
            .property(Expectation::Always, CLOSED_FIRST, |_, s| {
                !s.history.failed.contains(CLOSED_FIRST)
            })
    }
}

const CHAIN: &str = "one chain of values";
const LINEARIZABLE: &str = "linearizable";
const TAKE_EFFECT: &str = "changes take effect";

const ONE_VALUE_PER_BALLOT: &str = "one value for each ballot";
const RETURNS_AGREED: &str = "returned values are agreed";
const CLOSED_FIRST: &str = "a configuration is entered only once the one before is closed";

fn record(setup: &Setup, history: &History, env: Envelope<&Msg>) -> Option<History> {
    let mut h = history.clone();
    match env.msg {
        Msg::Req(op, req) => {
            if !h.started.contains_key(&(env.src, *op)) {
                let latest = h.done.iter().map(|v| v.version).max();
                h.started.insert((env.src, *op), latest);
            }
            match req {
                Request::Prepare { config, .. } => {
                    if *config > 0 && !h.closed(config - 1) {
                        h.failed.insert(CLOSED_FIRST);
                    }
                }
                Request::Accept {
                    config,
                    ballot,
                    value,
                } => {
                    let (v, _) = h
                        .accepts
                        .entry((*config, ballot.clone()))
                        .or_insert_with(|| (value.clone(), BTreeSet::new()));
                    if v != value {
                        h.failed.insert(ONE_VALUE_PER_BALLOT);
                    }
                }
            }
        }
        Msg::Rep(Reply::Accepted { config, ballot }) => {
            let (_, by) = h
                .accepts
                .get_mut(&(*config, ballot.clone()))
                .expect("an acceptor accepts only what was proposed");
            by.insert(usize::from(env.src));
        }
        Msg::Learn(op, chosen) if !h.finished.contains(&(env.src, *op)) => {
            let value = &chosen.value;
            if !h.done.iter().all(|d| in_chain(d, value)) {
                h.failed.insert(CHAIN);
            }
            // An operation sees every operation that finished before it
            // started.
            if h.started[&(env.src, *op)] > Some(value.version) {
                h.failed.insert(LINEARIZABLE);
            }
            let kept = match setup.op(env.src, *op) {
                Op::Append(x) => value.value.contains(x),
                Op::Close(x, set) => value.value.contains(x) && value.acceptors() == set,
                Op::Read => true,
            };
            if !kept {
                h.failed.insert(TAKE_EFFECT);
            }
            if !h.is_agreed(chosen) {
                h.failed.insert(RETURNS_AGREED);
            }
            h.finished.insert((env.src, *op));
            h.done.insert(value.clone());
        }
        _ => {}
    }
    (h != *history).then_some(h)
}

impl History {
    /// Agreed values: accepted by a majority of their configuration.
    fn agreed(&self) -> impl Iterator<Item = (&(u64, Ballot<usize>), &Value)> {
        self.accepts
            .iter()
            .filter(|(_, (v, by))| by.len() >= v.config.quorum())
            .map(|(k, (v, _))| (k, v))
    }

    fn closed(&self, config: u64) -> bool {
        self.agreed()
            .any(|((c, _), v)| *c == config && v.next.is_some())
    }

    /// A value is agreed if a majority accepted it at its ballot. Without a
    /// ballot, it must be the opening of an agreed closing value.
    fn is_agreed(&self, chosen: &Chosen<usize, Log>) -> bool {
        let config = chosen.value.config.number;
        match &chosen.ballot {
            Some(b) => self
                .agreed()
                .any(|(k, v)| *k == (config, b.clone()) && *v == chosen.value),
            None => self
                .agreed()
                .any(|(_, v)| v.open().as_ref() == Some(&chosen.value)),
        }
    }
}

/// One value for each version, and the later value extends the earlier one.
fn in_chain(a: &Value, b: &Value) -> bool {
    let (a, b) = if a.version <= b.version {
        (a, b)
    } else {
        (b, a)
    };
    if a.version == b.version {
        a == b
    } else {
        b.value.starts_with(&a.value) && a.config.number <= b.config.number
    }
}

fn threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

/// Visits every reachable state.
fn check_all(setup: Setup) {
    // Only a complete search can show that this state is never reached. A
    // simulation that misses it proves nothing.
    let model = setup
        .model()
        .property(Expectation::Sometimes, "all operations done", |m, s| {
            let ops: usize = m.cfg.proposers.iter().map(Vec::len).sum();
            s.history.finished.len() == ops
        });
    let checker = model
        .checker()
        .threads(threads())
        .finish_when(HasDiscoveries::AnyFailures)
        .spawn_dfs()
        .join();
    println!(
        "{} states, {} unique, max depth {}, done {}",
        checker.state_count(),
        checker.unique_state_count(),
        checker.max_depth(),
        checker.is_done()
    );
    checker.assert_properties();
    assert!(checker.is_done(), "the search stopped early");
}

/// Follows random paths for `secs` seconds, for setups too large to check
/// every state.
fn simulate(setup: Setup, secs: u64) {
    let checker = setup
        .model()
        .checker()
        .threads(threads())
        .timeout(std::time::Duration::from_secs(secs))
        .finish_when(HasDiscoveries::AnyFailures)
        .spawn_simulation(0, UniformChooser)
        .join();
    println!(
        "{} states, max depth {}",
        checker.state_count(),
        checker.max_depth()
    );
    checker.assert_properties();
}

fn set(ids: &[usize]) -> BTreeSet<usize> {
    ids.iter().copied().collect()
}

// Complete searches. Each extra round multiplies the number of states by
// about a thousand, since a timeout can happen at any time and the old
// round's messages are still delivered in any order. So the searches with
// two proposers allow one round each, and a retry is searched with one
// proposer alone. The simulations below cover more rounds and proposers.

#[test]
fn every_order_of_two_changes() {
    check_all(Setup {
        acceptors: 3,
        initial: set(&[0, 1, 2]),
        proposers: vec![vec![Op::Append(1)], vec![Op::Append(2)]],
        learning: Learning::None,
        rejoin: false,
        crashes: 0,
        max_rounds: 1,
    });
}

#[test]
fn every_order_of_a_change_and_a_read() {
    check_all(Setup {
        acceptors: 3,
        initial: set(&[0, 1, 2]),
        proposers: vec![vec![Op::Append(1)], vec![Op::Read]],
        learning: Learning::None,
        rejoin: false,
        crashes: 0,
        max_rounds: 1,
    });
}

#[test]
fn every_order_of_a_retried_change() {
    check_all(Setup {
        acceptors: 3,
        initial: set(&[0, 1, 2]),
        proposers: vec![vec![Op::Append(1)]],
        learning: Learning::None,
        rejoin: false,
        crashes: 0,
        max_rounds: 2,
    });
}

#[test]
fn every_order_of_growing_from_one_acceptor() {
    check_all(Setup {
        acceptors: 3,
        initial: set(&[0]),
        proposers: vec![vec![Op::Close(11, set(&[0, 1, 2]))], vec![Op::Append(2)]],
        learning: Learning::Values,
        rejoin: false,
        crashes: 0,
        max_rounds: 1,
    });
}

#[test]
fn every_order_of_replacing_the_acceptor() {
    check_all(Setup {
        acceptors: 2,
        initial: set(&[0]),
        proposers: vec![vec![Op::Close(12, set(&[1]))], vec![Op::Append(2)]],
        learning: Learning::Values,
        rejoin: false,
        crashes: 0,
        max_rounds: 2,
    });
}

#[test]
fn every_order_of_shrinking_from_three_acceptors() {
    // With three acceptors, one accept is not yet a majority, so a closing
    // value can be left on one acceptor only. The next configuration has one
    // acceptor, to keep the search small.
    check_all(Setup {
        acceptors: 3,
        initial: set(&[0, 1, 2]),
        proposers: vec![vec![Op::Close(13, set(&[0]))], vec![Op::Append(2)]],
        learning: Learning::None,
        rejoin: false,
        crashes: 0,
        max_rounds: 1,
    });
}

#[test]
fn every_order_of_a_change_with_restarts() {
    // A proposer that starts again has lost its ballot counter, so it uses
    // ballots it used before.
    check_all(Setup {
        acceptors: 3,
        initial: set(&[0, 1, 2]),
        proposers: vec![vec![Op::Append(1)]],
        learning: Learning::None,
        rejoin: false,
        crashes: 1,
        max_rounds: 1,
    });
}

#[test]
fn every_order_of_replacing_the_acceptor_with_commit_notices_and_a_rejoin() {
    // The acceptor learns from commit notices, as in the daemon; the one
    // replaced joins again, starting from the agreed value it joins with.
    check_all(Setup {
        acceptors: 2,
        initial: set(&[0]),
        proposers: vec![vec![Op::Close(12, set(&[1]))], vec![Op::Append(2)]],
        learning: Learning::Commits,
        rejoin: true,
        crashes: 0,
        max_rounds: 2,
    });
}

#[test]
fn every_order_of_a_change_with_restarts_and_commit_notices() {
    // A restarted proposer uses its old ballots again, and acceptors learn
    // from a ballot alone: they must learn only the value agreed at it.
    check_all(Setup {
        acceptors: 3,
        initial: set(&[0, 1, 2]),
        proposers: vec![vec![Op::Append(1)]],
        learning: Learning::Commits,
        rejoin: false,
        crashes: 1,
        max_rounds: 1,
    });
}

const SIMULATE_SECS: u64 = 5;

#[test]
fn simulate_concurrent_changes() {
    let setup = Setup {
        acceptors: 3,
        initial: set(&[0, 1, 2]),
        proposers: vec![
            vec![Op::Append(1), Op::Read],
            vec![Op::Append(2), Op::Append(3)],
            vec![Op::Read, Op::Append(4)],
        ],
        learning: Learning::None,
        rejoin: false,
        crashes: 0,
        max_rounds: 3,
    };
    simulate(setup, SIMULATE_SECS);
}

#[test]
fn simulate_concurrent_changes_with_restarts() {
    let setup = Setup {
        acceptors: 3,
        initial: set(&[0, 1, 2]),
        proposers: vec![vec![Op::Append(1), Op::Read], vec![Op::Append(2)]],
        learning: Learning::None,
        rejoin: false,
        crashes: 1,
        max_rounds: 3,
    };
    simulate(setup, SIMULATE_SECS);
}

#[test]
fn simulate_changing_acceptors_with_commit_notices_restarts_and_rejoins() {
    let setup = Setup {
        acceptors: 4,
        initial: set(&[0, 1, 2]),
        proposers: vec![
            vec![Op::Close(14, set(&[1, 2, 3])), Op::Append(1)],
            vec![Op::Append(2), Op::Read],
        ],
        learning: Learning::Commits,
        rejoin: true,
        crashes: 1,
        max_rounds: 3,
    };
    simulate(setup, SIMULATE_SECS);
}

#[test]
fn simulate_changing_acceptors_while_others_propose() {
    let setup = Setup {
        acceptors: 4,
        initial: set(&[0, 1, 2]),
        proposers: vec![
            vec![Op::Close(14, set(&[1, 2, 3])), Op::Append(1)],
            vec![Op::Append(2), Op::Read],
        ],
        learning: Learning::Values,
        rejoin: false,
        crashes: 0,
        max_rounds: 3,
    };
    simulate(setup, SIMULATE_SECS);
}

#[test]
fn simulate_two_acceptor_changes_at_once() {
    let setup = Setup {
        acceptors: 5,
        initial: set(&[0, 1, 2]),
        proposers: vec![
            vec![Op::Close(15, set(&[1, 2, 3])), Op::Append(1)],
            vec![Op::Close(16, set(&[0, 3, 4])), Op::Append(2)],
            vec![Op::Append(3), Op::Read],
        ],
        learning: Learning::Values,
        rejoin: false,
        crashes: 0,
        max_rounds: 3,
    };
    simulate(setup, SIMULATE_SECS);
}

#[test]
fn simulate_a_chain_of_acceptor_changes() {
    let setup = Setup {
        acceptors: 5,
        initial: set(&[0]),
        proposers: vec![
            vec![
                Op::Close(17, set(&[0, 1, 2])),
                Op::Close(18, set(&[2, 3, 4])),
                Op::Append(1),
            ],
            vec![Op::Append(2), Op::Read],
        ],
        learning: Learning::Values,
        rejoin: false,
        crashes: 0,
        max_rounds: 3,
    };
    simulate(setup, SIMULATE_SECS);
}
