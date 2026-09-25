//! CASPaxos for cheesecloth: agreement on one value, changed by
//! compare-and-set, with no leader and no log (see *Consensus and recovery*
//! in DESIGN.md).
//!
//! The acceptor and the proposer are state machines with no I/O, so they can
//! be model-checked. [`propose`] runs one change over a [`Transport`], and
//! [`store`] keeps an acceptor's state on disk.
//!
//! The crate is generic over the node ID `N` and the value `V`, and knows
//! nothing about the network or the cluster state.
//! It assumes honest participants; Byzantine evidence checks belong to the
//! daemon's authenticated round layer (see CONSENSUS-SAFETY.md).

mod acceptor;
mod driver;
mod proposer;
pub mod store;

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub use acceptor::{Acceptor, InvalidRequest, MAX_COUNTER_STEP};
pub use driver::{Error, Options, Transport, propose};
pub use proposer::{Change, Proposer, Step};

/// A ballot: a counter and the proposer's node ID, so no two proposers use the
/// same ballot. Ordered by counter, then by node ID.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Ballot<N> {
    pub counter: u64,
    pub node: N,
}

/// A set of acceptors, with its configuration number.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(bound(deserialize = "N: Ord + Deserialize<'de>"))]
pub struct Config<N> {
    pub number: u64,
    /// Use quorums whose intersection exceeds one voter. Byzantine safety
    /// additionally requires the daemon's authenticated verification layer.
    pub protected: bool,
    pub acceptors: BTreeSet<N>,
}

impl<N> Config<N> {
    pub fn successor(&self, acceptors: BTreeSet<N>, protected: bool) -> Self {
        Self {
            number: self.number + 1,
            acceptors,
            protected,
        }
    }

    /// The number of votes required by this configuration's security mode.
    pub fn quorum(&self) -> usize {
        quorum(self.acceptors.len(), self.protected)
    }
}

/// Quorum intersection contains an honest voter in protected mode.
pub fn quorum(n: usize, protected: bool) -> usize {
    (n + usize::from(protected)) / 2 + 1
}

/// The value that acceptors store: the user's value, its version, and the
/// configuration it was agreed in.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(bound(deserialize = "N: Ord + Deserialize<'de>, V: Deserialize<'de>"))]
pub struct Agreed<N, V> {
    /// Goes up by one with each change, so each agreed value has its own
    /// version.
    pub version: u64,
    /// The configuration this value belongs to.
    pub config: Config<N>,
    /// Set when this value closes `config`: the acceptors of the next
    /// configuration. Nothing else can be agreed in `config` after it.
    pub next: Option<Config<N>>,
    pub value: V,
}

impl<N, V> Agreed<N, V> {
    /// The configuration used for new rounds: the successor once this value
    /// closes its own configuration, otherwise the one that agreed it.
    pub fn active_config(&self) -> &Config<N> {
        self.next.as_ref().unwrap_or(&self.config)
    }

    /// The acceptors used for new rounds.
    pub fn acceptors(&self) -> &BTreeSet<N> {
        &self.active_config().acceptors
    }
}

impl<N: Clone + Ord, V: Clone> Agreed<N, V> {
    /// The first value of a cluster, with `acceptor` as its only acceptor.
    pub fn genesis(acceptor: N, value: V) -> Self {
        Agreed {
            version: 0,
            config: Config {
                protected: false,
                number: 0,
                acceptors: BTreeSet::from([acceptor]),
            },
            next: None,
            value,
        }
    }

    /// The first value of the next configuration, if this value closes its
    /// own. Every proposer derives the same value from the same closing value.
    pub fn open(&self) -> Option<Self> {
        let next = self.next.as_ref()?;
        Some(Agreed {
            version: self.version + 1,
            config: next.clone(),
            next: None,
            value: self.value.clone(),
        })
    }
}

/// An agreed value, with the ballot it was accepted at in its configuration.
///
/// The ballot is `None` for the first value of a configuration that no
/// acceptor holds yet (see [`Agreed::open`]).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(bound(deserialize = "N: Ord + Deserialize<'de>, V: Deserialize<'de>"))]
pub struct Chosen<N, V> {
    pub value: Agreed<N, V>,
    pub ballot: Option<Ballot<N>>,
}

impl<N, V> Chosen<N, V> {
    /// The agreed value itself (`value.value`), without its version and
    /// configuration.
    pub fn state(&self) -> &V {
        &self.value.value
    }
}

impl<N: Clone + Ord, V: Clone> Chosen<N, V> {
    /// The first value of a cluster, accepted by its only acceptor at ballot
    /// zero. See [`Acceptor::genesis`].
    pub fn genesis(acceptor: N, value: V) -> Self {
        Chosen {
            ballot: Some(Ballot {
                counter: 0,
                node: acceptor.clone(),
            }),
            value: Agreed::genesis(acceptor, value),
        }
    }
}

/// A request from a proposer to an acceptor.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(bound(deserialize = "N: Ord + Deserialize<'de>, V: Deserialize<'de>"))]
pub enum Request<N, V> {
    /// Promise to accept nothing below `ballot` in configuration `config`.
    /// `have` is the ballot of the value the proposer already holds for this
    /// configuration; the acceptor leaves that value out of its answer.
    Prepare {
        config: u64,
        ballot: Ballot<N>,
        have: Option<Ballot<N>>,
    },
    /// Accept `value` at `ballot` in configuration `config`.
    Accept {
        config: u64,
        ballot: Ballot<N>,
        value: Agreed<N, V>,
    },
}

/// A value an acceptor has accepted, with its ballot. The value is `None` if
/// it's the one the proposer said it has.
pub type Accepted<N, V> = (Ballot<N>, Option<Agreed<N, V>>);

/// An acceptor's answer to a [`Request`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(bound(deserialize = "N: Ord + Deserialize<'de>, V: Deserialize<'de>"))]
pub enum Reply<N, V> {
    /// The promise, with the last value accepted in this configuration.
    Promise {
        config: u64,
        ballot: Ballot<N>,
        accepted: Option<Accepted<N, V>>,
    },
    Accepted {
        config: u64,
        ballot: Ballot<N>,
    },
    /// Refused, because the acceptor has promised at least `promised`.
    /// This lower bound is limited to [`MAX_COUNTER_STEP`] above the request,
    /// allowing large gaps to be recovered over several bounded rounds.
    Rejected {
        config: u64,
        ballot: Ballot<N>,
        promised: Ballot<N>,
    },
    /// The configuration is closed. `learned` is an agreed value from a later
    /// one.
    Stale {
        learned: Chosen<N, V>,
    },
    /// Refused, because the ballot's counter is above `limit`, the highest
    /// counter the acceptor takes now (see [`MAX_COUNTER_STEP`]).
    TooHigh {
        config: u64,
        ballot: Ballot<N>,
        limit: u64,
    },
}
