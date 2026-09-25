//! Tests of `propose` over an in-memory network that loses, delays and
//! reorders messages.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use cheesecloth_paxos::{
    Acceptor, Ballot, Change, Chosen, Error, MAX_COUNTER_STEP, Options, Proposer, Reply, Request,
    Transport, propose,
};
use rand::RngExt;

type Value = BTreeSet<u32>;

/// Acceptors in memory. Requests and replies may be lost or delayed.
#[derive(Clone, Default)]
struct Net {
    acceptors: Arc<Mutex<BTreeMap<u8, Acceptor<u8, Value>>>>,
    down: Arc<Mutex<BTreeSet<u8>>>,
    /// What the proposer's node has learned in another way.
    learned: Arc<Mutex<Option<Chosen<u8, Value>>>>,
    /// Chance that a request or a reply is lost, in percent.
    loss: u32,
    max_delay_ms: u64,
}

impl Net {
    fn new(acceptors: &[u8], first: &Chosen<u8, Value>, loss: u32, max_delay_ms: u64) -> Self {
        let mut map = BTreeMap::new();
        for a in acceptors {
            let acceptor = if first.value.config.acceptors.contains(a) {
                Acceptor::genesis(first.clone(), ())
            } else {
                Acceptor::default()
            };
            map.insert(*a, acceptor);
        }
        Net {
            acceptors: Arc::new(Mutex::new(map)),
            loss,
            max_delay_ms,
            ..Default::default()
        }
    }

    async fn delay_or_lose(&self) -> Result<(), &'static str> {
        let (lost, delay) = {
            let mut rng = rand::rng();
            let delay = rng.random_range(0..=self.max_delay_ms);
            (rng.random_range(0..100) < self.loss, delay)
        };
        tokio::time::sleep(Duration::from_millis(delay)).await;
        if lost { Err("lost") } else { Ok(()) }
    }

    fn learn(&self, chosen: &Chosen<u8, Value>) {
        for a in self.acceptors.lock().unwrap().values_mut() {
            a.learn(chosen.clone(), ());
        }
    }
}

impl Transport<u8, Value> for Net {
    type Error = &'static str;

    async fn call(
        &self,
        to: &u8,
        req: Request<u8, Value>,
    ) -> Result<Reply<u8, Value>, &'static str> {
        self.delay_or_lose().await?;
        if self.down.lock().unwrap().contains(to) {
            return Err("down");
        }
        let reply = {
            let mut acceptors = self.acceptors.lock().unwrap();
            let a = acceptors.get_mut(to).ok_or("no such acceptor")?;
            a.handle(req).map_err(|_| "invalid request")?.0
        };
        self.delay_or_lose().await?;
        Ok(reply)
    }

    fn learned(&self) -> Option<Chosen<u8, Value>> {
        self.learned.lock().unwrap().clone()
    }
}

fn options() -> Options {
    Options {
        request_timeout: Duration::from_millis(100),
        deadline: Duration::from_secs(20),
        max_retry_wait: Duration::from_millis(20),
    }
}

/// Adds `x`. Adding twice has no effect, since a retried round may apply the
/// change to a value that already has it.
fn add(x: u32) -> impl FnMut(&cheesecloth_paxos::Agreed<u8, Value>) -> (Change<u8, Value>, ()) {
    move |v| {
        let mut set = v.value.clone();
        set.insert(x);
        (Change::Set(set), ())
    }
}

fn keep(_: &cheesecloth_paxos::Agreed<u8, Value>) -> (Change<u8, Value>, ()) {
    (Change::Keep, ())
}

fn genesis() -> Chosen<u8, Value> {
    let mut first = Chosen::genesis(1, Value::new());
    first.value.config.acceptors = [1, 2, 3].into();
    first
}

/// Runs `per` additions from each of `proposers` proposers at the same time.
async fn add_concurrently(net: &Net, first: &Chosen<u8, Value>, proposers: u8, per: u32) {
    let mut tasks = vec![];
    for id in 0..proposers {
        let net = net.clone();
        let first = first.clone();
        tasks.push(tokio::spawn(async move {
            let mut p = Proposer::new(100 + id, first);
            for i in 0..per {
                let x = u32::from(id) * 1000 + i;
                let (chosen, ()) = propose(&mut p, &net, &options(), add(x)).await.unwrap();
                assert!(chosen.value.value.contains(&x));
                net.learn(&chosen);
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}

async fn read(net: &Net, first: &Chosen<u8, Value>) -> Chosen<u8, Value> {
    let mut p = Proposer::new(99, first.clone());
    propose(&mut p, net, &options(), keep).await.unwrap().0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_proposers_over_a_lossy_network() {
    let first = genesis();
    let net = Net::new(&[1, 2, 3], &first, 10, 10);
    add_concurrently(&net, &first, 5, 10).await;

    let all = read(&net, &first).await;
    let expected: Value = (0..5)
        .flat_map(|p| (0..10).map(move |i| p * 1000 + i))
        .collect();
    assert_eq!(all.value.value, expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_acceptor_down() {
    let first = genesis();
    let net = Net::new(&[1, 2, 3], &first, 0, 2);
    net.down.lock().unwrap().insert(2);
    add_concurrently(&net, &first, 2, 5).await;
    assert_eq!(read(&net, &first).await.value.value.len(), 10);
}

#[tokio::test]
async fn no_majority_times_out() {
    let first = genesis();
    let net = Net::new(&[1, 2, 3], &first, 0, 0);
    net.down.lock().unwrap().extend([2, 3]);
    let mut p = Proposer::new(100, first);
    let options = Options {
        deadline: Duration::from_millis(500),
        ..options()
    };
    let err = propose(&mut p, &net, &options, add(1)).await.unwrap_err();
    let Error::Timeout(last) = &err else {
        panic!("{err}")
    };
    assert_eq!(last.as_deref(), Some("down"));
    assert!(err.to_string().contains("no majority"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn change_acceptors_while_others_propose() {
    let first = genesis();
    let net = Net::new(&[1, 2, 3, 4, 5], &first, 5, 5);

    let adding = {
        let (net, first) = (net.clone(), first.clone());
        tokio::spawn(async move { add_concurrently(&net, &first, 3, 10).await })
    };
    // Move to {3, 4, 5}, then take 1 and 2 away.
    let mut p = Proposer::new(50, first.clone());
    // A retried round may find the change already made, so it closes only
    // if the acceptors are not yet the new ones.
    let target = BTreeSet::from([3, 4, 5]);
    let close = |v: &cheesecloth_paxos::Agreed<u8, Value>| {
        if v.acceptors() == &target {
            (Change::Keep, ())
        } else {
            (
                Change::Close(v.value.clone(), v.config.successor(target.clone(), false)),
                (),
            )
        }
    };
    let (closed, ()) = propose(&mut p, &net, &options(), close).await.unwrap();
    assert_eq!(closed.value.acceptors(), &BTreeSet::from([3, 4, 5]));
    adding.await.unwrap();
    net.down.lock().unwrap().extend([1, 2]);

    // Acceptor 3 learns a value from configuration 1.
    net.learn(&read(&net, &closed).await);

    // A proposer that only knows the first value reaches only acceptor 3 of
    // configuration 0, which sends it on to configuration 1.
    let mut stale = Proposer::new(60, first.clone());
    let (seen, ()) = propose(&mut stale, &net, &options(), keep).await.unwrap();
    assert_eq!(seen.value.config.number, 1);
    assert_eq!(seen.value.value.len(), 30);
}

#[tokio::test]
async fn a_change_moves_on_to_a_value_learned_elsewhere() {
    // Acceptor 1 hands its role to acceptor 2, then stops and loses its
    // state, so nothing answers in configuration 0.
    let first = Chosen::genesis(1, Value::new());
    let net = Net::new(&[1, 2], &first, 0, 0);
    let mut p = Proposer::new(50, first.clone());
    let close = |v: &cheesecloth_paxos::Agreed<u8, Value>| {
        (
            Change::Close(
                v.value.clone(),
                v.config.successor(BTreeSet::from([2]), false),
            ),
            (),
        )
    };
    let (closed, ()) = propose(&mut p, &net, &options(), close).await.unwrap();
    net.down.lock().unwrap().insert(1);

    // A change that begins with the first value retries in configuration 0
    // until its node learns the closing value in another way.
    let mut late = Proposer::new(60, first);
    let options = Options {
        deadline: Duration::from_secs(2),
        ..options()
    };
    let learn = {
        let (net, closed) = (net.clone(), closed.clone());
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            *net.learned.lock().unwrap() = Some(closed);
        })
    };
    let (chosen, ()) = propose(&mut late, &net, &options, add(7)).await.unwrap();
    learn.await.unwrap();
    assert_eq!(chosen.value.config.number, 1);
    assert!(chosen.value.value.contains(&7));
}

#[tokio::test]
async fn a_proposer_far_ahead_of_new_acceptors_goes_back() {
    let first = genesis();
    let net = Net::new(&[1, 2, 3, 4, 5, 6], &first, 0, 0);
    // Another proposer's rounds move the promises of the first acceptors
    // far up, one step at a time.
    for a in [1, 2, 3] {
        for counter in 1..=3 {
            let prepare = Request::Prepare {
                config: 0,
                ballot: Ballot {
                    counter: counter * MAX_COUNTER_STEP,
                    node: 99,
                },
                have: None,
            };
            let mut acceptors = net.acceptors.lock().unwrap();
            acceptors.get_mut(&a).unwrap().handle(prepare).unwrap();
        }
    }
    let mut p = Proposer::new(100, first);
    // The first change follows those promises. It closes the configuration,
    // so it continues with the new acceptors, which have promised nothing:
    // the proposer's counter is too high for them.
    let close = |v: &cheesecloth_paxos::Agreed<u8, Value>| {
        (
            Change::Close(v.value.clone(), v.config.successor([4, 5, 6].into(), false)),
            (),
        )
    };
    propose(&mut p, &net, &options(), close).await.unwrap();
    let (chosen, ()) = propose(&mut p, &net, &options(), add(1)).await.unwrap();
    assert_eq!(chosen.value.config.number, 1);
    assert_eq!(chosen.value.value, BTreeSet::from([1]));
    assert!(chosen.ballot.unwrap().counter <= MAX_COUNTER_STEP);
}

/// Acceptors that have all promised the highest ballot.
struct AllUsedUp;

impl Transport<u8, Value> for AllUsedUp {
    type Error = &'static str;

    async fn call(&self, _: &u8, req: Request<u8, Value>) -> Result<Reply<u8, Value>, Self::Error> {
        let (Request::Prepare { config, ballot, .. } | Request::Accept { config, ballot, .. }) =
            req;
        Ok(Reply::Rejected {
            config,
            ballot,
            promised: Ballot {
                counter: u64::MAX,
                node: 1,
            },
        })
    }
}

#[tokio::test]
async fn a_change_ends_when_no_ballots_are_left() {
    let mut known = genesis();
    known.ballot = Some(Ballot {
        counter: u64::MAX,
        node: 1,
    });
    let mut p = Proposer::new(100, known);
    let err = propose(&mut p, &AllUsedUp, &options(), add(1))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::OutOfBallots), "{err}");
}

#[tokio::test]
async fn implausible_rejections_do_not_poison_later_changes() {
    let first = genesis();
    let mut p = Proposer::new(100, first.clone());
    let short = Options {
        deadline: Duration::from_millis(100),
        ..options()
    };
    let error = propose(&mut p, &AllUsedUp, &short, add(1))
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Timeout(_)));
    let net = Net::new(&[1, 2, 3], &first, 0, 0);
    let (chosen, ()) = propose(&mut p, &net, &options(), add(1)).await.unwrap();
    assert_eq!(chosen.value.value, BTreeSet::from([1]));
}
