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
