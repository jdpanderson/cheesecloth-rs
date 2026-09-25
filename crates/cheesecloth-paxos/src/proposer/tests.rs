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
