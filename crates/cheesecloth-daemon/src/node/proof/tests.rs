use std::collections::BTreeSet;

use super::*;
use cheesecloth_core::state::ClusterState;

const CLUSTER: ClusterId = ClusterId([7; 32]);

fn ids(n: usize) -> Vec<Identity> {
    (0..n).map(|_| Identity::generate()).collect()
}

fn set(ids: &[&Identity]) -> BTreeSet<NodeId> {
    ids.iter().map(|i| i.node_id()).collect()
}

/// A value in configuration `number` with acceptors `acceptors`.
fn value(version: u64, number: u64, acceptors: BTreeSet<NodeId>, now_ms: u64) -> Agreed {
    Agreed {
        version,
        config: Config {
            protected: false,
            number,
            acceptors,
        },
        next: None,
        value: ClusterState {
            now_ms,
            ..Default::default()
        },
    }
}

fn ballot(of: &Identity) -> Ballot<NodeId> {
    Ballot {
        counter: 1,
        node: of.node_id(),
    }
}

/// `value` at `ballot`, signed by `signers`.
fn certify(value: &Agreed, ballot: &Ballot<NodeId>, signers: &[&Identity]) -> Certificate {
    let header = Header::of(CLUSTER, value);
    let mut cert = Certificate::sign(signers[0], header.clone(), ballot.clone());
    for s in &signers[1..] {
        cert.sigs
            .extend(Certificate::sign(s, header.clone(), ballot.clone()).sigs);
    }
    cert
}

#[test]
fn a_majority_of_the_acceptors_must_sign() {
    let k = ids(4);
    let acceptors = set(&[&k[0], &k[1], &k[2]]);
    let v = value(5, 0, acceptors.clone(), 1000);
    let b = ballot(&k[0]);
    assert!(
        certify(&v, &b, &[&k[0], &k[1]])
            .check_config(&v.config, false)
            .is_ok()
    );
    // One acceptor, and one that isn't an acceptor.
    let e = certify(&v, &b, &[&k[0], &k[3]])
        .check_config(&v.config, false)
        .unwrap_err();
    assert!(
        e.to_string()
            .contains("1 valid acceptor signatures, 2 needed"),
        "{e}"
    );
    // A signature on another value doesn't count.
    let mut forged = certify(&v, &b, &[&k[0], &k[1]]);
    forged.header.version += 1;
    assert!(forged.check_config(&v.config, false).is_err());
    // The value must name the trusted set.
    let other = Config {
        acceptors: set(&[&k[0], &k[1], &k[3]]),
        ..v.config.clone()
    };
    assert!(
        certify(&v, &b, &[&k[0], &k[1]])
            .check_config(&other, false)
            .is_err()
    );
}

#[test]
fn a_certificate_proves_its_value_or_the_value_opened_from_it() {
    let k = ids(2);
    let v = value(5, 0, set(&[&k[0]]), 1000);
    let b = ballot(&k[0]);
    let cert = certify(&v, &b, &[&k[0]]);
    let chosen = Chosen {
        value: v.clone(),
        ballot: Some(b.clone()),
    };
    assert!(cert.proves(&chosen));
    let other_ballot = Chosen {
        ballot: Some(ballot(&k[1])),
        ..chosen.clone()
    };
    assert!(!cert.proves(&other_ballot));
    assert!(!cert.is_transition());

    let mut closing = v.clone();
    closing.next = Some(closing.config.successor(set(&[&k[1]]), false));
    let transition = certify(&closing, &b, &[&k[0]]);
    assert!(transition.is_transition());
    let opened = Chosen {
        value: closing.open().unwrap(),
        ballot: None,
    };
    assert!(transition.proves(&opened));
    // Only a closing value proves an opened one.
    let mut not_opened = opened.clone();
    not_opened.value.value.now_ms += 1;
    assert!(!transition.proves(&not_opened));
}

#[test]
fn transitions_lead_to_later_acceptor_sets() {
    let k = ids(3);
    let b = ballot(&k[0]);
    // Configuration 0: k0. It closes, naming k1; configuration 1 closes,
    // naming k2.
    let mine = value(5, 0, set(&[&k[0]]), 1000);
    let mut close0 = value(6, 0, set(&[&k[0]]), 1000);
    close0.next = Some(close0.config.successor(set(&[&k[1]]), false));
    let mut close1 = value(8, 1, set(&[&k[1]]), 2000);
    close1.next = Some(close1.config.successor(set(&[&k[2]]), false));
    let t0 = certify(&close0, &b, &[&k[0]]);
    let t1 = certify(&close1, &b, &[&k[1]]);
    let later = certify(&value(9, 2, set(&[&k[2]]), 3000), &b, &[&k[2]]);

    let mut trusted = Trusted::new(&mine);
    assert!(trusted.check(&later).is_err(), "configuration 2 is unknown");
    // A transition signed by the wrong acceptor is refused.
    assert!(trusted.follow(&certify(&close0, &b, &[&k[1]])).is_err());
    trusted.follow(&t0).unwrap();
    trusted.follow(&t1).unwrap();
    assert_eq!(trusted.frontier(), 2);
    trusted.check(&later).unwrap();

    // Stored transitions extend a node's trust the same way.
    let mut stored = Transitions::default();
    assert!(stored.insert(t0.clone()));
    assert!(!stored.insert(t0));
    stored.insert(t1);
    let mut trusted = Trusted::new(&mine);
    stored.extend(&mut trusted);
    assert_eq!(trusted.frontier(), 2);
    assert_eq!(stored.since(1).len(), 1);
}

#[test]
fn old_transitions_are_dropped() {
    let k = ids(1);
    let b = ballot(&k[0]);
    let day = 24 * 60 * 60 * 1000;
    let mut stored = Transitions::default();
    for (number, at) in [(0, 0), (1, 10 * day), (2, 20 * day)] {
        let mut closing = value(number + 1, number, set(&[&k[0]]), at);
        closing.next = Some(closing.config.successor(set(&[&k[0]]), false));
        stored.insert(certify(&closing, &b, &[&k[0]]));
    }
    assert!(!stored.prune(20 * day, 30));
    assert!(stored.prune(35 * day, 30));
    assert_eq!(stored.since(0).len(), 2);
    assert_eq!(stored.since(0)[0].header.config.number, 1);
}
