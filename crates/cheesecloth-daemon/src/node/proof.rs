//! Verification and acceptance certificates, plus configuration transitions
//! (see *Authenticated round* in CONSENSUS-SAFETY.md).
//!
//! A verification quorum permits acceptance; an acceptance quorum proves the
//! value was chosen. A node checks a certificate against an acceptor set
//! it trusts: its own latest state's, or one that a chain of transitions (the
//! certificates of closing values) leads to from there.

use std::{collections::BTreeMap, io, path::Path};

use anyhow::{Result, bail};
use cheesecloth_core::{ClusterId, Domain, Identity, NodeId, Signature, verify};
use cheesecloth_paxos::{Ballot, Config, store};
use serde::{Deserialize, Serialize};

use super::{Agreed, Chosen};

/// The most bytes of transitions sent with a state. A message may be 1 MiB,
/// and a state 320 KiB.
const MAX_TRANSITION_BYTES: usize = 256 << 10;

/// The complete value context that voters sign, with a hash of the state body.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Header {
    pub cluster_id: ClusterId,
    pub version: u64,
    pub config: Config<NodeId>,
    /// The next acceptors, if the value closes its configuration.
    pub next: Option<Config<NodeId>>,
    /// The state's time, so that old transitions can be dropped.
    pub now_ms: u64,
    /// The hash of the state (see `ClusterState::hash`).
    pub state: [u8; 32],
}

impl Header {
    pub fn of(cluster_id: ClusterId, value: &Agreed) -> Header {
        Header {
            cluster_id,
            version: value.version,
            config: value.config.clone(),
            next: value.next.clone(),
            now_ms: value.value.now_ms,
            state: value.value.hash(),
        }
    }
    /// Header of the opening derived from this closing value, without
    /// cloning or hashing the state body.
    pub fn opened(&self) -> Option<Self> {
        Some(Self {
            version: self.version.checked_add(1)?,
            config: self.next.clone()?,
            next: None,
            ..self.clone()
        })
    }
}

/// Votes on a value's header at a ballot. A verification quorum authorizes
/// acceptance; an acceptance quorum proves agreement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    pub verified: bool,
    pub header: Header,
    pub ballot: Ballot<NodeId>,
    pub sigs: BTreeMap<NodeId, Signature>,
}

impl Certificate {
    fn message(header: &Header, ballot: &Ballot<NodeId>) -> Vec<u8> {
        postcard::to_stdvec(&(header, ballot)).expect("serializable")
    }

    /// One acceptor's statement that it accepted the value with `header` at
    /// `ballot`.
    pub fn sign(identity: &Identity, header: Header, ballot: Ballot<NodeId>) -> Certificate {
        Self::sign_phase(identity, header, ballot, false)
    }

    pub fn sign_verified(identity: &Identity, header: Header, ballot: Ballot<NodeId>) -> Self {
        Self::sign_phase(identity, header, ballot, true)
    }

    fn domain(verified: bool) -> Domain {
        if verified {
            Domain::Verification
        } else {
            Domain::Accept
        }
    }

    fn sign_phase(
        identity: &Identity,
        header: Header,
        ballot: Ballot<NodeId>,
        verified: bool,
    ) -> Self {
        let sig = identity.sign(Self::domain(verified), &Self::message(&header, &ballot));
        Self {
            verified,
            header,
            ballot,
            sigs: BTreeMap::from([(identity.node_id(), sig)]),
        }
    }

    pub fn check_signer(&self, signer: &NodeId) -> Result<()> {
        let sig = self
            .sigs
            .get(signer)
            .ok_or_else(|| anyhow::anyhow!("missing signature"))?;
        verify(
            signer,
            Self::domain(self.verified),
            &Self::message(&self.header, &self.ballot),
            sig,
        )?;
        Ok(())
    }

    /// Checks the phase, complete trusted configuration and quorum signatures.
    /// Signatures from outside the configuration do not count.
    pub fn check_config(&self, config: &Config<NodeId>, verified: bool) -> Result<()> {
        if config.acceptors.is_empty()
            || config.acceptors.len() > 7
            || config.protected && config.acceptors.len() < 4
        {
            bail!("invalid voter configuration");
        }
        if self.verified != verified || self.header.config != *config {
            bail!("certificate phase or configuration mismatch");
        }
        let message = Self::message(&self.header, &self.ballot);
        let valid = self
            .sigs
            .iter()
            .filter(|(a, sig)| {
                config.acceptors.contains(a)
                    && verify(a, Self::domain(self.verified), &message, sig).is_ok()
            })
            .count();
        let need = config.quorum();
        if valid < need {
            bail!(
                "{valid} valid acceptor signatures, {need} needed (configuration {})",
                self.header.config.number
            );
        }
        Ok(())
    }

    /// Whether this is about `chosen`: the same value at its ballot. The
    /// first value of a configuration has no ballot; this must then be about
    /// the closing value it's opened from.
    pub fn proves(&self, chosen: &Chosen) -> bool {
        self.proves_header(
            &Header::of(self.header.cluster_id, &chosen.value),
            chosen.ballot.as_ref(),
        )
    }

    pub fn proves_header(&self, header: &Header, ballot: Option<&Ballot<NodeId>>) -> bool {
        match ballot {
            Some(ballot) => self.header == *header && self.ballot == *ballot,
            None => self.header.opened().as_ref() == Some(header),
        }
    }

    /// A transition: the certificate of a value that closes its
    /// configuration.
    pub fn is_transition(&self) -> bool {
        self.header.next.is_some()
    }

    fn size(&self) -> usize {
        postcard::to_stdvec(self).map_or(usize::MAX, |b| b.len())
    }
}

/// The proof of a cluster's first state: its founder, the only acceptor,
/// signs it.
pub fn genesis(identity: &Identity, cluster_id: ClusterId, first: &Chosen) -> Certificate {
    let ballot = first.ballot.clone().expect("the first state has a ballot");
    Certificate::sign(identity, Header::of(cluster_id, &first.value), ballot)
}

/// An agreed state with its proof, and transitions the receiver may need to
/// check the proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proven {
    pub chosen: Chosen,
    pub cert: Certificate,
    pub transitions: Vec<Certificate>,
}

/// The acceptor sets a node trusts, by configuration number: its latest
/// state's, and the ones that checked transitions lead to from there.
#[derive(Clone, Debug)]
pub struct Trusted(BTreeMap<u64, Config<NodeId>>);

impl Trusted {
    /// The sets that `latest`, a state this node has checked, names.
    pub fn new(latest: &Agreed) -> Trusted {
        let mut sets = BTreeMap::from([(latest.config.number, latest.config.clone())]);
        if let Some(next) = &latest.next {
            sets.insert(next.number, next.clone());
        }
        Trusted(sets)
    }

    /// The latest configuration whose acceptors are trusted.
    pub fn frontier(&self) -> u64 {
        *self.0.keys().next_back().expect("never empty")
    }

    /// Checks `cert` against the trusted set of its configuration.
    pub fn check(&self, cert: &Certificate) -> Result<()> {
        let number = cert.header.config.number;
        let Some(set) = self.0.get(&number) else {
            bail!(
                "this node can't check configuration {number} yet: it knows the acceptors \
                 up to configuration {}",
                self.frontier()
            );
        };
        cert.check_config(set, false)
    }

    /// Checks `transition`, a closing value's certificate for the frontier,
    /// and then trusts the set it names.
    pub fn follow(&mut self, transition: &Certificate) -> Result<()> {
        let Some(next) = &transition.header.next else {
            bail!("not a transition");
        };
        self.check(transition)?;
        if next.number != transition.header.config.number + 1
            || next.acceptors.is_empty()
            || next.acceptors.len() > 7
            || next.protected && next.acceptors.len() < 4
        {
            bail!("invalid successor configuration");
        }
        self.0
            .insert(transition.header.config.number + 1, next.clone());
        Ok(())
    }
}

/// The transitions a node has checked, by the configuration they close. They
/// are kept to help nodes that are behind, for the `catch_up_days` setting.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transitions(BTreeMap<u64, Certificate>);

impl Transitions {
    /// The transitions saved in `path`, or none if there is no file.
    pub fn load(path: &Path) -> io::Result<Transitions> {
        Ok(store::load(path)?.unwrap_or_default())
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        store::save(path, self)
    }

    /// Adds a checked transition. Returns true if it's new.
    pub fn insert(&mut self, transition: Certificate) -> bool {
        debug_assert!(transition.is_transition());
        let number = transition.header.config.number;
        if self.0.contains_key(&number) {
            return false;
        }
        self.0.insert(number, transition);
        true
    }

    /// Follows the stored transitions from `trusted`'s frontier on.
    pub fn extend(&self, trusted: &mut Trusted) {
        for t in self.0.range(trusted.frontier()..).map(|(_, t)| t) {
            if t.header.config.number != trusted.frontier() || trusted.follow(t).is_err() {
                break;
            }
        }
    }

    /// The transitions from configuration `from` on, in order, up to the
    /// size a message may carry.
    pub fn since(&self, from: u64) -> Vec<Certificate> {
        let mut size = 0;
        self.0
            .range(from..)
            .map(|(_, t)| t)
            .take_while(|t| {
                size += t.size();
                size <= MAX_TRANSITION_BYTES
            })
            .cloned()
            .collect()
    }

    /// Drops the transitions agreed more than `days` days before `now_ms`.
    /// Returns true if any were dropped.
    pub fn prune(&mut self, now_ms: u64, days: u32) -> bool {
        let keep_from = now_ms.saturating_sub(u64::from(days) * 24 * 60 * 60 * 1000);
        let before = self.0.len();
        self.0.retain(|_, t| t.header.now_ms >= keep_from);
        self.0.len() != before
    }
}

#[cfg(test)]
mod tests {
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
}
