//! Authenticated CASPaxos rounds. A prepare quorum justifies a candidate;
//! a durable verification quorum prevents proposer equivocation at a ballot.
use super::{
    Agreed, Chosen, Node,
    proof::{Certificate, Header, Proven, Trusted},
};
use crate::proto::{PaxosAnswer, SVC_PAXOS, SVC_VERIFY};
use anyhow::{Result, bail, ensure};
use cheesecloth_core::state::ClusterState;
use cheesecloth_core::{ClusterId, Domain, NodeId, Signed};
use cheesecloth_paxos::{Ballot, Config, Reply, Request, Transport};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Promise {
    pub cluster: ClusterId,
    pub config: u64,
    pub ballot: Ballot<NodeId>,
    pub accepted: Option<Certificate>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireRequest {
    pub request: Request<NodeId, ClusterState>,
    pub proof: Option<Certificate>,
    pub base: Option<Proven>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Verification {
    pub ballot: Ballot<NodeId>,
    pub value: Agreed,
    pub promises: Vec<Signed<Promise>>,
    pub base: Option<Proven>,
}

/// Check every assertion before selecting the highest accepted ballot. A lone
/// faulty acceptor cannot invent an accepted value or a higher accepted ballot.
pub(super) fn promises(
    cluster: ClusterId,
    config: &Config<NodeId>,
    ballot: &Ballot<NodeId>,
    evidence: &[Signed<Promise>],
) -> Result<Option<Certificate>> {
    ensure!(
        evidence.len() <= config.acceptors.len(),
        "too many promises"
    );
    let mut seen = BTreeSet::new();
    let mut highest: Option<Certificate> = None;
    for signed in evidence {
        ensure!(
            config.acceptors.contains(&signed.signer) && seen.insert(signed.signer),
            "duplicate or foreign promise"
        );
        let p = signed.open(Domain::Promise)?;
        ensure!(
            p.cluster == cluster && p.config == config.number && p.ballot == *ballot,
            "promise is for another round"
        );
        if let Some(c) = p.accepted {
            ensure!(
                c.header.cluster_id == cluster && c.ballot <= *ballot,
                "invalid accepted ballot or cluster"
            );
            c.check_config(config, c.verified)?;
            if let Some(h) = &highest {
                ensure!(
                    h.ballot != c.ballot || h.header == c.header,
                    "conflicting values at one ballot"
                );
            }
            if highest.as_ref().is_none_or(|h| h.ballot < c.ballot) {
                highest = Some(c);
            }
        }
    }
    ensure!(seen.len() >= config.quorum(), "insufficient prepare quorum");
    Ok(highest)
}

impl Node {
    pub(super) async fn handle_wire(
        &self,
        from: NodeId,
        wire: WireRequest,
    ) -> Result<PaxosAnswer, String> {
        if let Some(base) = wire.base {
            self.learn(base.chosen, base.cert, base.transitions)
                .await
                .map_err(|e| e.to_string())?;
        }
        self.handle_paxos_proven(from, wire.request, wire.proof)
            .await
            .map_err(|e| e.to_string())
    }

    pub(super) async fn verify_round(
        &self,
        from: NodeId,
        v: Verification,
    ) -> Result<Certificate, String> {
        self.verify_round_inner(from, v)
            .await
            .map_err(|e| format!("{e:#}"))
    }

    async fn verify_round_inner(&self, from: NodeId, v: Verification) -> Result<Certificate> {
        ensure!(
            v.ballot.node == from,
            "verification uses another member's ballot"
        );
        if let Some(base) = &v.base {
            {
                let _learning = self.learning.lock().await;
                let current = self.agreed();
                let current_cert = self.cert.lock().clone();
                let mut trusted = Trusted::new(&current.value);
                self.transitions.lock().extend(&mut trusted);
                for t in &base.transitions {
                    ensure!(t.header.cluster_id == self.cluster_id, "foreign transition");
                    if t.header.config.number == trusted.frontier() {
                        trusted.follow(t)?;
                    }
                }
                if base.cert.header.config == current_cert.header.config {
                    base.cert.check_config(&current_cert.header.config, false)?;
                } else {
                    trusted.check(&base.cert)?;
                }
                ensure!(base.cert.proves(&base.chosen), "predecessor proof mismatch");
            }
            self.learn(
                base.chosen.clone(),
                base.cert.clone(),
                base.transitions.clone(),
            )
            .await?;
        }
        let mut a = self.acceptor.clone().lock_owned().await;
        let learned = a
            .acceptor()
            .learned()
            .ok_or_else(|| anyhow::anyhow!("no trusted state"))?;
        let config = if v.value.config.number == learned.value.config.number {
            &learned.value.config
        } else {
            learned.value.active_config()
        };
        ensure!(
            v.value.config == *config && config.acceptors.contains(&self.me),
            "untrusted verification configuration"
        );
        ensure!(
            v.value.value.cluster_id == Some(self.cluster_id),
            "foreign state"
        );
        let highest = promises(self.cluster_id, config, &v.ballot, &v.promises)?;
        let header = Header::of(self.cluster_id, &v.value);
        let write_back = highest.as_ref().is_some_and(|c| c.header == header);
        if !write_back {
            let base = v
                .base
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("a new value requires a certified predecessor"))?;
            let b = &base.chosen.value;
            if let Some(h) = highest {
                ensure!(
                    h.header == Header::of(self.cluster_id, b),
                    "candidate ignores highest accepted value"
                );
            } else {
                // An empty new configuration may only start from its certified
                // opening. In configuration zero, genesis is already accepted.
                ensure!(
                    base.chosen.ballot.is_none() && base.cert.header.next.as_ref() == Some(config),
                    "empty round without certified opening"
                );
            }
            ensure!(
                b.config == v.value.config
                    && b.next.is_none()
                    && b.version.checked_add(1) == Some(v.value.version),
                "invalid successor"
            );
            b.value.check_step(
                &v.value.value,
                cheesecloth_core::now_ms() + crate::clock::MAX_SKEW.as_millis() as u64,
            )?;
            super::acceptors::check_policy(b, &v.value.value).map_err(anyhow::Error::msg)?;
            super::consensus::check_size(
                &b.value,
                &v.value.value,
                super::consensus::MAX_STATE_BYTES,
            )?;
            if let Some(next) = &v.value.next {
                super::acceptors::check_set(next, b, &v.value.value).map_err(anyhow::Error::msg)?;
                self.check_reconfiguration(b, &v.value)?;
            }
        }
        let identity = self.identity.clone();
        self.lifetime
            .blocking(move || {
                a.endorse(v.ballot.clone(), v.value)?;
                Ok(Certificate::sign_verified(&identity, header, v.ballot))
            })
            .await?
    }
}

struct Evidence {
    cert: Certificate,
    complete: bool,
}

#[derive(Default)]
struct Collected {
    shares: BTreeMap<(Header, Ballot<NodeId>, bool), Evidence>,
    values: BTreeMap<Header, Agreed>,
    promises: BTreeMap<(u64, Ballot<NodeId>), BTreeMap<NodeId, Signed<Promise>>>,
}

pub(super) struct Acceptors<'a> {
    node: &'a Node,
    collected: parking_lot::Mutex<Collected>,
    verified: tokio::sync::Mutex<BTreeMap<(u64, Ballot<NodeId>), Certificate>>,
}

impl<'a> Acceptors<'a> {
    pub fn new(node: &'a Node) -> Self {
        let this = Self {
            node,
            collected: parking_lot::Mutex::default(),
            verified: tokio::sync::Mutex::default(),
        };
        let value = &node.agreed().value;
        this.add_value(Header::of(node.cluster_id, value), value);
        this.add_share(node.cert.lock().clone());
        this
    }

    fn add_value(&self, header: Header, value: &Agreed) {
        self.collected
            .lock()
            .values
            .entry(header)
            .or_insert_with(|| value.clone());
    }

    /// Cache quorum checks per complete context. Any changed signature
    /// invalidates the cached result, including replacement of an existing vote.
    fn add_share(&self, share: Certificate) {
        let mut c = self.collected.lock();
        let key = (share.header.clone(), share.ballot.clone(), share.verified);
        match c.shares.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                let complete = share.check_config(&share.header.config, false).is_ok();
                entry.insert(Evidence {
                    cert: share,
                    complete,
                });
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let e = entry.get_mut();
                let changed = share
                    .sigs
                    .iter()
                    .any(|(signer, sig)| e.cert.sigs.get(signer) != Some(sig));
                if changed {
                    e.cert.sigs.extend(share.sigs);
                    e.complete = e.cert.check_config(&e.cert.header.config, false).is_ok();
                }
            }
        }
    }

    pub fn certify(&self, chosen: &Chosen) -> Option<Certificate> {
        let header = Header::of(self.node.cluster_id, &chosen.value);
        self.collected
            .lock()
            .shares
            .values()
            .find(|e| e.complete && e.cert.proves_header(&header, chosen.ballot.as_ref()))
            .map(|e| e.cert.clone())
            .or_else(|| {
                let c = self.node.cert.lock().clone();
                c.proves_header(&header, chosen.ballot.as_ref())
                    .then_some(c)
            })
    }

    pub fn transitions(&self) -> Vec<Certificate> {
        self.collected
            .lock()
            .shares
            .values()
            .filter(|e| e.complete && e.cert.is_transition())
            .map(|e| e.cert.clone())
            .collect()
    }

    fn base(&self, config: u64, header: Option<&Header>) -> Option<Proven> {
        let c = self.collected.lock();
        // Index lookup replaces the value/certificate cross product. Choose
        // the winner using compact headers, then clone its state exactly once.
        let mut best = None;
        for e in c.shares.values().filter(|e| e.complete) {
            for (candidate, opened) in std::iter::once((e.cert.header.clone(), false))
                .chain(e.cert.header.opened().map(|h| (h, true)))
            {
                if candidate.config.number != config || header.is_some_and(|h| *h != candidate) {
                    continue;
                }
                let value = c.values.get(&candidate).map(|v| (v, false)).or_else(|| {
                    opened
                        .then(|| c.values.get(&e.cert.header))
                        .flatten()
                        .map(|v| (v, true))
                });
                if let Some((value, needs_open)) = value
                    && best
                        .as_ref()
                        .is_none_or(|(version, _, _, _, _)| *version < candidate.version)
                {
                    best = Some((candidate.version, value, needs_open, opened, &e.cert));
                }
            }
        }
        let (_, value, needs_open, opened, cert) = best?;
        Some(Proven {
            chosen: Chosen {
                value: if needs_open {
                    value.open()?
                } else {
                    value.clone()
                },
                ballot: (!opened).then(|| cert.ballot.clone()),
            },
            cert: cert.clone(),
            transitions: c
                .shares
                .values()
                .filter(|e| e.complete && e.cert.is_transition())
                .map(|e| e.cert.clone())
                .collect(),
        })
    }

    async fn verification(&self, ballot: &Ballot<NodeId>, value: &Agreed) -> Result<Certificate> {
        let mut cache = self.verified.lock().await;
        let round = (value.config.number, ballot.clone());
        let header = Header::of(self.node.cluster_id, value);
        if let Some(c) = cache.get(&round) {
            ensure!(c.header == header, "conflicting candidate");
            return Ok(c.clone());
        }
        let evidence: Vec<_> = self
            .collected
            .lock()
            .promises
            .get(&round)
            .ok_or_else(|| anyhow::anyhow!("missing prepare evidence"))?
            .values()
            .cloned()
            .collect();
        let highest = promises(self.node.cluster_id, &value.config, ballot, &evidence)?;
        let base = self.base(value.config.number, highest.as_ref().map(|h| &h.header));
        let v = Verification {
            ballot: ballot.clone(),
            value: value.clone(),
            promises: evidence,
            base,
        };
        let requests = value.config.acceptors.iter().map(|to| {
            let v = v.clone();
            async move {
                let share = if *to == self.node.me {
                    self.node.verify_round(self.node.me, v).await?
                } else {
                    let body = postcard::to_stdvec(&v).map_err(|e| e.to_string())?;
                    let bytes = self
                        .node
                        .net
                        .request(*to, SVC_VERIFY, body, super::consensus::REQUEST_TIMEOUT)
                        .await
                        .map_err(|e| e.to_string())?;
                    postcard::from_bytes::<Certificate>(&bytes).map_err(|e| e.to_string())?
                };
                if share.sigs.len() != 1 || !share.sigs.contains_key(to) {
                    return Err("verification reply must contain only its sender's vote".into());
                }
                share.check_signer(to).map_err(|e| e.to_string())?;
                Ok::<Certificate, String>(share)
            }
        });
        use futures_util::StreamExt;
        let mut pending: futures_util::stream::FuturesUnordered<_> = requests.collect();
        let mut merged: Option<Certificate> = None;
        let mut errors = Vec::new();
        while let Some(reply) = pending.next().await {
            if let Err(e) = &reply {
                errors.push(e.clone());
            }
            if let Ok(c) = reply {
                if !c.verified || c.header != header || c.ballot != *ballot {
                    continue;
                }
                match &mut merged {
                    Some(m) => m.sigs.extend(c.sigs),
                    None => merged = Some(c),
                }
                let m = merged.as_ref().unwrap();
                if m.check_config(&value.config, true).is_ok() {
                    cache.insert(round, m.clone());
                    return Ok(m.clone());
                }
            }
        }
        bail!(
            "could not obtain a verification quorum: {}",
            errors.join("; ")
        )
    }
}

impl Transport<NodeId, ClusterState> for Acceptors<'_> {
    type Error = String;
    async fn call(
        &self,
        to: &NodeId,
        mut req: Request<NodeId, ClusterState>,
    ) -> Result<Reply<NodeId, ClusterState>, String> {
        // Always request the accepted body; checking a signed header must not
        // depend on an omitted value supplied by an untrusted peer.
        if let Request::Prepare { have, .. } = &mut req {
            *have = None;
        }
        let (config, ballot) = match &req {
            Request::Prepare { config, ballot, .. } | Request::Accept { config, ballot, .. } => {
                (*config, ballot.clone())
            }
        };
        let proof = if let Request::Accept { value, .. } = &req {
            let p = self
                .verification(&ballot, value)
                .await
                .map_err(|e| e.to_string())?;
            self.add_value(p.header.clone(), value);
            Some(p)
        } else {
            None
        };
        let wire = WireRequest {
            request: req.clone(),
            proof,
            base: self.base(config, None),
        };
        let answer = if *to == self.node.me {
            self.node.handle_wire(self.node.me, wire).await?
        } else {
            let bytes = self
                .node
                .net
                .request(
                    *to,
                    SVC_PAXOS,
                    postcard::to_stdvec(&wire).map_err(|e| e.to_string())?,
                    super::consensus::REQUEST_TIMEOUT,
                )
                .await
                .map_err(|e| e.to_string())?;
            postcard::from_bytes::<PaxosAnswer>(&bytes).map_err(|e| e.to_string())?
        };
        check_feedback(config, &ballot, &answer.reply).map_err(|e| e.to_string())?;
        let mut checked_promise = None;
        if let Reply::Promise {
            config: c,
            ballot: b,
            accepted,
        } = &answer.reply
        {
            let signed = answer.promise.ok_or("unsigned promise")?;
            let p = signed.open(Domain::Promise).map_err(|e| e.to_string())?;
            if signed.signer != *to
                || p.cluster != self.node.cluster_id
                || p.config != config
                || p.ballot != ballot
                || *c != config
                || *b != ballot
            {
                return Err("promise mismatch".into());
            }
            match (accepted, &p.accepted) {
                (None, None) => {}
                (Some((ab, Some(v))), Some(cert))
                    if *ab == cert.ballot && cert.header == Header::of(self.node.cluster_id, v) =>
                {
                    cert.check_config(&v.config, cert.verified)
                        .map_err(|e| e.to_string())?;
                    self.add_value(cert.header.clone(), v);
                }
                _ => return Err("accepted body does not match signed promise".into()),
            }
            checked_promise = Some(signed);
        }
        if let Some(share) = answer.share {
            if share.verified || share.sigs.keys().any(|a| a != to) {
                return Err("invalid acceptance share".into());
            }
            let matches = match &answer.reply {
                Reply::Accepted { config, ballot } => match &req {
                    Request::Accept { value, .. } => {
                        share.header == Header::of(self.node.cluster_id, value)
                            && share.header.config.number == *config
                            && share.ballot == *ballot
                    }
                    _ => false,
                },
                Reply::Promise {
                    accepted: Some((b, Some(v))),
                    ..
                } => share.header == Header::of(self.node.cluster_id, v) && share.ballot == *b,
                _ => false,
            };
            if !matches {
                return Err("acceptance share mismatch".into());
            }
            share.check_signer(to).map_err(|e| e.to_string())?;
            self.add_share(share);
        } else if matches!(
            answer.reply,
            Reply::Accepted { .. }
                | Reply::Promise {
                    accepted: Some(_),
                    ..
                }
        ) {
            return Err("unsigned acceptance".into());
        }
        if let Reply::Stale { learned } = &answer.reply {
            let (cert, transitions) = answer.stale_proof.ok_or("unproved stale answer")?;
            // `learn` may ignore an already-known state. Its proof still
            // needs checking before it can enter this round's evidence cache.
            cert.check_config(&cert.header.config, false)
                .map_err(|e| e.to_string())?;
            if cert.header.cluster_id != self.node.cluster_id || !cert.proves(learned) {
                return Err("stale proof mismatch".into());
            }
            self.node
                .learn(learned.clone(), cert.clone(), transitions)
                .await
                .map_err(|e| e.to_string())?;
            self.add_value(
                Header::of(self.node.cluster_id, &learned.value),
                &learned.value,
            );
            self.add_share(cert);
        }
        if let Some(signed) = checked_promise {
            self.collected
                .lock()
                .promises
                .entry((config, ballot))
                .or_default()
                .insert(*to, signed);
        }
        Ok(answer.reply)
    }
    fn learned(&self) -> Option<Chosen> {
        Some((*self.node.agreed()).clone())
    }
}

/// Feedback without a quorum proof is only a bounded hint for this request.
fn check_feedback(
    config: u64,
    ballot: &Ballot<NodeId>,
    reply: &Reply<NodeId, ClusterState>,
) -> Result<()> {
    match reply {
        Reply::Rejected {
            config: c,
            ballot: b,
            promised,
        } => {
            ensure!(
                *c == config && b == ballot,
                "rejection is for another round"
            );
            ensure!(
                *promised >= *ballot
                    && promised.counter
                        <= ballot
                            .counter
                            .saturating_add(cheesecloth_paxos::MAX_COUNTER_STEP),
                "implausible promised counter"
            );
        }
        Reply::TooHigh {
            config: c,
            ballot: b,
            limit,
        } => {
            ensure!(
                *c == config && b == ballot,
                "counter feedback is for another round"
            );
            ensure!(
                *limit >= cheesecloth_paxos::MAX_COUNTER_STEP && *limit < ballot.counter,
                "implausible counter limit"
            );
        }
        Reply::Accepted {
            config: c,
            ballot: b,
        } => {
            ensure!(
                *c == config && b == ballot,
                "acceptance is for another round"
            );
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheesecloth_core::Identity;
    use cheesecloth_paxos::{Acceptor, store::Stored};

    #[test]
    fn counter_feedback_must_match_the_request_and_existing_jump_limit() {
        let ballot = Ballot {
            counter: 7,
            node: NodeId([1; 32]),
        };
        for counter in [7, 7 + cheesecloth_paxos::MAX_COUNTER_STEP] {
            let reply = Reply::Rejected {
                config: 3,
                ballot: ballot.clone(),
                promised: Ballot {
                    counter,
                    node: ballot.node,
                },
            };
            assert!(check_feedback(3, &ballot, &reply).is_ok());
            assert!(check_feedback(4, &ballot, &reply).is_err());
        }
        for counter in [6, 8 + cheesecloth_paxos::MAX_COUNTER_STEP, u64::MAX] {
            let reply = Reply::Rejected {
                config: 3,
                ballot: ballot.clone(),
                promised: Ballot {
                    counter,
                    node: ballot.node,
                },
            };
            assert!(check_feedback(3, &ballot, &reply).is_err());
        }
        for limit in [0, 6, u64::MAX] {
            assert!(
                check_feedback(
                    3,
                    &ballot,
                    &Reply::TooHigh {
                        config: 3,
                        ballot: ballot.clone(),
                        limit
                    }
                )
                .is_err()
            );
        }
        let high = Ballot {
            counter: 2 * cheesecloth_paxos::MAX_COUNTER_STEP,
            ..ballot
        };
        let reply = Reply::TooHigh {
            config: 3,
            ballot: high.clone(),
            limit: cheesecloth_paxos::MAX_COUNTER_STEP,
        };
        assert!(check_feedback(3, &high, &reply).is_ok());
    }

    #[tokio::test]
    async fn evidence_index_deduplicates_values_and_preserves_openings_and_phases() {
        let h = crate::testing::harness(crate::RelayMode::Never, &[]).await;
        let n = &h.node;
        let transport = Acceptors::new(n);
        let mut closing = n.agreed().value.clone();
        closing.version += 1;
        closing.next = Some(
            closing
                .config
                .successor(closing.config.acceptors.clone(), false),
        );
        let header = Header::of(n.cluster_id, &closing);
        let ballot = Ballot {
            counter: 1,
            node: n.me,
        };
        for _ in 0..7 {
            transport.add_value(header.clone(), &closing);
            transport.add_share(Certificate::sign_verified(
                &n.identity,
                header.clone(),
                ballot.clone(),
            ));
        }
        assert_eq!(transport.collected.lock().values.len(), 2);
        assert_eq!(transport.collected.lock().shares.len(), 2);
        // A verification quorum must never be treated as acceptance.
        assert!(transport.base(0, Some(&header)).is_none());
        assert!(transport.base(1, None).is_none());
        transport.add_share(Certificate::sign(
            &n.identity,
            header.clone(),
            ballot.clone(),
        ));
        let closed = transport.base(0, Some(&header)).unwrap();
        assert_eq!(closed.chosen.value, closing);
        assert_eq!(closed.chosen.ballot, Some(ballot));
        assert!(closed.cert.proves(&closed.chosen));
        let opened = transport.base(1, None).unwrap();
        assert_eq!(opened.chosen.value, closing.open().unwrap());
        assert!(opened.chosen.ballot.is_none());
        assert!(opened.cert.proves(&opened.chosen));
        let mut foreign = header;
        foreign.cluster_id = ClusterId([99; 32]);
        assert!(transport.base(0, Some(&foreign)).is_none());
    }

    #[tokio::test]
    async fn cached_quorum_results_follow_signature_replacement() {
        let h = crate::testing::harness(crate::RelayMode::Never, &[]).await;
        let round = Acceptors::new(&h.node);
        let valid = h.node.cert.lock().clone();
        let mut invalid = valid.clone();
        invalid.sigs.insert(
            h.node.me,
            h.node.identity.sign(Domain::Accept, b"another value"),
        );
        round.add_share(invalid);
        assert!(round.base(0, None).is_none());
        round.add_share(valid);
        assert!(round.base(0, None).is_some());
    }

    #[tokio::test]
    async fn a_ballot_can_be_reused_in_a_new_configuration() {
        let h = crate::testing::harness(crate::RelayMode::Never, &[]).await;
        let n = &h.node;
        let transport = Acceptors::new(n);
        let ballot = Ballot {
            counter: 1,
            node: n.me,
        };
        transport
            .call(
                &n.me,
                Request::Prepare {
                    config: 0,
                    ballot: ballot.clone(),
                    have: None,
                },
            )
            .await
            .unwrap();
        let mut closing = n.agreed().value.clone();
        closing.version += 1;
        closing.value.record_step(n.agreed().state(), None);
        closing.next = Some(
            closing
                .config
                .successor(closing.config.acceptors.clone(), false),
        );
        transport
            .call(
                &n.me,
                Request::Accept {
                    config: 0,
                    ballot: ballot.clone(),
                    value: closing.clone(),
                },
            )
            .await
            .unwrap();
        let opened = closing.open().unwrap();
        transport
            .call(
                &n.me,
                Request::Prepare {
                    config: 1,
                    ballot: ballot.clone(),
                    have: None,
                },
            )
            .await
            .unwrap();
        let mut next = opened.clone();
        next.version += 1;
        next.value.record_step(&opened.value, None);
        let reply = transport
            .call(
                &n.me,
                Request::Accept {
                    config: 1,
                    ballot,
                    value: next,
                },
            )
            .await
            .unwrap();
        assert!(matches!(reply, Reply::Accepted { config: 1, .. }));
    }

    fn setup() -> (Vec<Identity>, Agreed, ClusterId) {
        let ids: Vec<_> = (0..4).map(|_| Identity::generate()).collect();
        let cluster = ClusterId([7; 32]);
        let mut value = Chosen::genesis(ids[0].node_id(), ClusterState::default()).value;
        value.value.cluster_id = Some(cluster);
        value.config.acceptors = ids.iter().map(Identity::node_id).collect();
        value.config.protected = true;
        (ids, value, cluster)
    }
    fn certificate(
        ids: &[Identity],
        value: &Agreed,
        cluster: ClusterId,
        ballot: &Ballot<NodeId>,
    ) -> Certificate {
        let mut c = Certificate::sign_verified(&ids[0], Header::of(cluster, value), ballot.clone());
        for id in &ids[1..3] {
            c.sigs
                .extend(Certificate::sign_verified(id, c.header.clone(), ballot.clone()).sigs);
        }
        c
    }
    #[test]
    fn signed_prepare_evidence_rejects_fabrication_replay_and_duplicates() {
        let (ids, value, cluster) = setup();
        let previous = Ballot {
            counter: 1,
            node: ids[0].node_id(),
        };
        let ballot = Ballot {
            counter: 2,
            node: ids[0].node_id(),
        };
        let c = certificate(&ids, &value, cluster, &previous);
        let p = Promise {
            cluster,
            config: value.config.number,
            ballot: ballot.clone(),
            accepted: Some(c.clone()),
        };
        let evidence: Vec<_> = ids[..3]
            .iter()
            .map(|id| id.seal(Domain::Promise, &p))
            .collect();
        assert_eq!(
            promises(cluster, &value.config, &ballot, &evidence).unwrap(),
            Some(c)
        );
        assert!(promises(cluster, &value.config, &ballot, &evidence[..2]).is_err());
        assert!(
            promises(
                cluster,
                &value.config,
                &ballot,
                &[
                    evidence[0].clone(),
                    evidence[0].clone(),
                    evidence[1].clone()
                ]
            )
            .is_err()
        );
        let wrong_ballot = Ballot {
            counter: 3,
            node: ballot.node,
        };
        assert!(promises(cluster, &value.config, &wrong_ballot, &evidence).is_err());
        assert!(promises(ClusterId([8; 32]), &value.config, &ballot, &evidence).is_err());
        let mut forged = p.clone();
        forged.accepted.as_mut().unwrap().ballot.counter = 99;
        let mut bad = evidence.clone();
        bad[0] = ids[0].seal(Domain::Promise, &forged);
        assert!(promises(cluster, &value.config, &ballot, &bad).is_err());
        forged = p;
        let cert = forged.accepted.as_mut().unwrap();
        cert.sigs.retain(|id, _| *id == ids[0].node_id());
        bad[0] = ids[0].seal(Domain::Promise, &forged);
        assert!(promises(cluster, &value.config, &ballot, &bad).is_err());
    }

    #[test]
    fn verification_and_acceptance_have_separate_signature_domains() {
        let (ids, value, cluster) = setup();
        let ballot = Ballot {
            counter: 1,
            node: ids[0].node_id(),
        };
        let mut c = certificate(&ids, &value, cluster, &ballot);
        c.check_config(&value.config, true).unwrap();
        assert!(c.check_config(&value.config, false).is_err());
        c.verified = false;
        assert!(c.check_config(&value.config, false).is_err());
        c.verified = true;
        let mut downgraded = value.config.clone();
        downgraded.protected = false;
        assert!(c.check_config(&downgraded, true).is_err());
    }

    #[test]
    fn a_restart_preserves_endorsements_and_accepted_proofs() {
        let (ids, value, cluster) = setup();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acceptor");
        let ballot = Ballot {
            counter: 1,
            node: ids[0].node_id(),
        };
        let mut store =
            Stored::<NodeId, ClusterState, Certificate>::create(path.clone(), Acceptor::default())
                .unwrap();
        store.endorse(ballot.clone(), value.clone()).unwrap();
        drop(store);
        let mut store = Stored::<NodeId, ClusterState, Certificate>::open(path.clone()).unwrap();
        let mut conflicting = value.clone();
        conflicting.version += 1;
        assert!(store.endorse(ballot.clone(), conflicting).is_err());
        let proof = certificate(&ids, &value, cluster, &ballot);
        store
            .handle_proven(
                Request::Accept {
                    config: value.config.number,
                    ballot: ballot.clone(),
                    value: value.clone(),
                },
                proof.clone(),
            )
            .unwrap();
        drop(store);
        let store = Stored::<NodeId, ClusterState, Certificate>::open(path).unwrap();
        assert_eq!(
            store.acceptor().accepted_proof(value.config.number),
            Some(&proof)
        );
        assert_eq!(
            store.acceptor().accepted(value.config.number, &ballot),
            Some(&value)
        );
    }
}
