//! Agreeing on changes with CASPaxos, and learning agreed states (see
//! *Consensus and recovery* in DESIGN.md).
//!
//! Every member proposes its own commands. A change reads the agreed state
//! from a quorum of the acceptors, applies the command, and has the result
//! accepted by a quorum. The proposer then tells the acceptors that the
//! value they accepted is agreed, so they learn it without a transfer. Other
//! members learn new states by fetching them from a member whose soft state
//! shows a higher version.

use std::{
    collections::BTreeSet,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use cheesecloth_core::{
    Domain, NodeId, now_ms,
    state::{
        ClusterState, Command, CommandBody, CommandError, DEFAULT_CATCH_UP_DAYS, Outcome, Request,
        Response, SignedCommand, invite_id,
    },
};
use pnyx::{Change, Options, Reply, propose};
use tracing::{debug, info, warn};

use super::{
    Agreed, Chosen, Node,
    acceptors::choose,
    proof::{Certificate, Header, Proven, Trusted},
    round::Acceptors,
};
use crate::proto::{PaxosAnswer, SVC_COMMIT, SVC_FETCH, SVC_STATE};

/// How long one request to an acceptor may take.
pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// How long one change may take.
const CHANGE_DEADLINE: Duration = Duration::from_secs(15);
/// How long fetching a state, or telling a removed member, may take.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a proposer waits to tell an acceptor that a change is agreed.
const COMMIT_TIMEOUT: Duration = Duration::from_secs(2);
/// How many configurations past the latest one it has learned an acceptor
/// answers for. A member can be made an acceptor of a configuration it
/// hasn't learned yet, but a live member catches up within seconds. The limit
/// bounds the slots a faulty member can make an acceptor keep on disk.
const MAX_CONFIGS_AHEAD: u64 = 8;
/// Leave room in the 1 MiB wire limit for a candidate, its certified base,
/// up to 256 KiB of transitions, and the compact quorum evidence.
pub(super) const MAX_STATE_BYTES: usize = 320 << 10;
/// How long a leaving node tries to hand the agreed state over.
const HAND_OFF_DEADLINE: Duration = Duration::from_secs(30);
/// How often a leaving node starts again because it was made an acceptor
/// again while leaving.
pub(super) const LEAVE_ATTEMPTS: u32 = 3;

type PaxosRequest = pnyx::Request<NodeId, ClusterState>;

/// Why a command was not proposed.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    #[error("{0}")]
    Security(String),
    /// The command removes this node while it's an acceptor. Its acceptor
    /// could then hold the only copy of the change when it stops, so it
    /// gives up the role first (see `Node::leave`).
    #[error("this node is an acceptor; it gives up the role before it leaves")]
    Acceptor,
    /// This node is the last member, so no member can take over its role.
    #[error("no other member can take over the acceptor role")]
    NoReplacement,
    /// The new acceptors couldn't agree on anything now: fewer than a
    /// quorum of them are present.
    #[error(
        "too few of the new acceptors are present to agree on changes; \
         try again when more members are connected"
    )]
    NoPresentMajority,
    #[error(
        "the change would make the agreed state {size} bytes, over the limit of \
         {MAX_STATE_BYTES}; remove members or wait for invites and proposals to expire"
    )]
    TooLarge { size: usize },
    /// The state machine refused a command that a change needs.
    #[error("{0}")]
    Command(CommandError),
}

/// Why this node's acceptor didn't answer a request.
#[derive(Debug, thiserror::Error)]
pub(super) enum AcceptError {
    #[error("{0}")]
    Refused(String),
}

impl Node {
    /// Signs a command and has it agreed.
    pub async fn submit(&self, command: Command) -> Result<Outcome> {
        let signed = self.identity.seal(
            Domain::Command,
            &CommandBody {
                cluster_id: Some(self.cluster_id),
                issued_at_ms: now_ms(),
                command,
            },
        );
        self.write(signed).await?.map_err(|e| anyhow!(e))
    }

    /// Has a signed command agreed, and returns the state machine's answer.
    pub(super) async fn write(&self, command: SignedCommand) -> Result<Response> {
        if let Some(refused) = self.check_redemption(&command) {
            return Ok(Err(refused));
        }
        let mut proposed = false;
        let result = self
            .propose_change(|agreed| self.write_round(&command, agreed, &mut proposed))
            .await?;
        Ok(result?)
    }

    /// One round of `write`: applies `command` to the value the round read,
    /// and gives the change to propose with the state machine's answer.
    ///
    /// `proposed` says whether an earlier round of the same `write` applied
    /// the command. A later round that finds the command applied returns the
    /// answer stored with it in the state it read. Any of the earlier rounds
    /// may be the one that was agreed, and their answers may differ.
    pub(super) fn write_round(
        &self,
        command: &SignedCommand,
        agreed: &Agreed,
        proposed: &mut bool,
    ) -> (Change<NodeId, ClusterState>, Result<Response, Refused>) {
        if !agreed.value.is_member(&self.me) {
            return (Change::Keep, Ok(Err(CommandError::NotMember)));
        }
        let mut next = agreed.value.clone();
        let request = Request {
            at_ms: now_ms().max(next.now_ms),
            command: command.clone(),
        };
        let resp = next.apply(&request);
        if resp == Err(CommandError::Replay)
            && *proposed
            && let Some(r) = agreed.value.applied(command)
        {
            return (Change::Keep, Ok(r.clone()));
        }
        if next != agreed.value {
            next.record_step(&agreed.value, Some(request));
        }
        // A refused command may still change the state (a redemption burns
        // the invite first), and such changes are kept.
        match self.change_to(agreed, next) {
            Ok(change) => {
                *proposed = true;
                (change, Ok(resp))
            }
            Err(refused) => (Change::Keep, Err(refused)),
        }
    }

    /// The change that makes `next` the state. If `next` removes an
    /// acceptor, the same change replaces it.
    pub(super) fn change_to(
        &self,
        agreed: &Agreed,
        next: ClusterState,
    ) -> Result<Change<NodeId, ClusterState>, Refused> {
        if next == agreed.value {
            return Ok(Change::Keep);
        }
        check_size(&agreed.value, &next, MAX_STATE_BYTES)?;
        super::acceptors::check_policy(agreed, &next).map_err(Refused::Security)?;
        let current = agreed.acceptors();
        if current.iter().all(|a| next.is_member(a)) {
            return Ok(Change::Set(next));
        }
        if current.contains(&self.me) && !next.is_member(&self.me) {
            return Err(Refused::Acceptor);
        }
        let live = self.live();
        let facts = |n: &NodeId| self.candidate(n, &live);
        let desired = choose(current, &next, facts);
        if desired.iter().any(|a| !next.is_member(a)) {
            return Err(Refused::NoReplacement);
        }
        let config = super::acceptors::configuration(agreed, &next, desired.clone())
            .map_err(Refused::Security)?;
        if desired.iter().filter(|a| facts(a).present).count() < config.quorum() {
            return Err(Refused::NoPresentMajority);
        }
        info!(acceptors = ?short(&desired), "replacing acceptors that are no longer members");
        Ok(Change::Close(next, config))
    }

    /// Leaves the cluster in three steps, so that when this node stops it
    /// holds nothing that the other members need:
    ///
    /// 1. If this node is an acceptor, a change gives the role to other
    ///    members. This node stays a member.
    /// 2. The agreed state is sent to the acceptors, until a quorum of
    ///    them have it on disk. Otherwise, if this node was the only
    ///    acceptor, it could hold the only copy of step 1.
    /// 3. The change that removes this node is agreed by the other
    ///    acceptors.
    ///
    /// If a step fails, this node usually is still a member. But if it has
    /// learned meanwhile that it isn't (another member got its removal agreed
    /// first, for example after an answer to step 3 was lost, and told it),
    /// it has left. With `force`, the next step is tried anyway, and the
    /// errors are returned for the caller to report before it stops the node.
    /// The cluster may then need repair.
    pub async fn leave(&self, force: bool) -> Result<Vec<String>> {
        match self.leave_steps(force).await {
            Err(e) if !self.is_member(&self.me) => {
                info!("this node is no longer a member, although leaving failed: {e:#}");
                Ok(Vec::new())
            }
            r => r,
        }
    }

    /// The steps of `leave`.
    async fn leave_steps(&self, force: bool) -> Result<Vec<String>> {
        let mut problems = Vec::new();
        let mut check = |r: Result<()>| match r {
            Err(e) if force => {
                warn!("leaving anyway: {e:#}");
                problems.push(format!("{e:#}"));
                Ok(false)
            }
            r => r.map(|()| true),
        };
        for attempt in 1..=LEAVE_ATTEMPTS {
            let moved = check(
                self.give_up_acceptor_role()
                    .await
                    .context("giving the acceptor role to other members"),
            )?;
            check(
                self.hand_off()
                    .await
                    .context("handing the agreed state to the acceptors"),
            )?;
            let removed = match self.submit(Command::Leave).await {
                // The state this round read, now agreed, already doesn't
                // have this node: it has left, for example by an earlier
                // `leave` whose answer was lost.
                Err(e) if e.downcast_ref() == Some(&CommandError::NotMember) => Ok(()),
                r => r.map(drop),
            };
            if start_over(&removed, moved, attempt) {
                continue;
            }
            check(removed.context("agreeing on this node's removal"))?;
            break;
        }
        Ok(problems)
    }

    /// Leaving, step 1: if this node is an acceptor, a change that gives the
    /// role to other members.
    pub(super) async fn give_up_acceptor_role(&self) -> Result<()> {
        if !self.agreed().value.acceptors().contains(&self.me) {
            return Ok(());
        }
        self.propose_change(|agreed| self.give_up_round(agreed))
            .await??;
        Ok(())
    }

    /// One round of `give_up_acceptor_role`: the change that gives this
    /// node's role to other members, given the value the round read.
    pub(super) fn give_up_round(
        &self,
        agreed: &Agreed,
    ) -> (Change<NodeId, ClusterState>, Result<(), Refused>) {
        let current = agreed.acceptors();
        if !current.contains(&self.me) {
            return (Change::Keep, Ok(()));
        }
        // Signed, so that acceptors let the new set leave this node out
        // (see `check_set`).
        let command = self.identity.seal(
            Domain::Command,
            &CommandBody {
                cluster_id: Some(self.cluster_id),
                issued_at_ms: now_ms(),
                command: Command::GiveUpAcceptor,
            },
        );
        let request = Request {
            at_ms: now_ms().max(agreed.value.now_ms),
            command,
        };
        let mut next = agreed.value.clone();
        if let Err(e) = next.apply(&request) {
            return (Change::Keep, Err(Refused::Command(e)));
        }
        next.record_step(&agreed.value, Some(request));
        let mut after = next.clone();
        after.members.remove(&self.me);
        let live = self.live();
        let facts = |n: &NodeId| self.candidate(n, &live);
        let desired = choose(current, &after, facts);
        if desired.contains(&self.me) {
            return (Change::Keep, Err(Refused::NoReplacement));
        }
        let config = match super::acceptors::configuration(agreed, &next, desired.clone()) {
            Ok(c) => c,
            Err(e) => return (Change::Keep, Err(Refused::Security(e))),
        };
        if desired.iter().filter(|a| facts(a).present).count() < config.quorum() {
            return (Change::Keep, Err(Refused::NoPresentMajority));
        }
        info!(acceptors = ?short(&desired), "giving up the acceptor role");
        (Change::Close(next, config), Ok(()))
    }

    /// Leaving, step 2: sends the agreed state to its acceptors other than
    /// this node, until a quorum of all its acceptors say they have it.
    pub(super) async fn hand_off(&self) -> Result<()> {
        let chosen = self.agreed();
        let version = chosen.value.version;
        let acceptors = chosen.value.acceptors();
        let need = chosen.value.active_config().quorum();
        let others: Vec<NodeId> = acceptors
            .iter()
            .filter(|a| **a != self.me)
            .copied()
            .collect();
        if others.len() < need {
            bail!("no majority of the acceptors is other members");
        }
        let from = chosen.value.config.number.saturating_sub(MAX_CONFIGS_AHEAD);
        let body = postcard::to_stdvec(&self.proven(from).await).expect("serializable");
        let deadline = tokio::time::Instant::now() + HAND_OFF_DEADLINE;
        let mut have = BTreeSet::new();
        let mut last_error = String::new();
        loop {
            let sends = others.iter().filter(|a| !have.contains(*a)).map(|a| {
                let body = body.clone();
                async move {
                    let reply = self.net.request(*a, SVC_STATE, body, FETCH_TIMEOUT).await;
                    (a, reply)
                }
            });
            for (a, reply) in futures_util::future::join_all(sends).await {
                match reply.map(|b| postcard::from_bytes::<u64>(&b)) {
                    Ok(Ok(v)) if v >= version => {
                        have.insert(*a);
                    }
                    Ok(Ok(v)) => last_error = format!("{} holds version {v}", a.short()),
                    Ok(Err(e)) => last_error = format!("{}: {e}", a.short()),
                    Err(e) => last_error = format!("{}: {e:#}", a.short()),
                }
            }
            if have.len() >= need {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                bail!(
                    "{} of the {} acceptors have the agreed state, {need} are needed \
                     (last error: {last_error})",
                    have.len(),
                    acceptors.len()
                );
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// Runs one change, then learns the result. `change` may be called more
    /// than once (see `pnyx::propose`).
    pub(super) async fn propose_change<R>(
        &self,
        change: impl FnMut(&Agreed) -> (Change<NodeId, ClusterState>, R),
    ) -> Result<R> {
        self.lifetime
            .run(async {
                let mut proposer = self.proposer.lock().await;
                proposer.learn((*self.agreed()).clone());
                let mut options = Options::default();
                options.request_timeout = REQUEST_TIMEOUT;
                options.deadline = CHANGE_DEADLINE;
                let acceptors = Acceptors::new(self);
                let result = propose(&mut proposer, &acceptors, &options, change).await;
                // A failed change may still have learned a newer state from an
                // acceptor.
                let known = proposer.known().clone();
                drop(proposer);
                match result {
                    Ok((chosen, r)) => {
                        let cert = acceptors
                            .certify(&chosen)
                            .context("the change lacks a valid acceptance certificate")?;
                        let proven = Proven {
                            transitions: {
                                let mut t = self.transitions_for(&chosen);
                                t.extend(acceptors.transitions());
                                t
                            },
                            chosen,
                            cert,
                        };
                        // Before learning it ourselves: until then, removed members
                        // still count as members, so they can be told. And before the
                        // commit notices: a relay that learns the change from one
                        // would no longer forward to a removed member.
                        self.tell_removed(&proven).await;
                        self.tell_acceptors(&proven).await;
                        self.learn(proven.chosen, proven.cert, proven.transitions)
                            .await
                            .context("learning the agreed change")?;
                        Ok(r)
                    }
                    Err(e) => {
                        if let Some(cert) = acceptors.certify(&known)
                            && let Err(e) = self.learn(known, cert, acceptors.transitions()).await
                        {
                            warn!("learning the state an acceptor sent: {e:#}");
                        }
                        Err(e).context("couldn't agree on the change")
                    }
                }
            })
            .await?
    }

    /// Answers a CASPaxos request. A request must come from the proposer its
    /// ballot names, so that no member can use another member's ballots. A
    /// value to accept must carry a matching verification quorum certificate.
    /// An answer that reports an accepted value carries
    /// this acceptor's signature on it; a stale answer carries the proof of
    /// the state it holds.
    #[cfg(test)]
    pub(super) async fn handle_paxos(
        &self,
        from: NodeId,
        req: PaxosRequest,
    ) -> Result<PaxosAnswer, AcceptError> {
        self.handle_paxos_proven(from, req, None).await
    }

    pub(super) async fn handle_paxos_proven(
        &self,
        from: NodeId,
        req: PaxosRequest,
        proof: Option<Certificate>,
    ) -> Result<PaxosAnswer, AcceptError> {
        let ballot = match &req {
            pnyx::Request::Prepare { ballot, .. } | pnyx::Request::Accept { ballot, .. } => ballot,
        };
        if ballot.node != from {
            return Err(AcceptError::Refused(format!(
                "request from {} uses another node's ballot",
                from.short()
            )));
        }
        let config = match &req {
            pnyx::Request::Prepare { config, .. } | pnyx::Request::Accept { config, .. } => *config,
        };
        let mut acceptor = self.acceptor.clone().lock_owned().await;
        if let Some(learned) = acceptor.acceptor().learned() {
            check_config(self.me, &learned.value, config).map_err(AcceptError::Refused)?;
        }
        let (identity, cluster_id) = (self.identity.clone(), self.cluster_id);
        // Checking and signing hash the state, checking applies it, and
        // saving syncs the disk: not on a worker thread.
        let (reply, share, stale_cert, promise) = self
            .lifetime
            .blocking(move || {
                let reply = if let pnyx::Request::Accept { value, ballot, .. } = &req {
                    let proof = proof.ok_or_else(|| {
                        AcceptError::Refused("accept requires a verification certificate".into())
                    })?;
                    let learned = acceptor
                        .acceptor()
                        .learned()
                        .ok_or_else(|| AcceptError::Refused("no trusted state".into()))?;
                    let trusted = if value.config.number == learned.value.config.number {
                        &learned.value.config
                    } else {
                        learned.value.active_config()
                    };
                    proof
                        .check_config(trusted, true)
                        .map_err(|e| AcceptError::Refused(e.to_string()))?;
                    if proof.ballot != *ballot || proof.header != Header::of(cluster_id, value) {
                        return Err(AcceptError::Refused("accept proof mismatch".into()));
                    }
                    acceptor.handle_proven(req, proof)
                } else {
                    acceptor.handle(req)
                }
                .map_err(|e| AcceptError::Refused(format!("{e:#}")))?;
                let a = acceptor.acceptor();
                let accepted = match &reply {
                    Reply::Accepted { config, ballot } => Some((*config, ballot)),
                    Reply::Promise {
                        config,
                        accepted: Some((ballot, _)),
                        ..
                    } => Some((*config, ballot)),
                    _ => None,
                };
                let share = accepted.and_then(|(config, ballot)| {
                    let value = a.accepted(config, ballot)?;
                    let header = Header::of(cluster_id, value);
                    Some(Certificate::sign(&identity, header, ballot.clone()))
                });
                let stale_cert = matches!(reply, Reply::Stale { .. })
                    .then(|| a.proof().cloned())
                    .flatten();
                let promise = if let Reply::Promise {
                    config,
                    ballot,
                    accepted,
                } = &reply
                {
                    let proof = if accepted.is_some() {
                        Some(a.accepted_proof(*config).cloned().ok_or_else(|| {
                            AcceptError::Refused(
                                "accepted value lacks its verification proof".into(),
                            )
                        })?)
                    } else {
                        None
                    };
                    Some(identity.seal(
                        Domain::Promise,
                        &super::round::Promise {
                            cluster: cluster_id,
                            config: *config,
                            ballot: ballot.clone(),
                            accepted: proof,
                        },
                    ))
                } else {
                    None
                };
                Ok::<_, AcceptError>((reply, share, stale_cert, promise))
            })
            .await
            .map_err(|e| AcceptError::Refused(format!("{e:#}")))??;
        let stale_proof = stale_cert.map(|cert| (cert, self.transitions.lock().since(config)));
        Ok(PaxosAnswer {
            reply,
            share,
            stale_proof,
            promise,
        })
    }

    /// An invite redemption goes through consensus only if this node knows
    /// the invite. Anyone who can reach a member can attempt a redemption,
    /// and a guessed secret must not cost a change. The invite token lists the
    /// inviter first, and the inviter knows its invite.
    fn check_redemption(&self, command: &SignedCommand) -> Option<CommandError> {
        let body = command.open(Domain::Command).ok()?;
        let Command::RedeemInvite { secret, .. } = &body.command else {
            return None;
        };
        let known = self
            .agreed()
            .value
            .value
            .invites
            .contains_key(&invite_id(secret));
        (!known).then_some(CommandError::InviteUnknown)
    }

    /// Records an agreed state if it's newer than ours: in memory, and in
    /// our acceptor, which saves it with its proof and drops older
    /// configurations. The proof must check out against the acceptors this
    /// node trusts, which `transitions` may extend (see `proof`). Checked
    /// transitions are kept even if the proof then fails, so a node that is
    /// far behind catches up over several fetches.
    ///
    /// If saving fails, the state isn't learned: this node then tells no one
    /// that it has it. If this future is dropped after the save, the state is
    /// taken in the next time it's learned: from the next fetch, or from the
    /// file after a restart.
    pub(crate) async fn learn(
        &self,
        chosen: Chosen,
        cert: Certificate,
        mut transitions: Vec<Certificate>,
    ) -> Result<()> {
        self.lifetime.run(async {
        if chosen.state().cluster_id != Some(self.cluster_id)
            || cert.header.cluster_id != self.cluster_id
        {
            bail!("the agreed state is from another cluster");
        }
        {
            let _one_at_a_time = self.learning.lock().await;
            let current = self.agreed();
            if chosen.value.version == current.value.version && chosen.value != current.value {
                bail!("conflicting state at the current version; refusing to merge histories");
            }
            if chosen.value.version <= current.value.version {
                return Ok(());
            }
            let mut stored = self.transitions.lock().clone();
            let mut trusted = Trusted::new(&current.value);
            stored.extend(&mut trusted);
            let mut changed = false;
            transitions.sort_by_key(|t| t.header.config.number);
            for t in transitions {
                if t.header.cluster_id == self.cluster_id
                    && t.header.config.number == trusted.frontier()
                {
                    trusted.follow(&t)?;
                    changed |= stored.insert(t);
                }
            }
            let checked = trusted.check(&cert).and_then(|()| {
                if !cert.proves(&chosen) {
                    bail!("the proof is for another value");
                }
                chosen.state().verify_members()?;
                Ok(())
            });
            if checked.is_ok() && cert.is_transition() {
                changed |= stored.insert(cert.clone());
            }
            let latest = if checked.is_ok() { &chosen } else { &*current };
            let days = latest
                .state()
                .settings()
                .map_or(DEFAULT_CATCH_UP_DAYS, |s| s.catch_up_days);
            changed |= stored.prune(latest.state().now_ms, days);
            if changed {
                let (path, saved) = (self.files.transitions(), stored.clone());
                self.lifetime.blocking(move || saved.save(&path))
                    .await?
                    .context("saving the transitions")?;
                *self.transitions.lock() = stored;
            }
            checked?;
            let mut acceptor = self.acceptor.clone().lock_owned().await;
            let (saved, proof) = (chosen.clone(), cert.clone());
            // Saving syncs the disk: not on a worker thread.
            let on_disk = self.lifetime.blocking(move || {
                    let learned = acceptor.learn(saved.clone(), proof)?;
                    // An earlier `learn` of this value that was dropped after
                    // its save left it in the acceptor but not in `state`.
                    Ok::<_, std::io::Error>(learned || acceptor.acceptor().learned() == Some(&saved))
                })
                .await?
                .context("saving the agreed state")?;
            // Otherwise, the version is newer than the one learned, so the
            // acceptor ignores the value only if it goes back to an older
            // configuration. Then it saved nothing.
            if !on_disk {
                bail!("this node's acceptor ignored the agreed state");
            }
            let previous = current.value.active_config();
            let installed = chosen.value.active_config();
            if previous.protected && !installed.protected {
                if installed.acceptors.len() < previous.acceptors.len() {
                    warn!(
                        nodes = installed.acceptors.len(),
                        "Network reduced to {} voters; Byzantine safety guarantees suspended",
                        installed.acceptors.len()
                    );
                } else {
                    warn!(
                        nodes = installed.acceptors.len(),
                        "Byzantine safety guarantees suspended by committed configuration policy"
                    );
                }
            } else if !previous.protected && installed.protected {
                info!(
                    nodes = installed.acceptors.len(),
                    quorum = installed.quorum(),
                    "Certified protected configuration activated"
                );
            }
            debug!(version = chosen.value.version, "learned a new agreed state");
            *self.cert.lock() = cert;
            self.state.send_replace(Arc::new(chosen));
        }
        self.publish.notify_one();
        self.wake.notify_one();
        Ok(())
            }).await?
    }

    /// This node's state with its proof, and the transitions from
    /// configuration `from` on, for a node that is behind.
    pub(super) async fn proven(&self, from: u64) -> Proven {
        let _one_at_a_time = self.learning.lock().await;
        Proven {
            chosen: (*self.agreed()).clone(),
            cert: self.cert.lock().clone(),
            transitions: self.transitions.lock().since(from),
        }
    }

    /// The transitions to send with `chosen` to members that are a little
    /// behind, such as removed members (see `check_config`).
    fn transitions_for(&self, chosen: &Chosen) -> Vec<Certificate> {
        let from = chosen.value.config.number.saturating_sub(MAX_CONFIGS_AHEAD);
        self.transitions.lock().since(from)
    }

    /// The latest configuration whose acceptors this node can check proofs
    /// against: its state's, and the ones its transitions lead to.
    fn frontier(&self) -> u64 {
        let mut trusted = Trusted::new(&self.agreed().value);
        self.transitions.lock().extend(&mut trusted);
        trusted.frontier()
    }

    /// Fetches the agreed state from `from`, which holds `version`, if that's
    /// newer than ours. One fetch at a time; a failed one is tried again on
    /// the soft state loop's next round, and a lasting failure is reported.
    pub(super) fn fetch_from(self: &Arc<Self>, from: NodeId, version: u64) {
        if version <= self.agreed().value.version || self.fetching.swap(true, Ordering::SeqCst) {
            return;
        }
        let node = self.clone();
        self.lifetime.spawn(async move {
            let before = (node.agreed().value.version, node.frontier());
            let mut result = node.fetch(from).await;
            let progress = (node.agreed().value.version, node.frontier()) > before;
            node.soft
                .lock()
                .fetched(from, progress, std::time::Instant::now());
            if result.is_ok() && !progress {
                result = Err(anyhow!(
                    "peer supplied no newer verified state or transitions"
                ));
            }
            if let Err(e) = &result {
                debug!(peer = %from.short(), "fetching the agreed state: {e:#}");
            }
            node.catch_up_problem.record(result);
            node.fetching.store(false, Ordering::SeqCst);
        });
    }

    async fn fetch(&self, from: NodeId) -> Result<()> {
        let frontier = self.frontier();
        let body = postcard::to_stdvec(&frontier).expect("serializable");
        let bytes = self
            .net
            .request(from, SVC_FETCH, body, FETCH_TIMEOUT)
            .await?;
        let proven: Proven = postcard::from_bytes(&bytes)?;
        let needs = proven.cert.header.config.number;
        let learned = self
            .learn(proven.chosen, proven.cert, proven.transitions)
            .await;
        if learned.is_err() && self.frontier() < needs {
            return learned.context(
                "the peer doesn't have all the changes of acceptors this node missed; if this \
                 node was away longer than the catch_up_days setting, remove it and invite it \
                 again",
            );
        }
        learned
    }

    /// Members that a change removed can no longer fetch states (members
    /// only answer members), so the proposer sends them the new state
    /// before it learns it itself: until then it still counts them as
    /// members.
    ///
    /// Only live members are told (see `Node::live`): the usual reason to
    /// remove a member is that it's gone, and a request to it would only
    /// wait for its timeout.
    async fn tell_removed(&self, proven: &Proven) {
        let before = self.agreed();
        let live = self.live();
        let removed: Vec<NodeId> = before
            .value
            .value
            .members
            .keys()
            .filter(|n| **n != self.me && !proven.chosen.state().is_member(n) && live.contains(n))
            .copied()
            .collect();
        if removed.is_empty() {
            return;
        }
        let body = postcard::to_stdvec(proven).expect("serializable");
        let tells = removed.iter().map(|n| {
            let body = body.clone();
            async move {
                if let Err(e) = self.net.request(*n, SVC_STATE, body, FETCH_TIMEOUT).await {
                    debug!(peer = %n.short(), "telling a removed member: {e:#}");
                }
            }
        });
        futures_util::future::join_all(tells).await;
    }

    /// Tells the other acceptors of the change's configuration that the value
    /// they accepted is agreed, with its proof. Only a few hundred bytes, and
    /// it means a proposer that stops next (such as one that just left) still
    /// leaves the change known.
    ///
    /// Only for this node's own ballots: acceptors take a notice only from the
    /// proposer its ballot names. A change that read a value already agreed
    /// by another proposer ends with that proposer's ballot, and that proposer
    /// has told the acceptors itself.
    async fn tell_acceptors(&self, proven: &Proven) {
        let Some(ballot) = &proven.chosen.ballot else {
            return; // the opening of a configuration: no acceptor holds it
        };
        if ballot.node != self.me {
            return;
        }
        let body = postcard::to_stdvec(&proven.cert).expect("serializable");
        // Not to acceptors that aren't live: the notice would only wait for
        // its timeout, and they learn the change later anyway.
        let live = self.live();
        let tells = proven
            .chosen
            .value
            .config
            .acceptors
            .iter()
            .filter(|a| **a != self.me && live.contains(a))
            .map(|a| {
                let body = body.clone();
                async move {
                    if let Err(e) = self.net.request(*a, SVC_COMMIT, body, COMMIT_TIMEOUT).await {
                        debug!(peer = %a.short(), "telling an acceptor of a change: {e:#}");
                    }
                }
            });
        futures_util::future::join_all(tells).await;
    }

    /// Learns the value our acceptor accepted in the configuration and at the
    /// ballot of `cert`, which its proposer `from` says is agreed. Only the
    /// proposer that the ballot names may say so, and the proof must check
    /// out.
    pub(super) async fn learn_commit(&self, from: NodeId, cert: Certificate) -> Result<(), String> {
        if cert.ballot.node != from {
            return Err(format!(
                "commit notice from {} for another node's ballot",
                from.short()
            ));
        }
        let value = self
            .acceptor
            .lock()
            .await
            .acceptor()
            .accepted(cert.header.config.number, &cert.ballot)
            .cloned();
        if let Some(value) = value {
            let chosen = Chosen {
                value,
                ballot: Some(cert.ballot.clone()),
            };
            self.learn(chosen, cert, Vec::new())
                .await
                .map_err(|e| format!("learning a committed change: {e:#}"))?;
        }
        Ok(())
    }

    /// Takes in an agreed state that another member sends (see
    /// `tell_removed` and `hand_off`). Returns the version this node then
    /// holds on disk.
    pub(super) async fn take_state(&self, proven: Proven) -> Result<u64, String> {
        self.learn(proven.chosen, proven.cert, proven.transitions)
            .await
            .map_err(|e| format!("{e:#}"))?;
        Ok(self.agreed().value.version)
    }
}

/// Whether `leave` starts over after step 3 gave `removed`: only when step 1
/// moved the acceptor role in this attempt, another member has made this node
/// an acceptor again since, and attempts remain.
pub(super) fn start_over(removed: &Result<()>, moved: bool, attempt: u32) -> bool {
    let again = matches!(removed, Err(e) if e.downcast_ref() == Some(&Refused::Acceptor));
    again && moved && attempt < LEAVE_ATTEMPTS
}

/// Refuses a change that makes the state larger than `max` bytes. A change
/// that doesn't make it larger passes, so a state over the limit can still be
/// made smaller.
pub(super) fn check_size(
    before: &ClusterState,
    after: &ClusterState,
    max: usize,
) -> Result<(), Refused> {
    let size = |s: &ClusterState| postcard::to_stdvec(s).expect("serializable").len();
    let after = size(after);
    if after > max && after > size(before) {
        return Err(Refused::TooLarge { size: after });
    }
    Ok(())
}

/// Refuses a request for configuration `config` that this node shouldn't get,
/// given the latest value it has learned: one too far past that value's
/// configuration, or one whose acceptors it knows and isn't one of.
/// Requests for older configurations pass: the acceptor answers them as
/// stale.
fn check_config(me: NodeId, learned: &Agreed, config: u64) -> Result<(), String> {
    let known = learned.config.number;
    if config > known + MAX_CONFIGS_AHEAD {
        return Err(format!(
            "configuration {config} is too far past the latest this node knows ({known})"
        ));
    }
    let acceptors = if config == known {
        Some(&learned.config.acceptors)
    } else if config == known + 1 {
        learned.next.as_ref().map(|c| &c.acceptors)
    } else {
        None
    };
    if acceptors.is_some_and(|a| !a.contains(&me)) {
        return Err(format!(
            "this node is not an acceptor of configuration {config}"
        ));
    }
    Ok(())
}

/// Short node IDs, for logs.
pub(super) fn short(nodes: &BTreeSet<NodeId>) -> Vec<String> {
    nodes.iter().map(|n| n.short()).collect()
}
