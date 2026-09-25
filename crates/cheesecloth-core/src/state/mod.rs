//! The cluster state agreed through consensus, and the commands that change it.
//!
//! `ClusterState::apply` is deterministic: every input, including the time, comes
//! from the request. The proposer stamps `Request::at_ms` when it applies a
//! command, never earlier than the state's time.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::{ClusterId, Domain, NodeId, Signed, WgKey};

/// How long an invite can wait to be redeemed. Deliberately not configurable.
pub const INVITE_TTL: Duration = Duration::from_secs(30 * 60);
/// How long a join/remove/setting proposal waits for approvals.
pub const PROPOSAL_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// A signed command must be applied within this long of being issued, and
/// the same command is refused if it's seen twice within it.
pub const REPLAY_WINDOW: Duration = Duration::from_secs(10 * 60);
/// The default of the `catch_up_days` setting.
pub const DEFAULT_CATCH_UP_DAYS: u32 = 30;
/// The largest value of the `catch_up_days` setting: ten years.
pub const MAX_CATCH_UP_DAYS: u32 = 3650;
/// The longest member name, in bytes.
pub const MAX_NAME_LEN: usize = 32;
/// The most control-plane addresses a member record may list. With the name
/// limit, this keeps a member record under about 1 KiB.
pub const MAX_CONTROL_ADDRS: usize = 16;

const fn ms(d: Duration) -> u64 {
    d.as_millis() as u64
}

/// What a node says about itself. Always signed by that node
/// (`Domain::MemberInfo`), so nobody else can change its keys or addresses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberInfo {
    pub node_id: NodeId,
    pub wg_key: WgKey,
    /// A human-friendly label (the host name by default).
    pub name: String,
    /// Where the node accepts control-plane (QUIC) connections.
    pub control_addrs: Vec<SocketAddr>,
    pub wg_port: u16,
    /// The node acts as a relay: publicly reachable, forwards control-plane
    /// messages and reports WireGuard endpoints.
    pub relay: bool,
}

/// A member as recorded in the cluster state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub info: MemberInfo,
    /// `info`, as signed by the member.
    pub signed_info: Signed<MemberInfo>,
    pub ipv4: Ipv4Addr,
    pub added_at_ms: u64,
    pub added_by: NodeId,
    /// Members whose approvals admitted this one (empty when none were needed).
    pub approved_by: Vec<NodeId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// Extra approvals needed for joins, removals and setting changes.
    pub approvals_required: u32,
    pub ipv4_range: Ipv4Net,
    /// Cap on the number of acceptors.
    pub acceptors: u8,
    pub strict_security: bool,
    pub buffer_nodes: u8,
    /// How long members keep the proofs of changes of acceptors, so that a
    /// member that was away that long can still check the current state (see
    /// *Consensus and recovery* in DESIGN.md).
    pub catch_up_days: u32,
}

impl Settings {
    pub fn new(ipv4_range: Ipv4Net) -> Self {
        Self {
            approvals_required: 0,
            ipv4_range,
            acceptors: 7,
            strict_security: false,
            buffer_nodes: 0,
            catch_up_days: DEFAULT_CATCH_UP_DAYS,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettingChange {
    ApprovalsRequired(u32),
    Acceptors(u8),
    StrictSecurity(bool),
    BufferNodes(u8),
    CatchUpDays(u32),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    pub creator: NodeId,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalKind {
    Join { joiner: Signed<MemberInfo> },
    Remove { target: NodeId },
    Setting { change: SettingChange },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    pub id: crate::ProposalId,
    pub kind: ProposalKind,
    pub proposer: NodeId,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    /// The signed `Approve` commands collected so far, by approver.
    pub approvals: BTreeMap<NodeId, SignedCommand>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    /// Creates the cluster. Only valid as the first command.
    Genesis {
        nonce: [u8; 16],
        settings: Settings,
        founder: Signed<MemberInfo>,
    },
    /// Registers an invite by the hash of its secret.
    CreateInvite {
        invite_id: [u8; 32],
    },
    /// Burns the invite and admits the joiner (or proposes it, with approvals).
    RedeemInvite {
        secret: [u8; 32],
        joiner: Signed<MemberInfo>,
    },
    ProposeRemove {
        target: NodeId,
    },
    /// The signer removes itself. Never needs approvals.
    Leave,
    ProposeSetting {
        change: SettingChange,
    },
    Approve {
        proposal: crate::ProposalId,
    },
    Reject {
        proposal: crate::ProposalId,
    },
    /// The signer updates its own addresses, name or relay flag.
    UpdateSelf {
        info: Signed<MemberInfo>,
    },
    /// The signer gives up its acceptor role, before it leaves. It changes
    /// nothing in the state: the change that carries it names acceptors
    /// without the signer, and acceptors check that change's set with one
    /// member fewer (see *Lifecycle and recovery* in DESIGN.md).
    GiveUpAcceptor,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandBody {
    /// Genesis uses None; every subsequent command names its cluster.
    pub cluster_id: Option<ClusterId>,
    pub issued_at_ms: u64,
    pub command: Command,
}

pub type SignedCommand = Signed<CommandBody>;

/// A signed command, stamped with the proposer's clock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub at_ms: u64,
    pub command: SignedCommand,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Genesis {
        cluster_id: ClusterId,
    },
    InviteCreated {
        expires_at_ms: u64,
    },
    Joined {
        node: NodeId,
        ipv4: Ipv4Addr,
    },
    Pending {
        proposal: crate::ProposalId,
    },
    Removed {
        node: NodeId,
    },
    Left {
        node: NodeId,
    },
    Approved {
        proposal: crate::ProposalId,
        remaining: u32,
    },
    Rejected {
        proposal: crate::ProposalId,
    },
    SettingChanged,
    Updated,
    GaveUpAcceptor,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum CommandError {
    #[error("the command belongs to another cluster")]
    WrongCluster,
    #[error("bad signature")]
    BadSignature,
    #[error("the command was issued too long ago, or the clocks differ too much")]
    Stale,
    #[error("the command was already applied")]
    Replay,
    #[error("the cluster has already been created")]
    AlreadyInitialized,
    #[error("the cluster doesn't exist yet")]
    NotInitialized,
    #[error("the signer is not a member")]
    NotMember,
    #[error("unknown, expired or already used invite")]
    InviteUnknown,
    #[error("the node is already a member")]
    AlreadyMember,
    #[error("a join for this node is already waiting for approval")]
    AlreadyPending,
    #[error("the node is not a member")]
    NoSuchMember,
    #[error("no such proposal")]
    NoSuchProposal,
    #[error("the proposer can't approve its own proposal")]
    OwnProposal,
    #[error("a member can't approve or reject its own removal")]
    OwnRemoval,
    #[error("already approved by this member")]
    AlreadyApproved,
    #[error("no free overlay IPv4 address left in {0}")]
    RangeFull(Ipv4Net),
    #[error("invalid setting: {0}")]
    InvalidSetting(String),
    #[error("invalid member record: {0}")]
    InvalidMember(String),
}

pub type Response = Result<Outcome, CommandError>;

/// The replicated cluster state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterState {
    pub cluster_id: Option<ClusterId>,
    pub settings: Option<Settings>,
    pub members: BTreeMap<NodeId, Member>,
    /// Keyed by the hash of the invite secret.
    pub invites: BTreeMap<[u8; 32], Invite>,
    pub proposals: BTreeMap<crate::ProposalId, Proposal>,
    pub next_proposal: u64,
    /// Recently applied commands, by digest.
    pub recent: BTreeMap<[u8; 32], Applied>,
    /// Time of the last applied command.
    pub now_ms: u64,
    /// How this state was made from the agreed state before it. `None` only
    /// for a cluster's first state.
    pub step: Option<Step>,
}

/// How a state was made from the agreed state before it, so that acceptors
/// can check it (see *Authenticated round* in CONSENSUS-SAFETY.md).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// The hash of the state it was made from (see [`ClusterState::hash`]).
    pub from: [u8; 32],
    /// The command applied, with the time the proposer gave it. `None` for a
    /// change that only names new acceptors.
    pub command: Option<Request>,
}

/// Why a state isn't a valid step from another.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StepError {
    #[error("the state doesn't record how it was made")]
    Missing,
    #[error("the state was made from another state")]
    OtherBase,
    #[error("the command's time {at_ms} is out of range ({min_ms} to {max_ms})")]
    Time {
        at_ms: u64,
        min_ms: u64,
        max_ms: u64,
    },
    #[error("the state isn't what the step makes")]
    Different,
}

/// A recently applied command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    /// When it may be forgotten.
    pub until_ms: u64,
    /// The answer it got. A proposer that finds its command already applied
    /// returns this answer (see [`ClusterState::applied`]).
    pub response: Response,
}

/// The ID under which an invite is stored: a hash of its secret.
pub fn invite_id(secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("cheesecloth/1 invite", secret)
}

impl ClusterId {
    /// The cluster ID is the hash of the signed genesis command.
    pub fn of_genesis(genesis: &SignedCommand) -> ClusterId {
        ClusterId(blake3::derive_key(
            "cheesecloth/1 cluster",
            &genesis.digest(),
        ))
    }
}

impl ClusterState {
    /// A hash of the whole state.
    pub fn hash(&self) -> [u8; 32] {
        let bytes = postcard::to_stdvec(self).expect("serializable");
        blake3::derive_key("cheesecloth/1 state", &bytes)
    }

    /// Records that this state was made from `from` by `command` (or by
    /// no command, for a change that only names new acceptors).
    pub fn record_step(&mut self, from: &ClusterState, command: Option<Request>) {
        self.step = Some(Step {
            from: from.hash(),
            command,
        });
    }

    /// Checks that `next` is what its recorded step makes from this state.
    /// The step's time must not be earlier than this state's time, nor later
    /// than `latest_ms` (unless this state's time is already later).
    pub fn check_step(&self, next: &ClusterState, latest_ms: u64) -> Result<(), StepError> {
        let step = next.step.as_ref().ok_or(StepError::Missing)?;
        if step.from != self.hash() {
            return Err(StepError::OtherBase);
        }
        let mut expected = self.clone();
        if let Some(req) = &step.command {
            let (min_ms, max_ms) = (self.now_ms, latest_ms.max(self.now_ms));
            if !(min_ms..=max_ms).contains(&req.at_ms) {
                return Err(StepError::Time {
                    at_ms: req.at_ms,
                    min_ms,
                    max_ms,
                });
            }
            // A refused command is still a valid step: it may change the
            // state (see `apply`).
            let _ = expected.apply(req);
        }
        expected.step = next.step.clone();
        if expected != *next {
            return Err(StepError::Different);
        }
        Ok(())
    }

    pub fn settings(&self) -> Option<&Settings> {
        self.settings.as_ref()
    }

    pub fn is_member(&self, node: &NodeId) -> bool {
        self.members.contains_key(node)
    }

    /// Checks that every member record is exactly what that member signed.
    /// Always true for state built by `apply`; used on states received from
    /// other nodes.
    pub fn verify_members(&self) -> Result<(), CommandError> {
        for (id, m) in &self.members {
            let info = open_member_info(&m.signed_info)?;
            if info != m.info || info.node_id != *id {
                return Err(CommandError::InvalidMember(format!(
                    "record for {} doesn't match its signature",
                    id.short()
                )));
            }
        }
        Ok(())
    }

    /// Operator-facing warnings about the agreed membership and settings.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        let n = self.members.len() as u32;
        if let Some(s) = &self.settings
            && s.approvals_required > 0
        {
            if s.approvals_required + 1 > n {
                out.push(format!(
                    "approvals_required is {} but only {n} member(s) exist: joins can no longer \
                     be approved; the cluster must be rebuilt",
                    s.approvals_required
                ));
            } else if s.approvals_required + 2 > n {
                out.push(format!(
                    "approvals_required is {} with {n} member(s): removals can no longer be \
                     approved (members can still leave)",
                    s.approvals_required
                ));
            }
        }
        out
    }

    /// Applies one command.
    pub fn apply(&mut self, req: &Request) -> Response {
        let at = req.at_ms;
        self.now_ms = self.now_ms.max(at);
        self.prune(at);

        let body = req
            .command
            .open(Domain::Command)
            .map_err(|_| CommandError::BadSignature)?;
        if !matches!(body.command, Command::Genesis { .. }) && body.cluster_id != self.cluster_id
            || matches!(body.command, Command::Genesis { .. }) && body.cluster_id.is_some()
        {
            return Err(CommandError::WrongCluster);
        }
        if body.issued_at_ms.abs_diff(at) > ms(REPLAY_WINDOW) {
            return Err(CommandError::Stale);
        }
        let digest = req.command.digest();
        if self.recent.contains_key(&digest) {
            return Err(CommandError::Replay);
        }
        let response = self.run(req, body, at);
        let applied = Applied {
            until_ms: at + 2 * ms(REPLAY_WINDOW),
            response: response.clone(),
        };
        self.recent.insert(digest, applied);
        response
    }

    /// The answer `command` got, if it was applied recently.
    pub fn applied(&self, command: &SignedCommand) -> Option<&Response> {
        self.recent.get(&command.digest()).map(|a| &a.response)
    }

    /// Carries out a command that passed the signature and replay checks.
    fn run(&mut self, req: &Request, body: CommandBody, at: u64) -> Response {
        let signer = req.command.signer;
        if let Command::Genesis {
            settings, founder, ..
        } = &body.command
        {
            return self.genesis(req, signer, settings, founder, at);
        }
        if self.cluster_id.is_none() {
            return Err(CommandError::NotInitialized);
        }
        if !self.is_member(&signer) {
            return Err(CommandError::NotMember);
        }
        match body.command {
            Command::Genesis { .. } => unreachable!("handled above"),
            Command::CreateInvite { invite_id } => Ok(self.create_invite(invite_id, signer, at)),
            Command::RedeemInvite { secret, joiner } => self.redeem(secret, joiner, signer, at),
            Command::ProposeRemove { target } => self.propose_remove(target, signer, at),
            Command::Leave => Ok(self.remove_member(&signer, true)),
            Command::ProposeSetting { change } => self.propose_setting(change, signer, at),
            Command::Approve { proposal } => self.approve(proposal, &req.command, signer, at),
            Command::Reject { proposal } => self.reject(proposal, signer),
            Command::UpdateSelf { info } => self.update_self(info, signer),
            Command::GiveUpAcceptor => Ok(Outcome::GaveUpAcceptor),
        }
    }

    fn genesis(
        &mut self,
        req: &Request,
        signer: NodeId,
        settings: &Settings,
        founder: &Signed<MemberInfo>,
        at: u64,
    ) -> Response {
        if self.cluster_id.is_some() {
            return Err(CommandError::AlreadyInitialized);
        }
        let info = open_member_info(founder)?;
        if info.node_id != signer {
            return Err(CommandError::InvalidMember(
                "founder must sign genesis".into(),
            ));
        }
        self.cluster_id = Some(ClusterId::of_genesis(&req.command));
        self.settings = Some(settings.clone());
        self.next_proposal = 1;
        self.add_member(founder.clone(), info, signer, vec![], at)?;
        Ok(Outcome::Genesis {
            cluster_id: self.cluster_id.expect("just set"),
        })
    }

    fn create_invite(&mut self, invite_id: [u8; 32], signer: NodeId, at: u64) -> Outcome {
        let expires_at_ms = at + ms(INVITE_TTL);
        self.invites.insert(
            invite_id,
            Invite {
                creator: signer,
                created_at_ms: at,
                expires_at_ms,
            },
        );
        Outcome::InviteCreated { expires_at_ms }
    }

    fn redeem(
        &mut self,
        secret: [u8; 32],
        joiner: Signed<MemberInfo>,
        signer: NodeId,
        at: u64,
    ) -> Response {
        // Burn first: whatever happens next, the invite is used up. An
        // expired invite was already pruned, so it's unknown here.
        self.invites
            .remove(&invite_id(&secret))
            .ok_or(CommandError::InviteUnknown)?;
        let info = open_member_info(&joiner)?;
        if self.is_member(&info.node_id) {
            return Err(CommandError::AlreadyMember);
        }
        let pending = self.proposals.values().any(
            |p| matches!(&p.kind, ProposalKind::Join { joiner } if joiner.signer == info.node_id),
        );
        if pending {
            return Err(CommandError::AlreadyPending);
        }
        self.check_wg_key_free(&info)?;
        if self.required() == 0 {
            let node = info.node_id;
            let ipv4 = self.add_member(joiner, info, signer, vec![], at)?;
            Ok(Outcome::Joined { node, ipv4 })
        } else {
            Ok(self.propose(ProposalKind::Join { joiner }, signer, at))
        }
    }

    fn propose_remove(&mut self, target: NodeId, signer: NodeId, at: u64) -> Response {
        if target == signer {
            return Ok(self.remove_member(&target, true));
        }
        if !self.is_member(&target) {
            return Err(CommandError::NoSuchMember);
        }
        if self.required() == 0 {
            Ok(self.remove_member(&target, false))
        } else {
            Ok(self.propose(ProposalKind::Remove { target }, signer, at))
        }
    }

    fn propose_setting(&mut self, change: SettingChange, signer: NodeId, at: u64) -> Response {
        self.validate_setting(&change)?;
        if self.required() == 0 {
            self.apply_setting(&change);
            Ok(Outcome::SettingChanged)
        } else {
            Ok(self.propose(ProposalKind::Setting { change }, signer, at))
        }
    }

    /// Records a signed approval, and executes the proposal once it has enough.
    fn approve(
        &mut self,
        id: crate::ProposalId,
        command: &SignedCommand,
        signer: NodeId,
        at: u64,
    ) -> Response {
        let required = self.required();
        let p = self
            .proposals
            .get_mut(&id)
            .ok_or(CommandError::NoSuchProposal)?;
        if p.proposer == signer {
            return Err(CommandError::OwnProposal);
        }
        if matches!(p.kind, ProposalKind::Remove { target } if target == signer) {
            return Err(CommandError::OwnRemoval);
        }
        if p.approvals.contains_key(&signer) {
            return Err(CommandError::AlreadyApproved);
        }
        p.approvals.insert(signer, command.clone());
        let have = p.approvals.len() as u32;
        if have < required {
            return Ok(Outcome::Approved {
                proposal: id,
                remaining: required - have,
            });
        }
        let p = self.proposals.remove(&id).expect("present");
        self.execute(p, at)
    }

    fn reject(&mut self, id: crate::ProposalId, signer: NodeId) -> Response {
        let p = self
            .proposals
            .get(&id)
            .ok_or(CommandError::NoSuchProposal)?;
        if matches!(p.kind, ProposalKind::Remove { target } if target == signer) {
            return Err(CommandError::OwnRemoval);
        }
        self.proposals.remove(&id);
        Ok(Outcome::Rejected { proposal: id })
    }

    fn update_self(&mut self, signed: Signed<MemberInfo>, signer: NodeId) -> Response {
        let info = open_member_info(&signed)?;
        if info.node_id != signer {
            return Err(CommandError::InvalidMember("can only update itself".into()));
        }
        let member = self.members.get_mut(&signer).expect("checked");
        if member.info.wg_key != info.wg_key {
            return Err(CommandError::InvalidMember(
                "the WireGuard key can't be changed".into(),
            ));
        }
        member.info = info;
        member.signed_info = signed;
        Ok(Outcome::Updated)
    }

    fn required(&self) -> u32 {
        self.settings.as_ref().map_or(0, |s| s.approvals_required)
    }

    fn prune(&mut self, at: u64) {
        self.recent.retain(|_, a| a.until_ms >= at);
        self.invites.retain(|_, i| i.expires_at_ms >= at);
        self.proposals.retain(|_, p| p.expires_at_ms >= at);
    }

    fn propose(&mut self, kind: ProposalKind, proposer: NodeId, at: u64) -> Outcome {
        // Bind creation context once; subsequent approvals do not change the ID.
        let descriptor = postcard::to_stdvec(&(
            self.cluster_id,
            self.hash(),
            self.next_proposal,
            &kind,
            proposer,
            at,
            at + ms(PROPOSAL_TTL),
        ))
        .expect("serializable proposal");
        let mut token = *blake3::hash(&descriptor).as_bytes();
        // Eight bytes for catch-up ordering, 192 bits binding the descriptor.
        token[..8].copy_from_slice(&self.next_proposal.to_be_bytes());
        let id = crate::ProposalId(token);
        self.next_proposal += 1;
        self.proposals.insert(
            id,
            Proposal {
                id,
                kind,
                proposer,
                created_at_ms: at,
                expires_at_ms: at + ms(PROPOSAL_TTL),
                approvals: BTreeMap::new(),
            },
        );
        Outcome::Pending { proposal: id }
    }

    fn execute(&mut self, p: Proposal, at: u64) -> Response {
        let approvers: Vec<NodeId> = p.approvals.keys().copied().collect();
        match p.kind {
            ProposalKind::Join { joiner } => {
                let info = open_member_info(&joiner)?;
                if self.is_member(&info.node_id) {
                    return Err(CommandError::AlreadyMember);
                }
                let node = info.node_id;
                let ipv4 = self.add_member(joiner, info, p.proposer, approvers, at)?;
                Ok(Outcome::Joined { node, ipv4 })
            }
            ProposalKind::Remove { target } => {
                if !self.is_member(&target) {
                    return Err(CommandError::NoSuchMember);
                }
                Ok(self.remove_member(&target, false))
            }
            ProposalKind::Setting { change } => {
                self.validate_setting(&change)?;
                self.apply_setting(&change);
                Ok(Outcome::SettingChanged)
            }
        }
    }

    fn validate_setting(&self, change: &SettingChange) -> Result<(), CommandError> {
        match change {
            SettingChange::ApprovalsRequired(n) => {
                let possible = self.members.len() as u32 - 1;
                if *n > possible {
                    return Err(CommandError::InvalidSetting(format!(
                        "approvals_required can be at most {possible} with {} member(s)",
                        self.members.len()
                    )));
                }
            }
            SettingChange::Acceptors(v) => {
                if !(1..=7).contains(v) {
                    return Err(CommandError::InvalidSetting(
                        "acceptors must be between 1 and 7".into(),
                    ));
                }
            }
            SettingChange::StrictSecurity(_) => {}
            SettingChange::BufferNodes(n) => {
                if *n > 3 {
                    return Err(CommandError::InvalidSetting(
                        "buffer_nodes must be at most 3 (the reserve of seven relaxed voters)"
                            .into(),
                    ));
                }
            }
            SettingChange::CatchUpDays(d) => {
                if !(1..=MAX_CATCH_UP_DAYS).contains(d) {
                    return Err(CommandError::InvalidSetting(format!(
                        "catch_up_days must be 1 to {MAX_CATCH_UP_DAYS}"
                    )));
                }
            }
        }
        Ok(())
    }

    fn apply_setting(&mut self, change: &SettingChange) {
        let s = self.settings.as_mut().expect("initialized");
        match change {
            SettingChange::ApprovalsRequired(n) => s.approvals_required = *n,
            SettingChange::Acceptors(v) => s.acceptors = *v,
            SettingChange::StrictSecurity(v) => s.strict_security = *v,
            SettingChange::BufferNodes(v) => s.buffer_nodes = *v,
            SettingChange::CatchUpDays(d) => s.catch_up_days = *d,
        }
    }

    fn add_member(
        &mut self,
        signed_info: Signed<MemberInfo>,
        info: MemberInfo,
        added_by: NodeId,
        approved_by: Vec<NodeId>,
        at: u64,
    ) -> Result<Ipv4Addr, CommandError> {
        self.check_wg_key_free(&info)?;
        let range = self.settings.as_ref().expect("initialized").ipv4_range;
        let used: BTreeSet<Ipv4Addr> = self.members.values().map(|m| m.ipv4).collect();
        let ipv4 = range
            .hosts()
            .find(|ip| !used.contains(ip))
            .ok_or(CommandError::RangeFull(range))?;
        self.members.insert(
            info.node_id,
            Member {
                info,
                signed_info,
                ipv4,
                added_at_ms: at,
                added_by,
                approved_by,
            },
        );
        Ok(ipv4)
    }

    /// WireGuard identifies peers by key, so two members can't share one.
    fn check_wg_key_free(&self, info: &MemberInfo) -> Result<(), CommandError> {
        if self
            .members
            .values()
            .any(|m| m.info.wg_key == info.wg_key && m.info.node_id != info.node_id)
        {
            return Err(CommandError::InvalidMember(
                "that WireGuard key already belongs to another member".into(),
            ));
        }
        Ok(())
    }

    fn remove_member(&mut self, node: &NodeId, left: bool) -> Outcome {
        self.members.remove(node);
        // Proposals about the node, and its approvals, no longer count.
        self.proposals.retain(|_, p| {
            !matches!(p.kind, ProposalKind::Remove { target } if target == *node)
                && p.proposer != *node
        });
        for p in self.proposals.values_mut() {
            p.approvals.remove(node);
        }
        self.invites.retain(|_, i| i.creator != *node);
        if left {
            Outcome::Left { node: *node }
        } else {
            Outcome::Removed { node: *node }
        }
    }
}

fn open_member_info(signed: &Signed<MemberInfo>) -> Result<MemberInfo, CommandError> {
    let info = signed
        .open(Domain::MemberInfo)
        .map_err(|_| CommandError::BadSignature)?;
    if info.node_id != signed.signer {
        return Err(CommandError::InvalidMember(
            "member info must be signed by the member".into(),
        ));
    }
    if info.name.len() > MAX_NAME_LEN {
        return Err(CommandError::InvalidMember(format!(
            "the name is longer than {MAX_NAME_LEN} bytes"
        )));
    }
    if info.control_addrs.len() > MAX_CONTROL_ADDRS {
        return Err(CommandError::InvalidMember(format!(
            "more than {MAX_CONTROL_ADDRS} control-plane addresses"
        )));
    }
    Ok(info)
}

#[cfg(test)]
mod tests;
