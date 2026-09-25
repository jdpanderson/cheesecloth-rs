//! Cluster commands: invites, removal, approvals and settings.

use anyhow::{Context, Result, bail};
use cheesecloth_core::{
    Domain, NodeId, now_ms,
    state::{Command, MemberInfo, Outcome, ProposalKind, SettingChange},
    token::{InviteToken, TOKEN_PEERS, TokenPeer},
};

use crate::{
    Daemon,
    api::{ConfigView, InviteView, ProposalView},
    node::Node,
};

impl Daemon {
    pub async fn invite(&self) -> Result<InviteView> {
        let node = self.require_node()?;
        let secret: [u8; 32] = rand::random();
        let outcome = node
            .submit(Command::CreateInvite {
                invite_id: cheesecloth_core::state::invite_id(&secret),
            })
            .await?;
        let Outcome::InviteCreated { expires_at_ms } = outcome else {
            bail!("unexpected outcome {outcome:?}");
        };
        // List this node first: only a member that knows the invite takes
        // the redemption to consensus, and this node knows it. Then relays,
        // then others.
        let me = self.node_id();
        let mut members: Vec<(bool, bool, NodeId)> = node
            .agreed()
            .value
            .value
            .members
            .keys()
            .map(|id| (*id != me, !node.is_relay(id), *id))
            .collect();
        members.sort();
        let peers: Vec<TokenPeer> = members
            .into_iter()
            .map(|(_, _, id)| TokenPeer {
                node_id: id,
                addrs: node.control_addrs_of(&id),
            })
            .filter(|p| !p.addrs.is_empty())
            .take(TOKEN_PEERS)
            .collect();
        let token = InviteToken {
            cluster_id: node.cluster_id,
            secret,
            peers,
        };
        Ok(InviteView {
            token: token.to_string(),
            expires_at_ms,
        })
    }

    fn resolve_node(&self, node: &Node, prefix: &str) -> Result<NodeId> {
        let prefix = prefix.to_lowercase();
        let matches: Vec<NodeId> = node
            .agreed()
            .value
            .value
            .members
            .iter()
            .filter(|(id, m)| {
                id.to_string().starts_with(&prefix) || m.info.name.to_lowercase() == prefix
            })
            .map(|(id, _)| *id)
            .collect();
        match matches.as_slice() {
            [one] => Ok(*one),
            [] => bail!("no member matches {prefix:?}"),
            _ => bail!("{prefix:?} matches several members; use more of the node ID"),
        }
    }

    pub async fn remove(&self, target: &str) -> Result<Outcome> {
        let node = self.require_node()?;
        let target = self.resolve_node(&node, target)?;
        if target == self.node_id() {
            bail!("use `cheesecloth leave` to remove this node");
        }
        node.submit(Command::ProposeRemove { target }).await
    }

    // ---------------------------------------------------- approvals

    pub fn pending(&self) -> Result<Vec<ProposalView>> {
        let node = self.require_node()?;
        let agreed = node.agreed();
        let st = agreed.state();
        let needed = st.settings().map_or(0, |s| s.approvals_required);
        let now = now_ms();
        Ok(st
            .proposals
            .values()
            .map(|p| {
                let (kind, n, name, setting) = match &p.kind {
                    ProposalKind::Join { joiner } => {
                        let info = joiner.open(Domain::MemberInfo).ok();
                        (
                            "join",
                            Some(joiner.signer),
                            info.map(|i: MemberInfo| i.name),
                            None,
                        )
                    }
                    ProposalKind::Remove { target } => (
                        "remove",
                        Some(*target),
                        st.members.get(target).map(|m| m.info.name.clone()),
                        None,
                    ),
                    ProposalKind::Setting { change } => {
                        ("setting", None, None, Some(format!("{change:?}")))
                    }
                };
                ProposalView {
                    id: p.id,
                    kind: kind.into(),
                    node: n,
                    name,
                    setting,
                    proposer: p.proposer,
                    approvals: p.approvals.keys().copied().collect(),
                    needed,
                    expires_in_secs: p.expires_at_ms.saturating_sub(now) / 1000,
                }
            })
            .collect())
    }

    pub async fn vote(
        &self,
        proposal: cheesecloth_core::ProposalId,
        approve: bool,
    ) -> Result<Outcome> {
        let node = self.require_node()?;
        let cmd = if approve {
            Command::Approve { proposal }
        } else {
            Command::Reject { proposal }
        };
        node.submit(cmd).await
    }

    // ------------------------------------------------------ settings

    pub fn config_get(&self) -> Result<ConfigView> {
        let node = self.require_node()?;
        let agreed = node.agreed();
        let s = agreed.state().settings().context("no settings")?;
        Ok(ConfigView {
            approvals_required: s.approvals_required,
            acceptors: s.acceptors,
            strict_security: s.strict_security,
            buffer_nodes: s.buffer_nodes,
            catch_up_days: s.catch_up_days,
            ipv4_range: s.ipv4_range,
            ipv6_prefix: cheesecloth_core::addr::ula_prefix(&node.cluster_id).to_string(),
        })
    }

    pub async fn config_set(&self, key: &str, value: &str) -> Result<Outcome> {
        let node = self.require_node()?;
        let change = match key {
            "approvals_required" => {
                SettingChange::ApprovalsRequired(value.parse().context("expected a number")?)
            }
            "strict_security" => {
                SettingChange::StrictSecurity(value.parse().context("expected true or false")?)
            }
            "buffer_nodes" => {
                SettingChange::BufferNodes(value.parse().context("expected a number")?)
            }
            "acceptors" => SettingChange::Acceptors(value.parse().context("expected a number")?),
            "catch_up_days" => {
                SettingChange::CatchUpDays(value.parse().context("expected a number of days")?)
            }
            "ipv4_range" => bail!("the IPv4 range is fixed once the cluster exists"),
            _ => bail!(
                "unknown setting {key:?} (known: approvals_required, acceptors, catch_up_days, strict_security, buffer_nodes)"
            ),
        };
        node.submit(Command::ProposeSetting { change }).await
    }
}
