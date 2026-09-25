//! The member side of joining: redeeming invites, and answering joiners who
//! ask about their join (including retries after a lost answer).

use std::time::Duration;

use anyhow::{Context, Result, bail};
use cheesecloth_core::{
    NodeId,
    state::{ClusterState, Command, CommandError, Outcome, ProposalKind},
};
use tracing::info;

use super::Node;
use crate::proto::{JoinMessage, JoinReply};

impl Node {
    pub(super) async fn join_request(&self, from: NodeId, msg: JoinMessage) -> Result<JoinReply> {
        match msg {
            JoinMessage::Redeem { secret, info } => {
                if info.signer != from {
                    bail!("the member record must be signed by the connecting key");
                }
                info!(joiner = %from.short(), "redeeming an invite");
                // Always submitted, so a live token is burnt whatever happens.
                let res = self
                    .submit(Command::RedeemInvite {
                        secret,
                        joiner: info,
                    })
                    .await;
                let e = match res {
                    Ok(Outcome::Joined { .. }) => return self.joined_reply(from).await,
                    Ok(Outcome::Pending { proposal }) => {
                        return Ok(JoinReply::Pending { proposal });
                    }
                    Ok(other) => bail!("unexpected outcome {other:?}"),
                    Err(e) => e,
                };
                // A joiner retries when an answer was lost. If its first
                // redemption went through, answer as that one would have.
                let retry_of_success = matches!(
                    e.downcast_ref::<CommandError>(),
                    Some(
                        CommandError::AlreadyMember
                            | CommandError::AlreadyPending
                            | CommandError::InviteUnknown
                    )
                );
                if retry_of_success && let Some(reply) = self.earlier_redemption(from).await? {
                    return Ok(reply);
                }
                Err(e)
            }
            JoinMessage::Status { proposal } => {
                if self.is_member(&from) {
                    return self.joined_reply(from).await;
                }
                let agreed = self.agreed();
                let st = agreed.state();
                let pending = st.proposals.get(&proposal).is_some_and(
                    |p| matches!(&p.kind, ProposalKind::Join { joiner } if joiner.signer == from),
                );
                // A member that hasn't seen the proposal yet is behind; it
                // mustn't tell the joiner to give up.
                let not_seen_yet = proposal.sequence() >= st.next_proposal;
                Ok(if pending || not_seen_yet {
                    JoinReply::Pending { proposal }
                } else {
                    JoinReply::Rejected {
                        reason: "the join was rejected or expired".into(),
                    }
                })
            }
        }
    }

    /// The join a node already has, if any: it's a member, or its join is
    /// waiting for approvals. The refusal that led here was agreed, so this
    /// node's state already has the earlier redemption.
    async fn earlier_redemption(&self, joiner: NodeId) -> Result<Option<JoinReply>> {
        if self.is_member(&joiner) {
            return self.joined_reply(joiner).await.map(Some);
        }
        let st = self.agreed();
        let pending = |st: &ClusterState| {
            st.proposals.values().find_map(|p| match &p.kind {
                ProposalKind::Join { joiner: j } if j.signer == joiner => Some(p.id),
                _ => None,
            })
        };
        Ok(pending(st.state()).map(|proposal| JoinReply::Pending { proposal }))
    }

    /// Waits until the local state has the new member, then sends the state
    /// and a bounded seed of current addresses.
    async fn joined_reply(&self, joiner: NodeId) -> Result<JoinReply> {
        let mut rx = self.state.subscribe();
        let wait = rx.wait_for(|a| a.state().is_member(&joiner));
        tokio::time::timeout(Duration::from_secs(10), wait)
            .await
            .context("timed out waiting to learn the join")??;
        let proven = self.proven(u64::MAX).await;
        Ok(JoinReply::Joined {
            cluster_id: self.cluster_id,
            state: Box::new(proven.chosen),
            cert: Box::new(proven.cert),
            soft: self.soft.lock().seed(self.me),
        })
    }
}
