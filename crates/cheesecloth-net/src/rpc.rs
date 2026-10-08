//! Requests: direct calls, routing through relays, the relay and destination
//! sides of forwarding, replay protection, soft-state pushes and joins.

use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use cheesecloth_core::{ClusterId, Domain, NodeId, Signed, now_ms, token::TokenPeer};
use quinn::{Connection, VarInt};
use tracing::debug;

use crate::{
    CallError, Handler, Net, tls,
    wire::{DirectRequest, Envelope, ForwardOutcome, ForwardRequest, Kind, MAX_MESSAGE, header},
};

/// Forwarded messages older than this (by their sequence number's clock) are refused.
const FORWARD_WINDOW_MS: u64 = 10 * 60 * 1000;
/// A join waits for a change to be agreed on the member's side, so it gets
/// longer.
const JOIN_TIMEOUT: Duration = Duration::from_secs(60);

impl Net {
    /// Sends one request on a new stream and waits for the answer.
    ///
    /// The peer acts on a request only once it has all of it (the stream's
    /// end), so anything that fails before `finish` is `NotSent`, and anything
    /// after is `Lost`.
    pub(crate) async fn call(
        &self,
        conn: &Connection,
        kind: Kind,
        cluster: ClusterId,
        body: &[u8],
    ) -> Result<Vec<u8>, CallError> {
        let limit = if kind == Kind::Join {
            crate::wire::MAX_JOIN_MESSAGE
        } else {
            MAX_MESSAGE
        };
        if body.len() > limit {
            return Err(CallError::NotSent(anyhow!(
                "encoded request exceeds the wire limit"
            )));
        }
        let not_sent = |e: &dyn std::fmt::Display| CallError::NotSent(anyhow!("{e}"));
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| not_sent(&e))?;
        let t0 = now_ms();
        send.write_all(&header(kind, cluster))
            .await
            .map_err(|e| not_sent(&e))?;
        send.write_all(body).await.map_err(|e| not_sent(&e))?;
        send.finish().map_err(|e| not_sent(&e))?;
        let lost = |e: &dyn std::fmt::Display| CallError::Lost(anyhow!("{e}"));
        let buf = recv.read_to_end(MAX_MESSAGE).await.map_err(|e| lost(&e))?;
        let t1 = now_ms();
        if buf.len() < 8 {
            return Err(lost(&"short response"));
        }
        let theirs = u64::from_be_bytes(buf[..8].try_into().expect("8 bytes"));
        if let Ok(peer) = tls::peer_id(conn)
            && self.dir().is_member(&peer)
        {
            self.record_clock(peer, theirs as i64 - ((t0 + t1) / 2) as i64);
        }
        let res: Result<Vec<u8>, String> = postcard::from_bytes(&buf[8..]).map_err(|e| lost(&e))?;
        res.map_err(CallError::Remote)
    }

    pub(crate) fn next_seq(&self) -> u64 {
        let base = now_ms() << 16;
        let mut cur = self.0.seq.load(Ordering::Relaxed);
        loop {
            let next = base.max(cur + 1);
            match self
                .0
                .seq
                .compare_exchange(cur, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return next,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Sends a request to a member: directly when possible, otherwise through
    /// a relay.
    pub async fn request(
        &self,
        to: NodeId,
        service: u8,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        tokio::time::timeout(timeout, self.request_inner(to, service, body))
            .await
            .map_err(|_| anyhow!("request to {} timed out", to.short()))?
    }

    pub(crate) async fn request_inner(
        &self,
        to: NodeId,
        service: u8,
        body: Vec<u8>,
    ) -> Result<Vec<u8>> {
        ensure!(
            body.len() <= crate::MAX_PAYLOAD,
            "payload exceeds the wire budget"
        );
        let cluster = self.cluster_id().context("not in a cluster")?;
        if to == self.0.me {
            return self
                .0
                .handler
                .request(to, service, body)
                .await
                .map_err(|e| anyhow!(e));
        }
        // Directly if possible. Only a request that certainly didn't reach
        // the peer is tried again through a relay: a lost answer might mean
        // it already ran.
        let direct = match self.connect(to).await {
            Ok(conn) => {
                let req = postcard::to_stdvec(&DirectRequest {
                    service,
                    body: body.clone(),
                })?;
                match self.call(&conn, Kind::Direct, cluster, &req).await {
                    Ok(r) => return Ok(r),
                    Err(CallError::NotSent(e)) => e,
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => e,
        };
        let forwarders = self.dir().forwarders(&to);
        let mut errors = vec![format!("direct: {direct:#}")];
        for via in forwarders {
            if via == self.0.me || via == to {
                continue;
            }
            match self
                .forward_via(via, to, service, body.clone(), false)
                .await
            {
                Ok(Some(r)) => return Ok(r),
                Ok(None) => bail!("relay returned no response"),
                Err(CallError::NotSent(e)) => errors.push(format!("via {}: {e:#}", via.short())),
                Err(e) => return Err(e.into()),
            }
        }
        bail!("no route to {}: {}", to.short(), errors.join("; "))
    }

    /// Sends a message to `to` through the relay `via`.
    ///
    /// With `synchronized`, the relay doesn't wait for the destination's
    /// response. It times its delivery and its (empty) response to us so both
    /// arrive at the same moment, using its RTT measurements to each side.
    pub async fn forward_via(
        &self,
        via: NodeId,
        to: NodeId,
        service: u8,
        body: Vec<u8>,
        synchronized: bool,
    ) -> Result<Option<Vec<u8>>, CallError> {
        let not_sent = |e: anyhow::Error| CallError::NotSent(e);
        let cluster = self
            .cluster_id()
            .context("not in a cluster")
            .map_err(not_sent)?;
        let seq = self.next_seq();
        let envelope = self.0.identity.seal(
            Domain::Forwarded,
            &Envelope {
                cluster,
                from: self.0.me,
                to,
                seq,
                reply_to: None,
                service,
                body,
            },
        );
        let conn = self.connect(via).await.map_err(not_sent)?;
        let req = postcard::to_stdvec(&ForwardRequest {
            envelope,
            synchronized,
        })
        .map_err(|e| not_sent(e.into()))?;
        let outcome = match self.call(&conn, Kind::Forward, cluster, &req).await {
            Ok(bytes) => postcard::from_bytes::<ForwardOutcome>(&bytes)
                .map_err(|e| CallError::Lost(e.into()))?,
            // The relay itself refused the message: nothing was delivered.
            Err(CallError::Remote(e)) => return Err(not_sent(anyhow!("relay refused: {e}"))),
            Err(e) => return Err(e),
        };
        let signed = match outcome {
            ForwardOutcome::Answered(Some(signed)) => signed,
            ForwardOutcome::Answered(None) if synchronized => return Ok(None),
            ForwardOutcome::Answered(None) => {
                return Err(CallError::Lost(anyhow!("relay returned no response")));
            }
            ForwardOutcome::Refused(e) => return Err(CallError::Remote(e)),
            ForwardOutcome::NotDelivered(e) => return Err(not_sent(anyhow!("{e}"))),
            ForwardOutcome::Lost(e) => return Err(CallError::Lost(anyhow!("{e}"))),
        };
        // The destination answered; if the answer doesn't check out, treat it
        // as lost (the request may have run).
        let bad = |why: &str| CallError::Lost(anyhow!("{why}"));
        let env = signed
            .open(Domain::Forwarded)
            .map_err(|_| bad("badly signed response"))?;
        if !(signed.signer == to && env.from == to && env.to == self.0.me) {
            return Err(bad("response from the wrong node"));
        }
        if !(env.cluster == cluster && env.reply_to == Some(seq)) {
            return Err(bad("mismatched response"));
        }
        Ok(Some(env.body))
    }

    /// Relay side of a forward. Errors before anything is sent to the
    /// destination are returned as errors (the origin may try another relay);
    /// what happened after that is reported in the `ForwardOutcome`.
    pub(crate) async fn relay(
        &self,
        from_conn: &Connection,
        peer: NodeId,
        req: ForwardRequest,
    ) -> Result<Vec<u8>> {
        ensure!(
            self.dir().is_relay(&self.0.me),
            "relaying is disabled on this node"
        );
        let env = req.envelope.open(Domain::Forwarded)?;
        ensure!(
            req.envelope.signer == peer && env.from == peer,
            "can only forward own messages"
        );
        ensure!(self.dir().is_member(&env.to), "destination is not a member");
        let to_conn = self
            .live(&env.to)
            .context("destination not connected to this relay")?;
        let cluster = self.cluster_id().context("not in a cluster")?;
        let body = postcard::to_stdvec(&req.envelope)?;
        if req.synchronized {
            // One-way delay estimates: half of each connection's RTT.
            let d_from = from_conn.rtt() / 2;
            let d_to = to_conn.rtt() / 2;
            let net = self.clone();
            let deliver_after = d_from.saturating_sub(d_to);
            tokio::spawn(async move {
                tokio::time::sleep(deliver_after).await;
                if let Err(e) = net.call(&to_conn, Kind::Deliver, cluster, &body).await {
                    debug!("synchronized delivery failed: {e:#}");
                }
            });
            tokio::time::sleep(d_to.saturating_sub(d_from)).await;
            return Ok(postcard::to_stdvec(&ForwardOutcome::Answered(None))?);
        }
        let outcome = match self.call(&to_conn, Kind::Deliver, cluster, &body).await {
            Ok(resp) => match postcard::from_bytes::<Signed<Envelope>>(&resp) {
                Ok(signed) => ForwardOutcome::Answered(Some(signed)),
                Err(e) => ForwardOutcome::Lost(format!("unreadable answer: {e}")),
            },
            Err(CallError::Remote(e)) => ForwardOutcome::Refused(e),
            Err(CallError::NotSent(e)) => ForwardOutcome::NotDelivered(format!("{e:#}")),
            Err(CallError::Lost(e)) => ForwardOutcome::Lost(format!("{e:#}")),
        };
        Ok(postcard::to_stdvec(&outcome)?)
    }

    /// Destination side of a forward.
    pub(crate) async fn deliver(
        &self,
        handler: Arc<dyn Handler>,
        signed: Signed<Envelope>,
    ) -> Result<Vec<u8>> {
        let env = signed.open(Domain::Forwarded)?;
        let cluster = self.cluster_id().context("not in a cluster")?;
        ensure!(env.cluster == cluster, "wrong cluster");
        ensure!(env.to == self.0.me, "not addressed to this node");
        ensure!(signed.signer == env.from, "sender mismatch");
        ensure!(self.dir().is_member(&env.from), "sender is not a member");
        self.check_fresh(env.from, env.seq)?;
        // The envelope's sequence number carries the sender's clock.
        self.record_clock(env.from, (env.seq >> 16) as i64 - now_ms() as i64);
        let body = handler
            .request(env.from, env.service, env.body)
            .await
            .map_err(|e| anyhow!(e))?;
        let reply = self.0.identity.seal(
            Domain::Forwarded,
            &Envelope {
                cluster,
                from: self.0.me,
                to: env.from,
                seq: self.next_seq(),
                reply_to: Some(env.seq),
                service: env.service,
                body,
            },
        );
        Ok(postcard::to_stdvec(&reply)?)
    }

    /// Refuses a forwarded message that is too old or was already seen.
    pub(crate) fn check_fresh(&self, from: NodeId, seq: u64) -> Result<()> {
        let now = now_ms();
        let sent = seq >> 16;
        ensure!(
            sent.abs_diff(now) <= FORWARD_WINDOW_MS,
            "message outside the replay window"
        );
        let mut seen = self.0.seen.lock();
        let set = seen.entry(from).or_default();
        let oldest = now.saturating_sub(FORWARD_WINDOW_MS) << 16;
        while set.first().is_some_and(|s| *s < oldest) {
            set.pop_first();
        }
        ensure!(set.insert(seq), "replayed message");
        Ok(())
    }

    /// Pushes soft state to a connected member. Never dials.
    pub async fn push_state(&self, to: NodeId, body: &[u8]) -> Result<()> {
        ensure!(
            body.len() <= crate::MAX_PAYLOAD,
            "payload exceeds the wire budget"
        );
        let cluster = self.cluster_id().context("not in a cluster")?;
        let conn = self.live(&to).context("not connected")?;
        let mut send = conn.open_uni().await?;
        send.write_all(&header(Kind::State, cluster)).await?;
        send.write_all(body).await?;
        send.finish()?;
        Ok(())
    }

    /// Redeems an invite (or asks about a pending join): dials one of the
    /// listed members, pinning its key. A timeout counts as `Lost`: the
    /// request may have been delivered.
    pub async fn join(
        &self,
        cluster: ClusterId,
        peer: &TokenPeer,
        body: &[u8],
    ) -> Result<Vec<u8>, CallError> {
        tokio::time::timeout(JOIN_TIMEOUT, self.join_inner(cluster, peer, body))
            .await
            .map_err(|_| {
                CallError::Lost(anyhow!(
                    "no answer from {} within {JOIN_TIMEOUT:?}",
                    peer.node_id.short()
                ))
            })?
    }

    pub(crate) async fn join_inner(
        &self,
        cluster: ClusterId,
        peer: &TokenPeer,
        body: &[u8],
    ) -> Result<Vec<u8>, CallError> {
        if let Some(conn) = self.live(&peer.node_id) {
            return self.call(&conn, Kind::Join, cluster, body).await;
        }
        // A connection just for this exchange. Neither side uses it for
        // anything else, so close it once the answer is in.
        let conn = self
            .dial_any(peer.node_id, &peer.addrs, tls::SERVER_NAME)
            .await
            .map_err(CallError::NotSent)?;
        let res = self.call(&conn, Kind::Join, cluster, body).await;
        conn.close(VarInt::from_u32(0), b"done");
        res
    }
}
