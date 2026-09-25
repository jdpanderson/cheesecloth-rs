//! Connections: the table of live member connections, dialling, accepting,
//! serving the streams a peer opens, and limits on non-members ("guests").

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use cheesecloth_core::{ClusterId, NodeId, Signed, now_ms};
use parking_lot::Mutex;
use quinn::{Connection, VarInt};
use tracing::{debug, trace};

use crate::{
    ConnInfo, Net, canonical, tls,
    wire::{
        DirectRequest, Envelope, ForwardRequest, HEADER_LEN, Kind, MAX_JOIN_MESSAGE, MAX_MESSAGE,
        ProbeRequest,
    },
};

pub(crate) const DIAL_TIMEOUT: Duration = Duration::from_secs(4);
/// After a failed dial, don't dial the same node again for this long.
const DIAL_BACKOFF: Duration = Duration::from_secs(15);
/// A guest only needs one join request at a time.
pub(crate) const GUEST_BI_STREAMS: u32 = 2;
/// Enough for a full join request on each guest stream.
pub(crate) const GUEST_RECEIVE_WINDOW: u32 = 4 * MAX_JOIN_MESSAGE as u32;

/// A guest's place in the count of guests; released when dropped.
struct GuestSlot {
    net: Net,
    addr: IpAddr,
}

impl Drop for GuestSlot {
    fn drop(&mut self) {
        let mut g = self.net.0.guests.lock();
        g.0 -= 1;
        if let Some(n) = g.1.get_mut(&self.addr) {
            *n -= 1;
            if *n == 0 {
                g.1.remove(&self.addr);
            }
        }
    }
}

/// The address guests are counted by: IPv4 as is, IPv6 by its /64, which
/// one host can easily have to itself.
fn guest_addr(remote: SocketAddr) -> IpAddr {
    match canonical(remote).ip() {
        IpAddr::V6(v6) => {
            let bits = u128::from(v6) & !((1u128 << 64) - 1);
            IpAddr::V6(Ipv6Addr::from(bits))
        }
        v4 => v4,
    }
}

/// Raises a guest's limits to a member's: quinn's defaults.
fn member_limits(conn: &Connection) {
    conn.set_max_concurrent_bi_streams(100u32.into());
    conn.set_max_concurrent_uni_streams(100u32.into());
    conn.set_receive_window(VarInt::MAX);
}

/// A stream the peer opened.
enum Stream {
    Bi(quinn::SendStream, quinn::RecvStream),
    Uni(quinn::RecvStream),
}

/// The next stream the peer opens, or `None` once the connection is closed.
async fn next_stream(conn: &Connection) -> Option<Stream> {
    tokio::select! {
        bi = conn.accept_bi() => bi.ok().map(|(send, recv)| Stream::Bi(send, recv)),
        uni = conn.accept_uni() => uni.ok().map(Stream::Uni),
    }
}

impl Net {
    /// Live connections to members.
    pub fn connections(&self) -> Vec<ConnInfo> {
        let conns = self.0.conns.lock();
        conns
            .iter()
            .filter(|(_, c)| c.close_reason().is_none())
            .map(|(node, c)| ConnInfo {
                node: *node,
                remote: canonical(c.remote_address()),
                rtt_ms: c.rtt().as_millis() as u64,
            })
            .collect()
    }

    pub fn is_connected(&self, node: &NodeId) -> bool {
        self.live(node).is_some()
    }

    /// Closes the connection to a node, e.g. one that was removed.
    pub fn disconnect(&self, node: &NodeId) {
        if let Some(c) = self.0.conns.lock().remove(node) {
            c.close(VarInt::from_u32(1), b"removed");
        }
    }

    pub(crate) fn live(&self, node: &NodeId) -> Option<Connection> {
        let conns = self.0.conns.lock();
        conns
            .get(node)
            .filter(|c| c.close_reason().is_none())
            .cloned()
    }

    pub(crate) fn insert(&self, node: NodeId, conn: Connection) {
        let old = self.0.conns.lock().insert(node, conn);
        // An older connection stays up until it idles out; it's still served.
        drop(old);
        self.0.dial_failed.lock().remove(&node);
        if let Some(h) = self.0.handler.get() {
            h.connected(node);
        }
    }

    /// A connection to `node`: the existing one, or a new direct dial.
    pub async fn connect(&self, node: NodeId) -> Result<Connection> {
        if let Some(c) = self.live(&node) {
            return Ok(c);
        }
        let lock = {
            let mut locks = self.0.dial_locks.lock();
            locks.entry(node).or_default().clone()
        };
        let _guard = lock.lock().await;
        if let Some(c) = self.live(&node) {
            return Ok(c);
        }
        if let Some(t) = self.0.dial_failed.lock().get(&node)
            && t.elapsed() < DIAL_BACKOFF
        {
            bail!("{} was unreachable recently", node.short());
        }
        let addrs = self.dir().map(|d| d.dial_addrs(&node)).unwrap_or_default();
        if addrs.is_empty() {
            bail!("no address to dial {}", node.short());
        }
        match self.dial_any(node, &addrs, tls::SERVER_NAME).await {
            Ok(conn) => {
                debug!(peer = %node.short(), remote = %conn.remote_address(), "connected");
                member_limits(&conn);
                self.insert(node, conn.clone());
                tokio::spawn(self.clone().serve(conn.clone(), node));
                Ok(conn)
            }
            Err(e) => {
                self.0.dial_failed.lock().insert(node, Instant::now());
                Err(e)
            }
        }
    }

    /// Dials all addresses at once and keeps the first connection that succeeds.
    pub(crate) async fn dial_any(
        &self,
        node: NodeId,
        addrs: &[SocketAddr],
        name: &str,
    ) -> Result<Connection> {
        let config = tls::client_config(&self.0.identity, node, self.0.transport.clone())?;
        let mut set = tokio::task::JoinSet::new();
        for addr in addrs {
            let connecting = self.0.endpoint.connect_with(config.clone(), *addr, name);
            let addr = *addr;
            set.spawn(async move {
                let conn = tokio::time::timeout(DIAL_TIMEOUT, connecting?)
                    .await
                    .map_err(|_| anyhow!("{addr}: timed out"))?
                    .map_err(|e| anyhow!("{addr}: {e}"))?;
                anyhow::Ok(conn)
            });
        }
        let mut errors = Vec::new();
        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok(conn)) => return Ok(conn),
                Ok(Err(e)) => errors.push(e.to_string()),
                Err(e) => errors.push(e.to_string()),
            }
        }
        bail!("dialling {}: {}", node.short(), errors.join("; "))
    }

    pub(crate) async fn accept_loop(self) {
        while let Some(incoming) = self.0.endpoint.accept().await {
            let net = self.clone();
            tokio::spawn(async move {
                let remote = incoming.remote_address();
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        debug!(%remote, "incoming handshake failed: {e}");
                        return;
                    }
                };
                let Ok(peer) = tls::peer_id(&conn) else {
                    return;
                };
                let probe =
                    tls::requested_server_name(&conn).as_deref() == Some(tls::PROBE_SERVER_NAME);
                let member = net.dir().is_some_and(|d| d.is_member(&peer));
                trace!(peer = %peer.short(), %remote, member, probe, "accepted");
                if member {
                    member_limits(&conn);
                    if !probe {
                        net.insert(peer, conn.clone());
                    }
                    net.serve(conn, peer).await;
                    return;
                }
                // A non-member ("guest"): it may only redeem an invite or ask
                // about its join. Guests are limited in number (in all, and
                // per address), and closed when idle or after a while,
                // unless they turn out to be members after all (a new member
                // whose join this node hadn't applied yet).
                let Some(slot) = net.guest_slot(remote) else {
                    debug!(peer = %peer.short(), %remote, "too many connections from non-members");
                    conn.close(VarInt::from_u32(2), b"busy");
                    return;
                };
                let became_member = net.clone().serve_guest(conn.clone(), peer).await;
                drop(slot);
                if became_member {
                    member_limits(&conn);
                    net.serve(conn, peer).await;
                }
            });
        }
    }

    /// Serves the streams the peer opens on a connection, dialled or accepted.
    pub(crate) async fn serve(self, conn: Connection, peer: NodeId) {
        while let Some(stream) = next_stream(&conn).await {
            self.spawn_stream(&conn, peer, stream, || {});
        }
        let mut conns = self.0.conns.lock();
        if conns
            .get(&peer)
            .is_some_and(|c| c.stable_id() == conn.stable_id())
        {
            conns.remove(&peer);
        }
    }

    /// A place for one more guest from `remote`, if there's room.
    fn guest_slot(&self, remote: SocketAddr) -> Option<GuestSlot> {
        let addr = guest_addr(remote);
        let mut g = self.0.guests.lock();
        let from_addr = g.1.get(&addr).copied().unwrap_or(0);
        if g.0 >= self.0.max_guests || from_addr >= self.0.max_guests_per_addr {
            return None;
        }
        g.0 += 1;
        g.1.insert(addr, from_addr + 1);
        Some(GuestSlot {
            net: self.clone(),
            addr,
        })
    }

    /// Serves a non-member's connection. Returns true if the peer has become
    /// a member (the caller then serves it as usual), false once the
    /// connection is closed: by the peer, or by us after `guest_idle` with no
    /// request in progress, or after `guest_lifetime` in any case.
    pub(crate) async fn serve_guest(self, conn: Connection, peer: NodeId) -> bool {
        let started = Instant::now();
        let in_flight = Arc::new(AtomicUsize::new(0));
        let last_active = Arc::new(Mutex::new(Instant::now()));
        let mut tick =
            tokio::time::interval((self.0.guest_idle / 4).max(Duration::from_millis(100)));
        loop {
            tokio::select! {
                stream = next_stream(&conn) => {
                    let Some(stream) = stream else {
                        return false;
                    };
                    in_flight.fetch_add(1, Ordering::Relaxed);
                    *last_active.lock() = Instant::now();
                    let (f, l) = (in_flight.clone(), last_active.clone());
                    self.spawn_stream(&conn, peer, stream, move || {
                        *l.lock() = Instant::now();
                        f.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                _ = tick.tick() => {
                    if self.dir().is_some_and(|d| d.is_member(&peer)) {
                        return true;
                    }
                    if started.elapsed() >= self.0.guest_lifetime {
                        conn.close(VarInt::from_u32(0), b"too long");
                        return false;
                    }
                    let idle = last_active.lock().elapsed();
                    if in_flight.load(Ordering::Relaxed) == 0 && idle >= self.0.guest_idle {
                        conn.close(VarInt::from_u32(0), b"idle");
                        return false;
                    }
                }
            }
        }
    }

    /// Serves one stream in its own task, then calls `done`.
    fn spawn_stream(
        &self,
        conn: &Connection,
        peer: NodeId,
        stream: Stream,
        done: impl FnOnce() + Send + 'static,
    ) {
        let net = self.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            let res = match stream {
                Stream::Bi(send, recv) => net.serve_bi(&conn, peer, send, recv).await,
                Stream::Uni(recv) => net.serve_uni(peer, recv).await,
            };
            if let Err(e) = res {
                debug!(peer = %peer.short(), "stream failed: {e:#}");
            }
            done();
        });
    }

    /// Reads a stream's header and body. The header (kind, cluster, and
    /// whether the peer may use that kind) is checked before any of the body
    /// is read. Non-members may only send small join requests, and must send
    /// them promptly.
    pub(crate) async fn read_request(
        &self,
        peer: NodeId,
        recv: &mut quinn::RecvStream,
    ) -> Result<(Kind, Vec<u8>)> {
        let member = self.dir().is_some_and(|d| d.is_member(&peer));
        if member {
            return self.read_request_inner(peer, recv, true).await;
        }
        tokio::time::timeout(
            self.0.guest_read_timeout,
            self.read_request_inner(peer, recv, false),
        )
        .await
        .map_err(|_| anyhow!("request not received in time"))?
    }

    pub(crate) async fn read_request_inner(
        &self,
        peer: NodeId,
        recv: &mut quinn::RecvStream,
        member: bool,
    ) -> Result<(Kind, Vec<u8>)> {
        let mut header = [0u8; HEADER_LEN];
        recv.read_exact(&mut header).await.context("short stream")?;
        let kind = Kind::from_u8(header[0]).context("unknown stream kind")?;
        let cluster = ClusterId(header[1..33].try_into().expect("32 bytes"));
        ensure!(Some(cluster) == self.cluster_id(), "wrong cluster");
        let sent = u64::from_be_bytes(header[33..41].try_into().expect("8 bytes"));
        if member {
            // One-way: the peer's clock is behind by our transit time, which
            // is negligible next to the skew worth warning about.
            self.record_clock(peer, sent as i64 - now_ms() as i64);
        }
        let limit = if kind == Kind::Join {
            MAX_JOIN_MESSAGE
        } else {
            ensure!(member, "not a member");
            MAX_MESSAGE
        };
        Ok((kind, recv.read_to_end(limit).await?))
    }

    pub(crate) async fn serve_bi(
        &self,
        conn: &Connection,
        peer: NodeId,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) -> Result<()> {
        let res = match self.read_request(peer, &mut recv).await {
            Ok((kind, body)) => self.dispatch(conn, peer, kind, body).await,
            Err(e) => Err(e.to_string()),
        };
        let mut encoded = postcard::to_stdvec(&res)?;
        if encoded.len() + 8 > MAX_MESSAGE {
            encoded = postcard::to_stdvec(&Result::<Vec<u8>, String>::Err(
                "encoded response exceeds the wire limit".into(),
            ))?;
        }
        send.write_all(&now_ms().to_be_bytes()).await?;
        send.write_all(&encoded).await?;
        send.finish()?;
        // Wait until the peer has the response before the stream is dropped.
        let _ = send.stopped().await;
        Ok(())
    }

    pub(crate) async fn serve_uni(&self, peer: NodeId, mut recv: quinn::RecvStream) -> Result<()> {
        let (kind, body) = self.read_request(peer, &mut recv).await?;
        ensure!(kind == Kind::State, "unexpected one-way stream");
        if let Some(h) = self.0.handler.get() {
            h.state(peer, body);
        }
        Ok(())
    }

    pub(crate) async fn dispatch(
        &self,
        conn: &Connection,
        peer: NodeId,
        kind: Kind,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let handler = self.0.handler.get().ok_or("not ready")?.clone();
        if kind == Kind::Join {
            return handler.join(peer, body).await;
        }
        if !self.dir().is_some_and(|d| d.is_member(&peer)) {
            return Err("not a member".into());
        }
        let decode_err = |e: postcard::Error| e.to_string();
        match kind {
            Kind::Direct => {
                let req: DirectRequest = postcard::from_bytes(&body).map_err(decode_err)?;
                handler.request(peer, req.service, req.body).await
            }
            Kind::Forward => {
                let req: ForwardRequest = postcard::from_bytes(&body).map_err(decode_err)?;
                self.relay(conn, peer, req)
                    .await
                    .map_err(|e| format!("{e:#}"))
            }
            Kind::Deliver => {
                let env: Signed<Envelope> = postcard::from_bytes(&body).map_err(decode_err)?;
                self.deliver(handler, env)
                    .await
                    .map_err(|e| format!("{e:#}"))
            }
            Kind::Probe => {
                let req: ProbeRequest = postcard::from_bytes(&body).map_err(decode_err)?;
                self.dial_back(peer, req.addr)
                    .await
                    .map_err(|e| format!("{e:#}"))?;
                Ok(Vec::new())
            }
            Kind::State | Kind::Join => Err("unexpected stream kind".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guests_are_counted_by_ipv4_address_or_ipv6_64() {
        let a = |s: &str| guest_addr(s.parse().unwrap());
        assert_eq!(a("192.0.2.1:1"), a("192.0.2.1:2"));
        assert_ne!(a("192.0.2.1:1"), a("192.0.2.2:1"));
        assert_eq!(a("[::ffff:192.0.2.1]:1"), a("192.0.2.1:1"));
        assert_eq!(a("[2001:db8:1:2::1]:1"), a("[2001:db8:1:2:ffff::9]:1"));
        assert_ne!(a("[2001:db8:1:2::1]:1"), a("[2001:db8:1:3::1]:1"));
    }
}
