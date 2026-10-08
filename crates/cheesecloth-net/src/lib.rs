//! The cheesecloth control plane: one QUIC endpoint per node, a connection table
//! keyed by node ID, and message forwarding through relays.
//!
//! Application messages are opaque bytes tagged with a one-byte service
//! number; the daemon defines the services. Every stream and response carries
//! its sender's clock, so each node knows how far its members' clocks are from
//! its own without extra messages.
//!
//! - `wire`: stream kinds, headers and messages.
//! - `conn`: the connection table, dialling, accepting and serving streams.
//! - `rpc`: requests, relay forwarding, soft-state pushes and joins.
//! - `probe`: reachability dial-backs.
//! - `tls`: raw-public-key authentication.

mod conn;
mod probe;
mod rpc;
pub mod tls;
mod wire;

pub use wire::CallError;

/// Application payload budget. Reserve space under the 1 MiB stream limit
/// for signed forwarding envelopes, result framing and the response clock.
pub const MAX_PAYLOAD: usize = wire::MAX_MESSAGE - 1024;

use parking_lot::Mutex;
use std::{
    collections::{BTreeSet, HashMap},
    future::Future,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, atomic::AtomicU64},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use cheesecloth_core::{ClusterId, Identity, NAT_KEEPALIVE_SECS, NodeId};
use quinn::{Connection, Endpoint, EndpointConfig, TransportConfig, VarInt};
use serde::{Deserialize, Serialize};
use tracing::warn;

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Clock measurements older than this are forgotten.
const CLOCK_FRESH_FOR: Duration = Duration::from_secs(300);

/// What the daemon tells the control plane about the cluster.
pub trait Directory: Send + Sync + 'static {
    fn cluster_id(&self) -> Option<ClusterId>;
    fn is_member(&self, node: &NodeId) -> bool;
    /// Whether `node` accepts control-plane forwarding requests. For the
    /// local node this must reflect its current policy, not a cached record.
    fn is_relay(&self, node: &NodeId) -> bool;
    /// Addresses at which `node` may accept direct connections, best first.
    /// Empty means "don't dial it; it will dial us or be reached via relays".
    fn dial_addrs(&self, node: &NodeId) -> Vec<SocketAddr>;
    /// Members that may be able to forward to `node`, best first.
    fn forwarders(&self, node: &NodeId) -> Vec<NodeId>;
}

/// The daemon's handlers for incoming messages.
pub trait Handler: Send + Sync + 'static {
    /// A request from a member, received directly or via a relay.
    fn request(
        &self,
        from: NodeId,
        service: u8,
        body: Vec<u8>,
    ) -> BoxFuture<Result<Vec<u8>, String>>;
    /// An invite redemption from a node that may not be a member.
    fn join(&self, from: NodeId, body: Vec<u8>) -> BoxFuture<Result<Vec<u8>, String>>;
    /// Soft state pushed by a member.
    fn state(&self, from: NodeId, body: Vec<u8>);
    /// A connection to a member came up (dialled or accepted).
    fn connected(&self, _peer: NodeId) {}
}

#[derive(Clone, Debug)]
pub struct NetOptions {
    pub bind: SocketAddr,
    /// QUIC keep-alive; keeps NAT mappings to relays open.
    pub keep_alive: Duration,
    pub idle_timeout: Duration,
    /// A non-member must send its (join) request within this long.
    pub guest_read_timeout: Duration,
    /// A non-member's connection is closed after this long with no request
    /// in progress.
    pub guest_idle: Duration,
    /// A non-member's connection is closed after this long in any case.
    pub guest_lifetime: Duration,
    /// At most this many connections from non-members at once.
    pub max_guests: usize,
    /// At most this many of them from one address (IPv6: one /64).
    pub max_guests_per_addr: usize,
}

impl NetOptions {
    pub fn new(bind: SocketAddr) -> Self {
        Self {
            bind,
            keep_alive: Duration::from_secs(NAT_KEEPALIVE_SECS.into()),
            idle_timeout: Duration::from_secs(60),
            guest_read_timeout: Duration::from_secs(30),
            guest_idle: Duration::from_secs(30),
            guest_lifetime: Duration::from_secs(120),
            max_guests: 64,
            max_guests_per_addr: 8,
        }
    }
}

/// A live connection, for status output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnInfo {
    pub node: NodeId,
    pub remote: SocketAddr,
    pub rtt_ms: u64,
}

struct Inner {
    identity: Arc<Identity>,
    me: NodeId,
    endpoint: Endpoint,
    transport: Arc<TransportConfig>,
    dir: Arc<dyn Directory>,
    handler: Arc<dyn Handler>,
    conns: Mutex<HashMap<NodeId, Connection>>,
    dial_locks: Mutex<HashMap<NodeId, Arc<tokio::sync::Mutex<()>>>>,
    dial_failed: Mutex<HashMap<NodeId, Instant>>,
    /// Recently seen forwarded sequence numbers, per sender.
    seen: Mutex<HashMap<NodeId, BTreeSet<u64>>>,
    seq: AtomicU64,
    /// Members' clock offsets from ours (ms), and when each was measured.
    clocks: Mutex<HashMap<NodeId, (i64, Instant)>>,
    guest_read_timeout: Duration,
    guest_idle: Duration,
    guest_lifetime: Duration,
    max_guests: usize,
    max_guests_per_addr: usize,
    /// Open connections from non-members: in all, and per address.
    guests: Mutex<(usize, HashMap<IpAddr, usize>)>,
}

#[derive(Clone)]
pub struct Net(Arc<Inner>);

/// Every connection starts with a non-member's ("guest's") limits, as the
/// peer isn't known until the handshake is done; `conn::member_limits` raises
/// them for members. Limits can only be raised on a live connection.
fn transport_config(opts: &NetOptions) -> Result<Arc<TransportConfig>> {
    let mut t = TransportConfig::default();
    t.keep_alive_interval(Some(opts.keep_alive));
    t.max_idle_timeout(Some(opts.idle_timeout.try_into()?));
    t.max_concurrent_bidi_streams(conn::GUEST_BI_STREAMS.into());
    t.max_concurrent_uni_streams(0u32.into());
    t.receive_window(conn::GUEST_RECEIVE_WINDOW.into());
    Ok(Arc::new(t))
}

/// Binds a UDP socket; for an unspecified IPv6 address, dual-stack.
/// Errors name the address.
fn bind_socket(addr: SocketAddr) -> Result<std::net::UdpSocket> {
    use socket2::{Domain as SDomain, Protocol, Socket, Type};
    let bind = || -> std::io::Result<Socket> {
        let domain = if addr.is_ipv6() {
            SDomain::IPV6
        } else {
            SDomain::IPV4
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        if addr.is_ipv6() {
            socket.set_only_v6(false)?;
        }
        socket.bind(&addr.into())?;
        Ok(socket)
    };
    Ok(bind().with_context(|| format!("binding {addr}"))?.into())
}

/// Whether a failed bind means the host has no IPv6, rather than another
/// problem such as a port in use, which IPv4 would not solve.
fn ipv6_missing(e: &anyhow::Error) -> bool {
    let Some(e) = e.downcast_ref::<std::io::Error>() else {
        return false;
    };
    // "Address family not supported" has no `io::ErrorKind`.
    #[cfg(unix)]
    let no_family = e.raw_os_error() == Some(libc::EAFNOSUPPORT);
    #[cfg(windows)]
    let no_family = e.raw_os_error() == Some(10047); // WSAEAFNOSUPPORT
    no_family || e.kind() == std::io::ErrorKind::AddrNotAvailable
}

/// Normalises IPv4-mapped IPv6 addresses to IPv4.
pub fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// A bound control-plane endpoint that doesn't accept connections yet (see
/// `Net::bind`).
pub struct Bound {
    opts: NetOptions,
    identity: Arc<Identity>,
    endpoint: Endpoint,
    transport: Arc<TransportConfig>,
}

impl Bound {
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    /// Starts accepting connections. `dir` says who the members are, and
    /// `handler` answers their requests.
    pub fn start(self, dir: Arc<dyn Directory>, handler: Arc<dyn Handler>) -> Net {
        let Bound {
            opts,
            identity,
            endpoint,
            transport,
        } = self;
        let me = identity.node_id();
        let net = Net(Arc::new(Inner {
            identity,
            me,
            endpoint,
            transport,
            dir,
            handler,
            conns: Mutex::new(HashMap::new()),
            dial_locks: Mutex::new(HashMap::new()),
            dial_failed: Mutex::new(HashMap::new()),
            seen: Mutex::new(HashMap::new()),
            seq: AtomicU64::new(0),
            clocks: Mutex::new(HashMap::new()),
            guest_read_timeout: opts.guest_read_timeout,
            guest_idle: opts.guest_idle,
            guest_lifetime: opts.guest_lifetime,
            max_guests: opts.max_guests,
            max_guests_per_addr: opts.max_guests_per_addr,
            guests: Mutex::default(),
        }));
        tokio::spawn(net.clone().accept_loop());
        net
    }
}

impl Net {
    /// Binds the control-plane endpoint. `[::]:port` binds dual-stack, falling
    /// back to IPv4 only if IPv6 is unavailable.
    ///
    /// The endpoint accepts no connections until `Bound::start` gives it its
    /// directory and handler.
    pub fn bind(opts: NetOptions, identity: Arc<Identity>) -> Result<Bound> {
        let transport = transport_config(&opts)?;
        let server = tls::server_config(&identity, transport.clone())?;
        let socket = match bind_socket(opts.bind) {
            Ok(s) => s,
            Err(e) if opts.bind.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED) && ipv6_missing(&e) => {
                warn!("IPv6 unavailable ({e:#}); control plane uses IPv4 only");
                bind_socket(SocketAddr::from(([0, 0, 0, 0], opts.bind.port())))?
            }
            Err(e) => return Err(e),
        };
        let endpoint = Endpoint::new(
            EndpointConfig::default(),
            Some(server),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        Ok(Bound {
            opts,
            identity,
            endpoint,
            transport,
        })
    }

    pub fn node_id(&self) -> NodeId {
        self.0.me
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.0.endpoint.local_addr()?)
    }

    fn dir(&self) -> &Arc<dyn Directory> {
        &self.0.dir
    }

    fn cluster_id(&self) -> Option<ClusterId> {
        self.dir().cluster_id()
    }

    pub fn close(&self) {
        self.0.endpoint.close(VarInt::from_u32(0), b"shutdown");
    }

    fn record_clock(&self, peer: NodeId, offset_ms: i64) {
        self.0
            .clocks
            .lock()
            .insert(peer, (offset_ms, Instant::now()));
    }

    /// Recent measurements of members' clocks: their clock minus ours, in ms.
    pub fn clock_offsets(&self) -> Vec<(NodeId, i64)> {
        let mut clocks = self.0.clocks.lock();
        clocks.retain(|_, (_, at)| at.elapsed() < CLOCK_FRESH_FOR);
        clocks.iter().map(|(n, (o, _))| (*n, *o)).collect()
    }
}
