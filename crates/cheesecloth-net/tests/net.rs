//! Control-plane tests over real QUIC on localhost.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use cheesecloth_core::{ClusterId, Identity, NodeId, token::TokenPeer};
use cheesecloth_net::{BoxFuture, Directory, Handler, Net, NetOptions};

const T: Duration = Duration::from_secs(5);

#[derive(Default)]
struct Dir {
    cluster: Option<ClusterId>,
    members: Mutex<HashSet<NodeId>>,
    addrs: Mutex<HashMap<NodeId, SocketAddr>>,
    /// Nodes that can't be dialled directly (as if behind NAT).
    hidden: Mutex<HashSet<NodeId>>,
    relays: Mutex<Vec<NodeId>>,
    /// Local refusal, even when senders still list the node as a relay.
    disabled_relays: Mutex<HashSet<NodeId>>,
}

impl Directory for Dir {
    fn cluster_id(&self) -> Option<ClusterId> {
        self.cluster
    }
    fn is_member(&self, node: &NodeId) -> bool {
        self.members.lock().unwrap().contains(node)
    }
    fn is_relay(&self, node: &NodeId) -> bool {
        self.relays.lock().unwrap().contains(node)
            && !self.disabled_relays.lock().unwrap().contains(node)
    }
    fn dial_addrs(&self, node: &NodeId) -> Vec<SocketAddr> {
        if self.hidden.lock().unwrap().contains(node) {
            return vec![];
        }
        self.addrs
            .lock()
            .unwrap()
            .get(node)
            .copied()
            .into_iter()
            .collect()
    }
    fn forwarders(&self, _node: &NodeId) -> Vec<NodeId> {
        self.relays.lock().unwrap().clone()
    }
}

struct Echo {
    me: NodeId,
    states: Mutex<Vec<(NodeId, Vec<u8>)>>,
    /// Service 97 counts its calls here, then drops the caller's connection
    /// before answering (a lost answer).
    runs: std::sync::atomic::AtomicUsize,
    net: Mutex<Option<Net>>,
}

impl Handler for Echo {
    fn request(
        &self,
        from: NodeId,
        service: u8,
        body: Vec<u8>,
    ) -> BoxFuture<Result<Vec<u8>, String>> {
        let me = self.me;
        if service == 97 {
            self.runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let net = self.net.lock().unwrap().clone();
            return Box::pin(async move {
                if let Some(net) = net {
                    net.disconnect(&from);
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
                Ok(b"too late".to_vec())
            });
        }
        Box::pin(async move {
            if service == 96 {
                return Ok(vec![0; 1 << 20]);
            }
            if service == 99 {
                return Err("refused".into());
            }
            Ok(format!(
                "{} from {} svc {}: {}",
                me.short(),
                from.short(),
                service,
                String::from_utf8_lossy(&body)
            )
            .into_bytes())
        })
    }
    fn join(&self, from: NodeId, body: Vec<u8>) -> BoxFuture<Result<Vec<u8>, String>> {
        Box::pin(async move {
            if body == b"slow" {
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            Ok([b"welcome ".as_slice(), &from.0[..2], &body].concat())
        })
    }
    fn state(&self, from: NodeId, body: Vec<u8>) {
        self.states.lock().unwrap().push((from, body));
    }
}

struct Node {
    id: NodeId,
    net: Net,
    handler: Arc<Echo>,
}

fn node(dir: &Arc<Dir>) -> Node {
    node_with(dir, NetOptions::new("127.0.0.1:0".parse().unwrap()))
}

fn node_with(dir: &Arc<Dir>, opts: NetOptions) -> Node {
    let identity = Arc::new(Identity::generate());
    let id = identity.node_id();
    let net = Net::bind(opts, identity).unwrap();
    let handler = Arc::new(Echo {
        me: id,
        states: Mutex::default(),
        runs: Default::default(),
        net: Mutex::new(Some(net.clone())),
    });
    net.set_directory(dir.clone());
    net.set_handler(handler.clone());
    dir.addrs
        .lock()
        .unwrap()
        .insert(id, net.local_addr().unwrap());
    Node { id, net, handler }
}

fn cluster() -> Arc<Dir> {
    Arc::new(Dir {
        cluster: Some(ClusterId([42; 32])),
        ..Default::default()
    })
}

#[tokio::test]
async fn direct_request_between_members() {
    let dir = cluster();
    let (a, b) = (node(&dir), node(&dir));
    dir.members.lock().unwrap().extend([a.id, b.id]);
    let r = a.net.request(b.id, 7, b"hi".to_vec(), T).await.unwrap();
    assert_eq!(
        String::from_utf8(r).unwrap(),
        format!("{} from {} svc 7: hi", b.id.short(), a.id.short())
    );
    // The connection is reused in the other direction.
    assert!(b.net.is_connected(&a.id));
    let r = b.net.request(a.id, 1, b"back".to_vec(), T).await.unwrap();
    assert!(String::from_utf8(r).unwrap().ends_with("back"));
    // Remote errors come back as errors.
    let e = a.net.request(b.id, 99, vec![], T).await.unwrap_err();
    assert!(e.to_string().contains("refused"), "{e:#}");
}

#[tokio::test]
async fn non_member_can_only_join() {
    let dir = cluster();
    let (a, outsider) = (node(&dir), node(&dir));
    dir.members.lock().unwrap().insert(a.id);
    let peer = TokenPeer {
        node_id: a.id,
        addrs: vec![a.net.local_addr().unwrap()],
    };
    let r = outsider
        .net
        .join(ClusterId([42; 32]), &peer, b"please")
        .await
        .unwrap();
    assert!(r.starts_with(b"welcome "));
    // Any other request is refused.
    let e = outsider.net.request(a.id, 1, vec![], T).await.unwrap_err();
    assert!(e.to_string().contains("not a member"), "{e:#}");
    // Wrong cluster ID is refused even for joins.
    let e = outsider
        .net
        .join(ClusterId([1; 32]), &peer, b"x")
        .await
        .unwrap_err();
    assert!(e.to_string().contains("wrong cluster"), "{e:#}");
}

#[tokio::test]
async fn join_pins_the_member_key() {
    let dir = cluster();
    let (a, outsider) = (node(&dir), node(&dir));
    dir.members.lock().unwrap().insert(a.id);
    let wrong = TokenPeer {
        node_id: NodeId([3; 32]),
        addrs: vec![a.net.local_addr().unwrap()],
    };
    assert!(
        outsider
            .net
            .join(ClusterId([42; 32]), &wrong, b"x")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn forwarding_through_a_relay() {
    let dir = cluster();
    let (relay, n1, n2) = (node(&dir), node(&dir), node(&dir));
    dir.members.lock().unwrap().extend([relay.id, n1.id, n2.id]);
    dir.relays.lock().unwrap().push(relay.id);
    // n1 and n2 can't dial each other; both keep a connection to the relay.
    dir.hidden.lock().unwrap().extend([n1.id, n2.id]);
    n1.net.connect(relay.id).await.unwrap();
    n2.net.connect(relay.id).await.unwrap();
    let r = n1
        .net
        .request(n2.id, 5, b"via relay".to_vec(), T)
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8(r).unwrap(),
        format!("{} from {} svc 5: via relay", n2.id.short(), n1.id.short())
    );
    assert!(!n1.net.is_connected(&n2.id));

    // Synchronized forwarding returns without the destination's response.
    let r = n2
        .net
        .forward_via(relay.id, n1.id, 5, b"go".to_vec(), true)
        .await
        .unwrap();
    assert!(r.is_none());
}

#[tokio::test]
async fn a_disabled_relay_refuses_both_forwarding_modes_before_delivery() {
    let dir = cluster();
    let (disabled, relay, n1, n2) = (node(&dir), node(&dir), node(&dir), node(&dir));
    dir.members
        .lock()
        .unwrap()
        .extend([disabled.id, relay.id, n1.id, n2.id]);
    // The sender has a stale advertisement, with the disabled relay first.
    dir.relays.lock().unwrap().extend([disabled.id, relay.id]);
    dir.disabled_relays.lock().unwrap().insert(disabled.id);
    dir.hidden.lock().unwrap().extend([n1.id, n2.id]);
    for via in [&disabled, &relay] {
        n1.net.connect(via.id).await.unwrap();
        n2.net.connect(via.id).await.unwrap();
    }
    for synchronized in [false, true] {
        let error = n1
            .net
            .forward_via(disabled.id, n2.id, 97, vec![], synchronized)
            .await
            .unwrap_err();
        assert!(
            matches!(error, cheesecloth_net::CallError::NotSent(_)),
            "{error:#}"
        );
        assert!(
            format!("{error:#}").contains("relaying is disabled"),
            "{error:#}"
        );
    }
    assert_eq!(n2.handler.runs.load(std::sync::atomic::Ordering::SeqCst), 0);
    // It still serves requests addressed to itself.
    let direct = n1
        .net
        .request(disabled.id, 5, b"direct".to_vec(), T)
        .await
        .unwrap();
    assert!(
        String::from_utf8(direct)
            .unwrap()
            .ends_with("svc 5: direct")
    );
    // Refusal allows the sender to retry another relay without duplicate work.
    let answer = n1.net.request(n2.id, 97, vec![], T).await.unwrap();
    assert_eq!(answer, b"too late");
    assert_eq!(n2.handler.runs.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(!n1.net.is_connected(&n2.id));
}

#[tokio::test]
async fn soft_state_push() {
    let dir = cluster();
    let (a, b) = (node(&dir), node(&dir));
    dir.members.lock().unwrap().extend([a.id, b.id]);
    a.net.connect(b.id).await.unwrap();
    a.net.push_state(b.id, b"state").await.unwrap();
    for _ in 0..50 {
        if !b.handler.states.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        b.handler.states.lock().unwrap()[0],
        (a.id, b"state".to_vec())
    );
}

#[tokio::test]
async fn probe_dials_back() {
    let dir = cluster();
    let (a, b) = (node(&dir), node(&dir));
    dir.members.lock().unwrap().extend([a.id, b.id]);
    a.net
        .probe(b.id, a.net.local_addr().unwrap())
        .await
        .unwrap();
    // A dead address fails.
    let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
    assert!(a.net.probe(b.id, dead).await.is_err());
}

#[tokio::test]
async fn oversized_join_requests_are_refused() {
    let dir = cluster();
    let (a, outsider) = (node(&dir), node(&dir));
    dir.members.lock().unwrap().insert(a.id);
    let peer = TokenPeer {
        node_id: a.id,
        addrs: vec![a.net.local_addr().unwrap()],
    };
    let small = outsider
        .net
        .join(ClusterId([42; 32]), &peer, &[0; 1000])
        .await;
    assert!(small.is_ok());
    let big = outsider
        .net
        .join(ClusterId([42; 32]), &peer, &vec![0; 1 << 20])
        .await;
    assert!(big.is_err(), "a 1 MiB join request must be refused");
}

#[tokio::test]
async fn requests_and_responses_carry_clocks() {
    let dir = cluster();
    let (a, b) = (node(&dir), node(&dir));
    dir.members.lock().unwrap().extend([a.id, b.id]);
    assert!(a.net.clock_offsets().is_empty());
    a.net.request(b.id, 1, vec![], T).await.unwrap();
    // b saw a's clock in the request header; a saw b's in the response.
    for (net, peer) in [(&a.net, b.id), (&b.net, a.id)] {
        let offsets = net.clock_offsets();
        assert_eq!(offsets.len(), 1);
        assert_eq!(offsets[0].0, peer);
        assert!(
            offsets[0].1.abs() < 1000,
            "same machine, same clock: {offsets:?}"
        );
    }
}

// ------------------------------------------------- non-member connections

fn strict(dir: &Arc<Dir>, idle_secs: u64, max_guests: usize) -> Node {
    strict_with(dir, idle_secs, max_guests, |_| {})
}

fn strict_with(
    dir: &Arc<Dir>,
    idle_secs: u64,
    max_guests: usize,
    tweak: impl FnOnce(&mut NetOptions),
) -> Node {
    let mut opts = NetOptions::new("127.0.0.1:0".parse().unwrap());
    opts.guest_read_timeout = Duration::from_secs(1);
    opts.guest_idle = Duration::from_secs(idle_secs);
    opts.max_guests = max_guests;
    tweak(&mut opts);
    node_with(dir, opts)
}

/// A bare QUIC connection from a fresh (non-member) key.
async fn raw_connect(to: &Node, as_id: &Identity) -> quinn::Connection {
    raw_connect_via(to, as_id, "127.0.0.1").await
}

/// Like `raw_connect`, from and to the loopback address `ip`.
async fn raw_connect_via(to: &Node, as_id: &Identity, ip: &str) -> quinn::Connection {
    let ip: std::net::IpAddr = ip.parse().unwrap();
    let ep = quinn::Endpoint::client((ip, 0).into()).unwrap();
    let cfg = cheesecloth_net::tls::client_config(
        as_id,
        to.id,
        Arc::new(quinn::TransportConfig::default()),
    )
    .unwrap();
    let port = to.net.local_addr().unwrap().port();
    ep.connect_with(cfg, (ip, port).into(), "cheesecloth")
        .unwrap()
        .await
        .unwrap()
}

#[tokio::test]
async fn idle_guests_are_closed() {
    let dir = cluster();
    let a = strict(&dir, 1, 64);
    dir.members.lock().unwrap().insert(a.id);
    let conn = raw_connect(&a, &Identity::generate()).await;
    let closed = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
    assert!(
        closed.is_ok(),
        "an idle non-member connection must be closed"
    );
}

#[tokio::test]
async fn stalled_guest_requests_time_out() {
    let dir = cluster();
    let a = strict(&dir, 30, 64);
    dir.members.lock().unwrap().insert(a.id);
    let conn = raw_connect(&a, &Identity::generate()).await;
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&[4, 42, 42]).await.unwrap(); // a partial header, then nothing
    let resp = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1 << 16))
        .await
        .expect("answered")
        .unwrap();
    let res: Result<Vec<u8>, String> = postcard::from_bytes(&resp[8..]).unwrap();
    assert!(res.unwrap_err().contains("not received in time"));
}

#[tokio::test]
async fn slow_joins_are_not_cut_off() {
    let dir = cluster();
    let (a, outsider) = (strict(&dir, 1, 64), node(&dir));
    dir.members.lock().unwrap().insert(a.id);
    let peer = TokenPeer {
        node_id: a.id,
        addrs: vec![a.net.local_addr().unwrap()],
    };
    // The handler takes 3 s, three times the idle limit.
    let r = outsider
        .net
        .join(ClusterId([42; 32]), &peer, b"slow")
        .await
        .unwrap();
    assert!(r.ends_with(b"slow"));
}

#[tokio::test]
async fn guests_are_capped() {
    let dir = cluster();
    let a = strict(&dir, 30, 2);
    dir.members.lock().unwrap().insert(a.id);
    let _g1 = raw_connect(&a, &Identity::generate()).await;
    let _g2 = raw_connect(&a, &Identity::generate()).await;
    let g3 = raw_connect(&a, &Identity::generate()).await;
    let closed = tokio::time::timeout(Duration::from_secs(5), g3.closed()).await;
    assert!(closed.is_ok(), "a third guest must be refused");
    // Members aren't guests: they still get in.
    let m = Identity::generate();
    dir.members.lock().unwrap().insert(m.node_id());
    let conn = raw_connect(&a, &m).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(conn.close_reason().is_none());
}

#[tokio::test]
async fn guests_are_capped_per_address() {
    let dir = cluster();
    let a = strict_with(&dir, 30, 64, |o| {
        o.bind = "[::]:0".parse().unwrap();
        o.max_guests_per_addr = 2;
    });
    dir.members.lock().unwrap().insert(a.id);
    let _g1 = raw_connect_via(&a, &Identity::generate(), "127.0.0.1").await;
    let _g2 = raw_connect_via(&a, &Identity::generate(), "127.0.0.1").await;
    let g3 = raw_connect_via(&a, &Identity::generate(), "127.0.0.1").await;
    let closed = tokio::time::timeout(Duration::from_secs(5), g3.closed()).await;
    assert!(
        closed.is_ok(),
        "a third guest from one address must be refused"
    );
    // A guest from another address is accepted.
    let other = raw_connect_via(&a, &Identity::generate(), "::1").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(other.close_reason().is_none());
    // A guest that leaves frees its place.
    drop(_g1);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let g4 = raw_connect_via(&a, &Identity::generate(), "127.0.0.1").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(g4.close_reason().is_none(), "room after a guest left");
}

#[tokio::test]
async fn busy_guests_are_closed_after_a_while() {
    let dir = cluster();
    let a = strict_with(&dir, 1, 64, |o| o.guest_lifetime = Duration::from_secs(3));
    dir.members.lock().unwrap().insert(a.id);
    let conn = raw_connect(&a, &Identity::generate()).await;
    // Always a request in progress, so never idle.
    let c = conn.clone();
    tokio::spawn(async move {
        while let Ok((mut send, _recv)) = c.open_bi().await {
            let _ = send.write_all(&[4]).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    });
    let reason = tokio::time::timeout(Duration::from_secs(8), conn.closed())
        .await
        .expect("closed");
    assert!(format!("{reason}").contains("too long"), "{reason}");
}

#[tokio::test]
async fn a_guest_that_becomes_a_member_is_kept() {
    let dir = cluster();
    let a = strict(&dir, 1, 64);
    dir.members.lock().unwrap().insert(a.id);
    let late = Identity::generate();
    let conn = raw_connect(&a, &late).await;
    // Its join reaches this node a moment later.
    dir.members.lock().unwrap().insert(late.node_id());
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        conn.close_reason().is_none(),
        "a new member's connection must not be closed"
    );
}

/// `f`, if it completes within half a second.
fn soon<F: std::future::Future>(f: F) -> tokio::time::Timeout<F> {
    tokio::time::timeout(Duration::from_millis(500), f)
}

#[tokio::test]
async fn guests_get_few_streams_and_members_many() {
    let dir = cluster();
    // Idle long enough that the guest isn't closed while the test runs.
    let a = strict(&dir, 5, 64);
    let m = Identity::generate();
    dir.members.lock().unwrap().extend([a.id, m.node_id()]);

    let guest = raw_connect(&a, &Identity::generate()).await;
    let _open = (
        guest.open_bi().await.unwrap(),
        guest.open_bi().await.unwrap(),
    );
    assert!(soon(guest.open_bi()).await.is_err(), "a third stream");
    assert!(soon(guest.open_uni()).await.is_err(), "a one-way stream");
    // They waited for credit, rather than failing.
    assert!(guest.close_reason().is_none());

    let member = raw_connect(&a, &m).await;
    let mut open = Vec::new();
    for _ in 0..20 {
        open.push(soon(member.open_bi()).await.unwrap().unwrap());
    }
    soon(member.open_uni()).await.unwrap().unwrap();

    // A guest that turns out to be a member gets a member's limits.
    let late = Identity::generate();
    let conn = raw_connect(&a, &late).await;
    dir.members.lock().unwrap().insert(late.node_id());
    tokio::time::timeout(Duration::from_secs(5), conn.open_uni())
        .await
        .unwrap()
        .unwrap();
}

// ------------------------------------------------- lost answers and retries

#[tokio::test]
async fn a_lost_answer_is_not_resent_through_a_relay() {
    let dir = cluster();
    let (relay, n1, n2) = (node(&dir), node(&dir), node(&dir));
    dir.members.lock().unwrap().extend([relay.id, n1.id, n2.id]);
    dir.relays.lock().unwrap().push(relay.id);
    n1.net.connect(relay.id).await.unwrap();
    n2.net.connect(relay.id).await.unwrap();
    n1.net.connect(n2.id).await.unwrap();
    // n2 runs the request, then n1 loses the answer.
    let err = n1.net.request(n2.id, 97, vec![], T).await.unwrap_err();
    assert!(format!("{err:#}").contains("no answer"), "{err:#}");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        n2.handler.runs.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the request must run exactly once"
    );
}

#[tokio::test]
async fn an_undeliverable_forward_tries_the_next_relay() {
    let dir = cluster();
    let (r1, r2, n1, n2) = (node(&dir), node(&dir), node(&dir), node(&dir));
    dir.members
        .lock()
        .unwrap()
        .extend([r1.id, r2.id, n1.id, n2.id]);
    // r1 first, but only r2 is connected to n2.
    dir.relays.lock().unwrap().extend([r1.id, r2.id]);
    dir.hidden.lock().unwrap().extend([n1.id, n2.id]);
    n1.net.connect(r1.id).await.unwrap();
    n1.net.connect(r2.id).await.unwrap();
    n2.net.connect(r2.id).await.unwrap();
    let r = n1.net.request(n2.id, 5, b"x".to_vec(), T).await.unwrap();
    assert!(String::from_utf8(r).unwrap().ends_with(": x"));
}

#[tokio::test]
async fn join_errors_say_whether_the_request_was_sent() {
    use cheesecloth_net::CallError;
    let dir = cluster();
    let (a, outsider) = (node(&dir), node(&dir));
    dir.members.lock().unwrap().insert(a.id);
    let dead = TokenPeer {
        node_id: a.id,
        addrs: vec!["127.0.0.1:9".parse().unwrap()],
    };
    let e = outsider
        .net
        .join(ClusterId([42; 32]), &dead, b"x")
        .await
        .unwrap_err();
    assert!(matches!(e, CallError::NotSent(_)), "{e:#}");
    let peer = TokenPeer {
        node_id: a.id,
        addrs: vec![a.net.local_addr().unwrap()],
    };
    let e = outsider
        .net
        .join(ClusterId([1; 32]), &peer, b"x")
        .await
        .unwrap_err();
    assert!(
        matches!(e, CallError::Remote(ref m) if m.contains("wrong cluster")),
        "{e:#}"
    );
}

// ------------------------------------------------- errors and edge cases

#[tokio::test]
async fn a_request_to_self_goes_straight_to_the_handler() {
    let dir = cluster();
    let a = node(&dir);
    dir.members.lock().unwrap().insert(a.id);
    assert_eq!(a.net.node_id(), a.id);
    let r = a.net.request(a.id, 3, b"me".to_vec(), T).await.unwrap();
    assert!(String::from_utf8(r).unwrap().ends_with("svc 3: me"));
    assert!(a.net.connections().is_empty(), "no connection to itself");
}

#[tokio::test]
async fn nothing_is_sent_outside_a_cluster() {
    let dir = Arc::new(Dir::default());
    let (a, b) = (node(&dir), node(&dir));
    let e = a.net.request(b.id, 1, vec![], T).await.unwrap_err();
    assert!(e.to_string().contains("not in a cluster"), "{e:#}");
    let e = a
        .net
        .forward_via(b.id, b.id, 1, vec![], false)
        .await
        .unwrap_err();
    assert!(matches!(e, cheesecloth_net::CallError::NotSent(_)), "{e:#}");
    assert!(a.net.push_state(b.id, b"x").await.is_err());
    assert!(
        a.net
            .probe(b.id, a.net.local_addr().unwrap())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn requests_time_out() {
    let dir = cluster();
    let (a, b) = (node(&dir), node(&dir));
    dir.members.lock().unwrap().extend([a.id, b.id]);
    let e = a
        .net
        .request(b.id, 1, vec![], Duration::ZERO)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("timed out"), "{e:#}");
}

#[tokio::test]
async fn soft_state_is_only_pushed_on_live_connections() {
    let dir = cluster();
    let (a, b) = (node(&dir), node(&dir));
    dir.members.lock().unwrap().extend([a.id, b.id]);
    let e = a.net.push_state(b.id, b"x").await.unwrap_err();
    assert!(e.to_string().contains("not connected"), "{e:#}");
}

#[tokio::test]
async fn a_relay_passes_on_the_destinations_refusal() {
    let dir = cluster();
    let (relay, n1, n2) = (node(&dir), node(&dir), node(&dir));
    dir.members.lock().unwrap().extend([relay.id, n1.id, n2.id]);
    dir.relays.lock().unwrap().push(relay.id);
    dir.hidden.lock().unwrap().extend([n1.id, n2.id]);
    n1.net.connect(relay.id).await.unwrap();
    n2.net.connect(relay.id).await.unwrap();
    let e = n1.net.request(n2.id, 99, vec![], T).await.unwrap_err();
    assert!(e.to_string().contains("refused"), "{e:#}");
    // Service 97 drops n1's connection to n2 (there is none) and answers
    // late, but through a relay the answer still arrives.
    let r = n1.net.request(n2.id, 97, vec![], T).await.unwrap();
    assert_eq!(r, b"too late");
}

#[tokio::test]
async fn relays_that_cant_deliver_leave_no_route() {
    let dir = cluster();
    let (relay, n1, n2) = (node(&dir), node(&dir), node(&dir));
    dir.members.lock().unwrap().extend([relay.id, n1.id, n2.id]);
    // The node itself and the destination in the list are skipped.
    dir.relays.lock().unwrap().extend([n1.id, n2.id, relay.id]);
    dir.hidden.lock().unwrap().extend([n1.id, n2.id]);
    n1.net.connect(relay.id).await.unwrap();
    // n2 isn't connected to the relay.
    let e = n1.net.request(n2.id, 5, vec![], T).await.unwrap_err();
    let msg = format!("{e:#}");
    assert!(msg.contains("no route"), "{msg}");
    assert!(msg.contains("not connected to this relay"), "{msg}");

    // A synchronized forward is refused the same way.
    let e = n1
        .net
        .forward_via(relay.id, n2.id, 5, vec![], true)
        .await
        .unwrap_err();
    assert!(matches!(e, cheesecloth_net::CallError::NotSent(_)), "{e:#}");

    // A relay refuses to forward to non-members.
    let stranger = NodeId([7; 32]);
    let e = n1
        .net
        .forward_via(relay.id, stranger, 5, vec![], false)
        .await
        .unwrap_err();
    assert!(format!("{e:#}").contains("not a member"), "{e:#}");
}

#[tokio::test]
async fn an_unreachable_relay_is_not_sent_anything() {
    let dir = cluster();
    let (n1, n2) = (node(&dir), node(&dir));
    let gone = NodeId([8; 32]);
    dir.members.lock().unwrap().extend([n1.id, n2.id, gone]);
    let e = n1
        .net
        .forward_via(gone, n2.id, 5, vec![], false)
        .await
        .unwrap_err();
    assert!(matches!(e, cheesecloth_net::CallError::NotSent(_)), "{e:#}");
}

/// Sends one request on a raw connection and returns the decoded result.
async fn raw_request(conn: &quinn::Connection, kind: u8, body: &[u8]) -> Result<Vec<u8>, String> {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let mut header = vec![kind];
    header.extend_from_slice(&[42; 32]);
    header.extend_from_slice(&cheesecloth_core::now_ms().to_be_bytes());
    send.write_all(&header).await.unwrap();
    send.write_all(body).await.unwrap();
    send.finish().unwrap();
    let resp = recv.read_to_end(1 << 16).await.unwrap();
    postcard::from_bytes(&resp[8..]).unwrap()
}

#[tokio::test]
async fn members_only_streams_refuse_guests() {
    let dir = cluster();
    let a = node(&dir);
    dir.members.lock().unwrap().insert(a.id);
    let conn = raw_connect(&a, &Identity::generate()).await;
    for kind in [1, 3, 5, 6] {
        let e = raw_request(&conn, kind, b"").await.unwrap_err();
        assert!(e.contains("not a member"), "kind {kind}: {e}");
    }
}

#[tokio::test]
async fn malformed_member_requests_are_refused() {
    let dir = cluster();
    let a = node(&dir);
    let m = Identity::generate();
    dir.members.lock().unwrap().extend([a.id, m.node_id()]);
    let conn = raw_connect(&a, &m).await;
    for kind in [1, 3, 5, 6] {
        assert!(
            raw_request(&conn, kind, &[0xff; 3]).await.is_err(),
            "kind {kind}"
        );
    }
    // State is one-way only.
    let e = raw_request(&conn, 2, b"").await.unwrap_err();
    assert!(e.contains("unexpected stream kind"), "{e}");
    // So is an unknown stream kind.
    assert!(raw_request(&conn, 9, b"").await.is_err());
}

#[tokio::test]
async fn binding_dual_stack_and_to_a_taken_port() {
    let dir = cluster();
    let a = node_with(&dir, NetOptions::new("[::]:0".parse().unwrap()));
    let port = a.net.local_addr().unwrap().port();
    assert!(port != 0);
    let taken = NetOptions::new(
        format!("127.0.0.1:{}", {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let p = s.local_addr().unwrap().port();
            std::mem::forget(s);
            p
        })
        .parse()
        .unwrap(),
    );
    let e = Net::bind(taken, Arc::new(Identity::generate()))
        .err()
        .unwrap();
    assert!(format!("{e:#}").contains("binding"), "{e:#}");
}

#[tokio::test]
async fn payload_budgets_include_framing_and_oversized_replies_return_errors() {
    let dir = cluster();
    let (a, b) = (node(&dir), node(&dir));
    dir.members.lock().unwrap().extend([a.id, b.id]);
    let error = a
        .net
        .request(b.id, 7, vec![0; cheesecloth_net::MAX_PAYLOAD + 1], T)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("wire budget"));
    let error = a.net.request(b.id, 96, vec![], T).await.unwrap_err();
    assert!(error.to_string().contains("encoded response exceeds"));
    let error = a
        .net
        .push_state(b.id, &vec![0; cheesecloth_net::MAX_PAYLOAD + 1])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("wire budget"));
    // A bounded request can still use the same connection after either error.
    assert!(a.net.request(b.id, 7, b"ok".to_vec(), T).await.is_ok());
    a.net.close();
    b.net.close();
}
