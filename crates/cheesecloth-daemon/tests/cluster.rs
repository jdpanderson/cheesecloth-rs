//! Whole daemons in one process on localhost, with a mock WireGuard backend.
//! One node is a relay; the others count as NATed, so they only reach each
//! other through it.

use std::{net::UdpSocket, sync::Arc, time::Duration};

use cheesecloth_core::state::Outcome;
use cheesecloth_daemon::{
    Daemon, Options, RelayMode,
    api::{self, ApiRequest, PeerView, StatusView},
};
use cheesecloth_wg::BackendKind;
use serde_json::Value;

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct TestNode {
    daemon: Arc<Daemon>,
    name: String,
    _dir: tempfile::TempDir,
}

async fn start(name: &str, relay: RelayMode) -> TestNode {
    start_in(name, relay, tempfile::tempdir().unwrap()).await
}

/// A second daemon with the same keys as `like` (as if it had lost its
/// cluster state, or never got the answer to its join).
async fn start_as(name: &str, like: &TestNode) -> TestNode {
    let dir = tempfile::tempdir().unwrap();
    for f in ["identity.key", "wireguard.key"] {
        std::fs::copy(like._dir.path().join(f), dir.path().join(f)).unwrap();
    }
    start_in(name, RelayMode::Auto, dir).await
}

async fn start_in(name: &str, relay: RelayMode, dir: tempfile::TempDir) -> TestNode {
    let daemon = Daemon::start(options(name, relay, &dir)).await.unwrap();
    TestNode {
        daemon,
        name: name.into(),
        _dir: dir,
    }
}

fn options(name: &str, relay: RelayMode, dir: &tempfile::TempDir) -> Options {
    let mut opts = Options::new(dir.path().to_path_buf(), Some(name.into())).unwrap();
    opts.bind_ip = "127.0.0.1".parse().unwrap();
    opts.listen_port = 0;
    opts.wg_port = free_port();
    opts.relay = relay;
    // Give relays a public address (unreachable, like the host's own global
    // ones), so the tests don't depend on the host having one.
    if relay == RelayMode::Always {
        opts.advertise = vec!["203.0.113.1".parse().unwrap()];
    }
    opts.backend = BackendKind::Mock;
    opts.interface = format!("mock-{name}");
    // Never touch the real router of the machine running the tests.
    opts.port_mapping = false;
    opts
}

/// Logs with the filter in `RUST_LOG`, or only errors without it.
fn init_tracing() {
    use tracing_subscriber::{
        filter::{LevelFilter, Targets},
        prelude::*,
    };
    let filter: Targets = match std::env::var("RUST_LOG") {
        Ok(s) => s.parse().expect("a valid RUST_LOG filter"),
        Err(_) => Targets::new().with_default(LevelFilter::ERROR),
    };
    let output = tracing_subscriber::fmt::layer().with_test_writer();
    let _ = tracing_subscriber::registry()
        .with(output)
        .with(filter)
        .try_init();
}

async fn eventually<F, Fut>(what: &str, secs: u64, f: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..secs * 5 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("timed out waiting for {what}");
}

async fn status(n: &TestNode) -> StatusView {
    n.daemon.status().await.unwrap()
}

async fn members(n: &TestNode) -> usize {
    n.daemon.peers().map(|p| p.len()).unwrap_or(0)
}

async fn invite(n: &TestNode) -> String {
    let v = n.daemon.invite().await.unwrap();
    v.token
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cluster_lifecycle() {
    init_tracing();
    let a = start("a", RelayMode::Always).await;
    let b = start("b", RelayMode::Auto).await;
    let c = start("c", RelayMode::Auto).await;

    // Genesis.
    let v = a
        .daemon
        .init(Some("100.64.42.0/24".parse().unwrap()))
        .await
        .unwrap();
    assert_eq!(v.ipv4_range.to_string(), "100.64.42.0/24");
    let s = status(&a).await;
    assert_eq!(s.phase, "member");
    assert_eq!(s.ipv4, Some("100.64.42.1".parse().unwrap()));
    assert!(a.daemon.init(None).await.is_err(), "init twice");

    // Joins.
    let token = invite(&a).await;
    let v = b.daemon.join(&token).await.unwrap();
    assert!(v.joined);
    assert_eq!(v.ipv4, Some("100.64.42.2".parse().unwrap()));

    // The token is burnt.
    let err = c.daemon.join(&token).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("unknown, expired or already used invite"),
        "{err:#}"
    );
    assert_eq!(status(&c).await.phase, "none");

    // An invite from a NATed member works too (redeemed through the relay).
    let token = invite(&b).await;
    c.daemon.join(&token).await.unwrap();

    for n in [&a, &b, &c] {
        eventually(&format!("{} sees 3 members", n.name), 30, || async {
            members(n).await == 3
        })
        .await;
    }
    // Every member becomes an acceptor (3 is the target).
    eventually("3 acceptors", 30, || async {
        status(&a).await.acceptors.len() == 3
    })
    .await;

    // b and c are "behind NAT": no direct connection, but the control plane
    // still works between them via the relay.
    let peers: Vec<PeerView> = b.daemon.peers().unwrap();
    let pc = peers.iter().find(|p| p.name == "c").unwrap();
    assert!(!pc.connected, "b must not dial c directly");
    let pa = peers.iter().find(|p| p.name == "a").unwrap();
    assert!(pa.relay && pa.connected);
    assert_eq!(pa.path, "public");

    // Any member can make changes.
    let token = invite(&c).await;
    assert!(token.starts_with("cc1"));

    // Remove c (no approvals needed by default); c notices and forgets the cluster.
    let cid = status(&c).await.node_id.to_string();
    b.daemon.remove(&cid[..10]).await.unwrap();
    eventually("c removed everywhere", 30, || async {
        members(&a).await == 2 && members(&b).await == 2
    })
    .await;
    eventually("c forgets the cluster", 30, || async {
        status(&c).await.phase == "none"
    })
    .await;

    // b leaves (it's an acceptor): a keeps working on its own.
    b.daemon.leave(false).await.unwrap();
    assert_eq!(status(&b).await.phase, "none");
    eventually("a alone", 30, || async { members(&a).await == 1 }).await;
    eventually("a is the only acceptor", 30, || async {
        status(&a).await.acceptors.len() == 1
    })
    .await;
    invite(&a).await;

    // A node that left can join again with a new invite.
    let token = invite(&a).await;
    b.daemon.join(&token).await.unwrap();
    eventually("b back", 30, || async { members(&a).await == 2 }).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_only_acceptor_can_leave() {
    init_tracing();
    let a = start("a", RelayMode::Always).await;
    let b = start("b", RelayMode::Auto).await;
    a.daemon.init(None).await.unwrap();
    b.daemon.join(&invite(&a).await).await.unwrap();
    eventually("b caught up", 30, || async { members(&b).await == 2 }).await;
    eventually("a connected to b", 30, || async {
        let peers = a.daemon.peers().unwrap();
        peers.iter().any(|p| p.name == "b" && p.connected)
    })
    .await;
    // With two members there is one acceptor: a, which founded the cluster.
    let a_id = status(&a).await.node_id;
    assert_eq!(status(&a).await.acceptors, [a_id]);

    let v = a.daemon.leave(false).await.unwrap();
    assert!(
        matches!(v, api::LeaveView::Left { ref problems, .. } if problems.is_empty()),
        "{v:?}"
    );
    assert_eq!(status(&a).await.phase, "none");
    // b was handed the role and the state before a stopped, so it can make
    // changes at once.
    assert_eq!(status(&b).await.acceptors, [status(&b).await.node_id]);
    invite(&b).await;
    assert_eq!(members(&b).await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forced_leave_stops_even_if_a_step_fails() {
    init_tracing();
    let a = start("a", RelayMode::Always).await;
    let b = start("b", RelayMode::Auto).await;
    a.daemon.init(None).await.unwrap();
    b.daemon.join(&invite(&a).await).await.unwrap();
    eventually("b caught up", 30, || async { members(&b).await == 2 }).await;
    b.daemon.shutdown().await;

    // b can't take over the role or the state.
    assert!(a.daemon.leave(false).await.is_err());
    assert_eq!(status(&a).await.phase, "member");

    let v = a.daemon.leave(true).await.unwrap();
    assert!(
        matches!(v, api::LeaveView::Left { ref problems, .. } if !problems.is_empty()),
        "{v:?}"
    );
    assert_eq!(status(&a).await.phase, "none");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_a_stopped_relay_is_quick() {
    init_tracing();
    let r1 = start("r1", RelayMode::Always).await;
    let r2 = start("r2", RelayMode::Always).await;
    let b = start("b", RelayMode::Auto).await;
    r1.daemon.init(None).await.unwrap();
    r2.daemon.join(&invite(&r1).await).await.unwrap();
    b.daemon.join(&invite(&r1).await).await.unwrap();
    eventually("3 acceptors", 30, || async {
        status(&r1).await.acceptors.len() == 3
    })
    .await;
    let r2_id = status(&r2).await.node_id.to_string();
    r2.daemon.shutdown().await;
    eventually("r2 no longer present for r1", 30, || async {
        let peers = r1.daemon.peers().unwrap();
        peers.iter().any(|p| p.name == "r2" && !p.present)
    })
    .await;

    // r2's addresses don't answer. Telling it of its removal, or of the
    // change as an acceptor, would wait for the requests to time out.
    let started = std::time::Instant::now();
    r1.daemon.remove(&r2_id[..10]).await.unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(members(&r1).await, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approvals_gate_joins() {
    init_tracing();
    let a = start("a", RelayMode::Always).await;
    let b = start("b", RelayMode::Auto).await;
    let c = start("c", RelayMode::Auto).await;
    a.daemon.init(None).await.unwrap();
    b.daemon.join(&invite(&a).await).await.unwrap();
    eventually("b caught up", 30, || async { members(&b).await == 2 }).await;

    // Needs the current threshold (0), so it applies at once.
    let v = a
        .daemon
        .config_set("approvals_required", "1")
        .await
        .unwrap();
    assert_eq!(v, Outcome::SettingChanged);
    // Can't exceed the members who could approve.
    assert!(
        a.daemon
            .config_set("approvals_required", "5")
            .await
            .is_err()
    );

    // c's join waits for one approval from someone other than a.
    let v = c.daemon.join(&invite(&a).await).await.unwrap();
    assert!(!v.joined);
    let proposal = v.proposal.unwrap();
    assert_eq!(status(&c).await.phase, "pending");
    let pending = a.daemon.pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].kind, "join");
    assert_eq!(pending[0].node, Some(status(&c).await.node_id));
    assert!(
        a.daemon.vote(proposal, true).await.is_err(),
        "proposer can't approve"
    );

    eventually("b sees the proposal", 30, || async {
        b.daemon.pending().map(|p| p.len() == 1).unwrap_or(false)
    })
    .await;
    let v = b.daemon.vote(proposal, true).await.unwrap();
    assert!(matches!(v, Outcome::Joined { .. }), "{v:?}");
    eventually("c joins after approval", 30, || async {
        status(&c).await.phase == "member"
    })
    .await;
    eventually("c caught up", 30, || async { members(&c).await == 3 }).await;

    // Lowering the threshold is itself a proposal now.
    let v = a
        .daemon
        .config_set("approvals_required", "0")
        .await
        .unwrap();
    assert!(matches!(v, Outcome::Pending { .. }), "{v:?}");

    // Leaving never needs approvals.
    c.daemon.leave(false).await.unwrap();
    eventually("c gone", 30, || async { members(&a).await == 2 }).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_api_over_the_socket() {
    init_tracing();
    let a = start("a", RelayMode::Always).await;
    let socket = a._dir.path().join("control.sock");
    tokio::spawn(a.daemon.clone().serve_api());
    eventually("socket", 10, || async { socket.exists() }).await;
    let s: StatusView = api::call(&socket, &ApiRequest::Status).await.unwrap();
    assert_eq!(s.phase, "none");
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&socket).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // A second daemon can't take over a live socket.
    let err = a.daemon.clone().serve_api().await.unwrap_err();
    assert!(format!("{err:#}").contains("already listening"), "{err:#}");
    let s: StatusView = api::call(&socket, &ApiRequest::Status).await.unwrap();
    assert_eq!(s.phase, "none");
    let v: Value = api::call(
        &socket,
        &ApiRequest::Init {
            ipv4_range: None,
            strict_security: false,
        },
    )
    .await
    .unwrap();
    assert!(v["ipv4_range"].as_str().unwrap().starts_with("100."));
    let err = api::call::<Value>(&socket, &ApiRequest::Remove { node: "zz".into() })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no member matches"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn guessed_invites_cost_no_change() {
    init_tracing();
    let a = start("a", RelayMode::Always).await;
    let b = start("b", RelayMode::Auto).await;
    a.daemon.init(None).await.unwrap();
    let valid = invite(&a).await;

    // Wait for the state to settle (genesis, member-record updates).
    let index = || async { status(&a).await.version };
    let mut last = index().await;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let now = index().await;
        if now == last {
            break;
        }
        last = now;
    }

    // A token for the right cluster and member, with a guessed secret.
    let mut guessed: cheesecloth_core::token::InviteToken = valid.parse().unwrap();
    guessed.secret = [7; 32];
    let err = b.daemon.join(&guessed.to_string()).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("unknown, expired or already used invite"),
        "{err:#}"
    );
    assert_eq!(
        index().await,
        last,
        "a guessed secret must not change the state"
    );

    // The real invite still works, and is burnt by its redemption.
    b.daemon.join(&valid).await.unwrap();
    assert!(index().await > last);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_redemption_is_answered_like_the_first() {
    init_tracing();
    let a = start("a", RelayMode::Always).await;
    let b = start("b", RelayMode::Auto).await;
    let c = start("c", RelayMode::Auto).await;
    a.daemon.init(None).await.unwrap();
    let token = invite(&a).await;
    let first = b.daemon.join(&token).await.unwrap();

    // b never saw that answer and asks again with the same (now used) token.
    b.daemon.shutdown().await;
    let b2 = start_as("b", &b).await;
    let again = b2.daemon.join(&token).await.unwrap();
    assert!(again.joined, "{again:?}");
    assert_eq!(again.ipv4, first.ipv4);

    // An existing member redeeming a live token still burns it.
    b2.daemon.shutdown().await;
    let b3 = start_as("b", &b).await;
    let fresh = invite(&a).await;
    let v = b3.daemon.join(&fresh).await.unwrap();
    assert_eq!(v.ipv4, first.ipv4);
    let err = c.daemon.join(&fresh).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("unknown, expired or already used invite"),
        "{err:#}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rejected_join_is_forgotten_even_after_a_restart() {
    init_tracing();
    let a = start("a", RelayMode::Always).await;
    let b = start("b", RelayMode::Auto).await;
    let c = start("c", RelayMode::Auto).await;
    a.daemon.init(None).await.unwrap();
    b.daemon.join(&invite(&a).await).await.unwrap();
    eventually("b caught up", 30, || async { members(&b).await == 2 }).await;
    a.daemon
        .config_set("approvals_required", "1")
        .await
        .unwrap();

    let v = c.daemon.join(&invite(&a).await).await.unwrap();
    let proposal = v.proposal.unwrap();
    let err = c.daemon.join(&invite(&a).await).await.unwrap_err();
    assert!(format!("{err:#}").contains("waiting to join"), "{err:#}");

    // c restarts while waiting, and picks up where it was.
    let TestNode { daemon, _dir, .. } = c;
    daemon.shutdown().await;
    drop(daemon);
    let c = start_in("c", RelayMode::Auto, _dir).await;
    let s = status(&c).await;
    assert_eq!(s.phase, "pending");
    assert_eq!(s.pending_proposal, Some(proposal));

    eventually("b sees the proposal", 30, || async {
        b.daemon.pending().map(|p| p.len() == 1).unwrap_or(false)
    })
    .await;
    b.daemon.vote(proposal, false).await.unwrap();
    eventually("c gives up", 30, || async {
        status(&c).await.phase == "none"
    })
    .await;
    assert!(!c._dir.path().join("cluster.json").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pending_join_can_be_cancelled_offline_and_stays_cancelled_after_restart() {
    let a = start("a", RelayMode::Always).await;
    let b = start("b", RelayMode::Auto).await;
    let c = start("c", RelayMode::Auto).await;
    a.daemon.init(None).await.unwrap();
    b.daemon.join(&invite(&a).await).await.unwrap();
    eventually("b caught up", 30, || async { members(&b).await == 2 }).await;
    a.daemon
        .config_set("approvals_required", "1")
        .await
        .unwrap();
    let join = c.daemon.join(&invite(&a).await).await.unwrap();
    assert!(!join.joined);
    let id = c.daemon.node_id();
    let keys = ["identity.key", "wireguard.key"]
        .map(|file| std::fs::read(c._dir.path().join(file)).unwrap());
    a.daemon.shutdown().await;
    b.daemon.shutdown().await;
    let result = tokio::time::timeout(Duration::from_secs(2), c.daemon.leave(false))
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(result, api::LeaveView::JoinCancelled { proposal, .. } if Some(proposal) == join.proposal)
    );
    assert_eq!(status(&c).await.phase, "none");
    let TestNode { daemon, _dir, .. } = c;
    daemon.shutdown().await;
    let c = start_in("c", RelayMode::Auto, _dir).await;
    assert_eq!(status(&c).await.phase, "none");
    assert_eq!(c.daemon.node_id(), id);
    for (file, key) in ["identity.key", "wireguard.key"].into_iter().zip(keys) {
        assert_eq!(std::fs::read(c._dir.path().join(file)).unwrap(), key);
    }
    c.daemon.init(None).await.unwrap();
    assert_eq!(status(&c).await.phase, "member");
    c.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_state_directory_is_explained() {
    init_tracing();
    let a = start("a", RelayMode::Always).await;
    a.daemon.init(None).await.unwrap();
    let TestNode { daemon, _dir, .. } = a;
    daemon.shutdown().await;
    drop(daemon);

    // As if written by an older version, in another format.
    // A start with no acceptor state is tested in `node::lifecycle_tests`.
    std::fs::write(_dir.path().join("acceptor.bin"), [0xff; 40]).unwrap();
    let e = Daemon::start(options("a", RelayMode::Always, &_dir))
        .await
        .err()
        .expect("the state can't be read");
    let e = format!("{e:#}");
    assert!(e.contains("older version of cheesecloth"), "{e}");
    assert!(e.contains("delete cluster.json, acceptor.*"), "{e}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn commands_explain_what_went_wrong() {
    init_tracing();
    let a = start("a", RelayMode::Always).await;
    let b = start("b", RelayMode::Auto).await;
    let err = |r: anyhow::Result<_>| format!("{:#}", r.map(|_: Outcome| ()).unwrap_err());
    assert!(err(a.daemon.remove("x").await).contains("not in a cluster"));
    a.daemon.init(None).await.unwrap();

    // Nobody listed in the token can be reached; nothing was sent.
    let mut dead: cheesecloth_core::token::InviteToken = invite(&a).await.parse().unwrap();
    dead.peers[0].addrs = vec!["127.0.0.1:9".parse().unwrap()];
    let e = b.daemon.join(&dead.to_string()).await.unwrap_err();
    assert!(
        format!("{e:#}").contains("couldn't reach any member"),
        "{e:#}"
    );
    assert!(b.daemon.join("not a token").await.is_err());
    // The same secret still works through a reachable member.
    let mut live = dead.clone();
    live.peers[0].addrs = vec![status(&a).await.control_addr.unwrap()];
    b.daemon.join(&live.to_string()).await.unwrap();
    let e = b.daemon.join(&invite(&a).await).await.unwrap_err();
    assert!(format!("{e:#}").contains("already in a cluster"), "{e:#}");

    let me = status(&a).await.node_id.to_string();
    assert!(err(a.daemon.remove(&me).await).contains("cheesecloth leave"));
    assert!(err(a.daemon.config_set("ipv4_range", "10.0.0.0/8").await).contains("fixed"));
    assert!(err(a.daemon.config_set("colour", "1").await).contains("unknown setting"));
    assert!(err(a.daemon.config_set("acceptors", "many").await).contains("expected a number"));
    assert!(err(a.daemon.config_set("approvals_required", "-1").await).contains("number"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strict_security_bootstraps_then_keeps_protection_and_pauses_without_quorum() {
    let a = start("strict-a", RelayMode::Always).await;
    let b = start("strict-b", RelayMode::Always).await;
    let c = start("strict-c", RelayMode::Always).await;
    let d = start("strict-d", RelayMode::Always).await;
    a.daemon.init_with_security(None, true).await.unwrap();
    let bootstrap = status(&a).await;
    assert!(bootstrap.strict_security);
    assert_eq!(bootstrap.security, "relaxed");
    for peer in [&b, &c, &d] {
        peer.daemon.join(&invite(&a).await).await.unwrap();
    }
    eventually("four protected voters", 40, || async {
        status(&a).await.security == "protected"
            && status(&b).await.security == "protected"
            && status(&c).await.security == "protected"
            && status(&d).await.security == "protected"
    })
    .await;
    let protected = status(&a).await;
    assert_eq!((protected.acceptors.len(), protected.quorum), (4, 3));
    a.daemon.config_set("buffer_nodes", "2").await.unwrap();
    assert_eq!(
        status(&a).await.security,
        "protected",
        "strict latch overrides requested reserve"
    );
    let error = a.daemon.config_set("acceptors", "3").await.unwrap_err();
    assert!(
        error.to_string().contains("disable strict_security"),
        "{error:#}"
    );
    c.daemon.shutdown().await;
    d.daemon.shutdown().await;
    eventually("loss of the installed quorum", 30, || async {
        status(&a).await.changes_paused
    })
    .await;
    let paused = status(&a).await;
    assert_eq!(
        (
            paused.security.as_str(),
            paused.acceptors.len(),
            paused.quorum
        ),
        ("protected", 4, 3)
    );
    assert!(paused.reachable_voters < paused.quorum);
    assert!(
        a.daemon.invite().await.is_err(),
        "two cannot commit using the four-voter configuration"
    );
    a.daemon.shutdown().await;
    b.daemon.shutdown().await;
}
