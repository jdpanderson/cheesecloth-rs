//! A single `Node` for unit tests: a real cluster in which this node is the
//! founder and the only acceptor, a control-plane endpoint on localhost, the
//! mock WireGuard backend, and no loops running. The peers are members that
//! exist only as member records and the soft state tests publish for them.

use std::sync::Arc;

use cheesecloth_core::{
    ClusterId, Domain, Identity, NodeId, WgKey, now_ms,
    state::{
        ClusterState, Command, CommandBody, MemberInfo, Outcome, Request, Settings, SignedCommand,
        invite_id,
    },
};
use cheesecloth_net::{Net, NetOptions};
use cheesecloth_paxos::Acceptor;
use cheesecloth_wg::BackendKind;

use crate::{
    Options, RelayMode,
    files::Files,
    node::{Chosen, Node, StoredAcceptor, proof},
    soft::SoftState,
};

/// A peer that exists only as a member record and signed soft state.
pub struct Peer {
    pub identity: Identity,
    pub info: MemberInfo,
}

impl Peer {
    pub fn id(&self) -> NodeId {
        self.identity.node_id()
    }
}

pub struct Harness {
    pub node: Arc<Node>,
    pub peers: Vec<Peer>,
    seq: std::sync::atomic::AtomicU64,
    /// Holds the node's state directory.
    pub dir: tempfile::TempDir,
}

/// Starts a node that founded a cluster (100.64.0.0/24, so it's 100.64.0.1)
/// and admitted one peer per `relays` entry (100.64.0.2, ...); `true` makes
/// the peer a relay.
pub async fn harness(relay: RelayMode, relays: &[bool]) -> Harness {
    harness_with(relay, relays, |_| {}).await
}

/// Like `harness`, with further changes to the options.
pub async fn harness_with(
    relay: RelayMode,
    relays: &[bool],
    tweak: impl FnOnce(&mut Options),
) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let mut opts = Options::new(dir.path().to_path_buf(), Some("me".into())).unwrap();
    opts.bind_ip = "127.0.0.1".parse().unwrap();
    opts.listen_port = 0;
    opts.wg_port = 51999;
    opts.relay = relay;
    opts.backend = BackendKind::Mock;
    opts.interface = "mock-test".into();
    opts.port_mapping = false;
    tweak(&mut opts);
    let identity = Arc::new(Identity::generate());
    let net = Net::bind(
        NetOptions::new("127.0.0.1:0".parse().unwrap()),
        identity.clone(),
    )
    .unwrap();
    let (wg_private, wg_public) = cheesecloth_wg::generate_keypair();
    let me = MemberInfo {
        node_id: identity.node_id(),
        wg_key: wg_public,
        name: "me".into(),
        control_addrs: vec![net.local_addr().unwrap()],
        wg_port: 51999,
        relay: relay == RelayMode::Always,
    };
    let peers: Vec<Peer> = relays
        .iter()
        .enumerate()
        .map(|(i, relay)| {
            let identity = Identity::generate();
            let info = MemberInfo {
                node_id: identity.node_id(),
                wg_key: WgKey(identity.node_id().0),
                name: format!("peer{i}"),
                control_addrs: vec![format!("192.0.2.{}:51821", i + 2).parse().unwrap()],
                wg_port: 51820,
                relay: *relay,
            };
            Peer { identity, info }
        })
        .collect();

    // The first state: genesis, then an invite and its redemption for each
    // peer.
    let mut state = ClusterState::default();
    let mut apply = |command| {
        let out = state.apply(&Request {
            at_ms: now_ms(),
            command: signed(&identity, state.cluster_id, command),
        });
        out.unwrap()
    };
    let founder = identity.seal(Domain::MemberInfo, &me);
    let Outcome::Genesis { cluster_id } = apply(Command::Genesis {
        nonce: [0; 16],
        settings: Settings::new("100.64.0.0/24".parse().unwrap()),
        founder,
    }) else {
        panic!("genesis failed");
    };
    for (i, p) in peers.iter().enumerate() {
        let secret = [i as u8 + 1; 32];
        apply(Command::CreateInvite {
            invite_id: invite_id(&secret),
        });
        let joiner = p.identity.seal(Domain::MemberInfo, &p.info);
        apply(Command::RedeemInvite { secret, joiner });
    }
    let files = Files::new(&dir.path().join("state")).unwrap();
    let first = Chosen::genesis(identity.node_id(), state);
    let cert = proof::genesis(&identity, cluster_id, &first);
    StoredAcceptor::create(files.acceptor(), Acceptor::genesis(first, cert)).unwrap();

    let node = start(opts, cluster_id, identity, wg_private, net, files);
    Harness {
        node,
        peers,
        seq: 1.into(),
        dir,
    }
}

fn start(
    opts: Options,
    cluster_id: ClusterId,
    identity: Arc<Identity>,
    wg_private: [u8; 32],
    net: Net,
    files: Files,
) -> Arc<Node> {
    Node::start(Arc::new(opts), cluster_id, identity, wg_private, net, files).unwrap()
}

impl Harness {
    /// A proof of `chosen`, signed by those of this node and its peers that
    /// are acceptors of its configuration.
    pub fn certify(&self, chosen: &Chosen) -> proof::Certificate {
        let header = proof::Header::of(self.node.cluster_id, &chosen.value);
        let ballot = chosen.ballot.clone().expect("a ballot");
        let mut cert =
            proof::Certificate::sign(&self.node.identity, header.clone(), ballot.clone());
        cert.sigs.clear();
        let identities =
            std::iter::once(&*self.node.identity).chain(self.peers.iter().map(|p| &p.identity));
        for id in identities {
            if chosen.value.config.acceptors.contains(&id.node_id()) {
                let one = proof::Certificate::sign(id, header.clone(), ballot.clone());
                cert.sigs.extend(one.sigs);
            }
        }
        cert
    }

    /// `chosen` with its proof (see `certify`), as another member sends it.
    pub fn proven(&self, chosen: Chosen) -> proof::Proven {
        proof::Proven {
            cert: self.certify(&chosen),
            chosen,
            transitions: Vec::new(),
        }
    }

    /// Has the node learn `chosen`, with its proof.
    pub async fn learn(&self, chosen: Chosen) -> anyhow::Result<()> {
        let p = self.proven(chosen);
        self.node.learn(p.chosen, p.cert, p.transitions).await
    }

    /// Publishes `state` as peer `i`'s soft state entry.
    pub fn soft(&self, i: usize, state: SoftState) {
        let p = &self.peers[i];
        let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let signed = p.identity.seal(
            Domain::SoftState,
            &SoftState {
                node: p.id(),
                seq,
                ..state
            },
        );
        assert!(self.node.soft.lock().merge(signed, |_| true));
    }
}

/// A command signed by `id`, as a member would submit it.
pub fn signed(id: &Identity, cluster_id: Option<ClusterId>, command: Command) -> SignedCommand {
    id.seal(
        Domain::Command,
        &CommandBody {
            cluster_id,
            issued_at_ms: now_ms(),
            command,
        },
    )
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.node.net.close();
    }
}

/// A whole daemon on localhost, with a mock WireGuard backend, for tests that
/// need real connections. `Always` relays get an unreachable public address,
/// so the test doesn't depend on the host having one.
pub async fn daemon(name: &str, relay: RelayMode) -> (Arc<crate::Daemon>, tempfile::TempDir) {
    let free_port = || {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let dir = tempfile::tempdir().unwrap();
    let mut opts = Options::new(dir.path().to_path_buf(), Some(name.into())).unwrap();
    opts.bind_ip = "127.0.0.1".parse().unwrap();
    opts.listen_port = free_port();
    opts.wg_port = free_port();
    opts.relay = relay;
    if relay == RelayMode::Always {
        opts.advertise = vec!["203.0.113.1".parse().unwrap()];
    }
    opts.backend = BackendKind::Mock;
    opts.interface = format!("mock-{name}");
    opts.port_mapping = false;
    (crate::Daemon::start(opts).await.unwrap(), dir)
}
