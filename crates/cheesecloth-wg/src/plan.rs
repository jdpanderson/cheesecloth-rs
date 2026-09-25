//! How to reach a peer over WireGuard. Pure logic, so it can be tested.

use std::net::{IpAddr, SocketAddr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// What this node knows about itself.
#[derive(Clone, Debug, Default)]
pub struct Local {
    /// Publicly reachable (confirmed by a dial-back).
    pub public: bool,
    /// Networks of this node's interfaces.
    pub nets: Vec<IpNet>,
    /// The public IP the NAT gives this node, as a relay sees it (or its own
    /// address when public).
    pub public_ip: Option<IpAddr>,
    /// The cluster has at least one relay.
    pub have_relays: bool,
}

/// What this node knows about a peer.
#[derive(Clone, Debug, Default)]
pub struct Remote {
    /// The peer's WireGuard endpoints on the public internet, when the peer is
    /// publicly reachable.
    pub public_endpoints: Vec<SocketAddr>,
    /// The peer's WireGuard endpoints on its own LAN(s).
    pub lan_endpoints: Vec<SocketAddr>,
    /// The peer's public IP, as a relay sees it.
    pub public_ip: Option<IpAddr>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "endpoint")]
pub enum Path {
    /// Same site: use the peer's LAN address.
    Lan(SocketAddr),
    /// The peer is publicly reachable at this endpoint.
    Public(SocketAddr),
    /// This node is public and the peer isn't: the peer connects to us, and
    /// WireGuard learns its endpoint.
    Await,
    /// Both are behind NAT: a coordinated punch is needed.
    Punch,
}

fn prefer_v4(addrs: &[SocketAddr]) -> Option<SocketAddr> {
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .copied()
}

pub fn plan(local: &Local, remote: &Remote) -> Path {
    let same_site = match (local.public_ip, remote.public_ip) {
        (Some(a), Some(b)) => a == b,
        // Without relays nobody observes public addresses; assume a LAN-only
        // cluster.
        _ => !local.have_relays,
    };
    if same_site {
        let on_my_lan = remote
            .lan_endpoints
            .iter()
            .find(|e| local.nets.iter().any(|n| n.contains(&e.ip())));
        if let Some(e) = on_my_lan {
            return Path::Lan(*e);
        }
    }
    if let Some(e) = prefer_v4(&remote.public_endpoints) {
        return Path::Public(e);
    }
    if local.public {
        return Path::Await;
    }
    Path::Punch
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn natted(ip: &str, net: &str) -> Local {
        Local {
            public: false,
            nets: vec![net.parse().unwrap()],
            public_ip: Some(ip.parse().unwrap()),
            have_relays: true,
        }
    }

    #[test]
    fn same_nat_uses_lan() {
        let me = natted("203.0.113.1", "192.168.1.0/24");
        let peer = Remote {
            lan_endpoints: vec![sa("192.168.1.20:51820")],
            public_ip: Some("203.0.113.1".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(plan(&me, &peer), Path::Lan(sa("192.168.1.20:51820")));
    }

    #[test]
    fn same_subnet_behind_different_nats_punches() {
        let me = natted("203.0.113.1", "192.168.1.0/24");
        let peer = Remote {
            lan_endpoints: vec![sa("192.168.1.20:51820")],
            public_ip: Some("198.51.100.7".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(plan(&me, &peer), Path::Punch);
    }

    #[test]
    fn public_peer_is_dialled_and_public_node_waits() {
        let me = natted("203.0.113.1", "192.168.1.0/24");
        let relay = Remote {
            public_endpoints: vec![sa("[2001:db8::1]:51820"), sa("198.51.100.9:51820")],
            public_ip: Some("198.51.100.9".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(plan(&me, &relay), Path::Public(sa("198.51.100.9:51820")));

        let public_me = Local { public: true, ..me };
        let natted_peer = Remote {
            public_ip: Some("192.0.2.4".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(plan(&public_me, &natted_peer), Path::Await);
    }

    #[test]
    fn lan_only_cluster_without_relays() {
        let me = Local {
            nets: vec!["10.0.0.0/24".parse().unwrap()],
            ..Default::default()
        };
        let peer = Remote {
            lan_endpoints: vec![sa("10.0.0.5:51820")],
            ..Default::default()
        };
        assert_eq!(plan(&me, &peer), Path::Lan(sa("10.0.0.5:51820")));
    }
}
