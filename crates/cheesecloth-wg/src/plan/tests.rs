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
