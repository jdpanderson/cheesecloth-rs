use super::*;

#[test]
fn backend_kinds_parse() {
    for (s, k) in [
        ("auto", BackendKind::Auto),
        ("kernel", BackendKind::Kernel),
        ("userspace", BackendKind::Userspace),
        ("mock", BackendKind::Mock),
    ] {
        assert_eq!(s.parse::<BackendKind>().unwrap(), k);
    }
    assert!("wg".parse::<BackendKind>().is_err());
    assert!(!default_interface_name().is_empty());
}

#[test]
fn public_keys_derive_from_private_keys() {
    let (private, public) = generate_keypair();
    assert_eq!(public_key(&private), public);
    assert_ne!(generate_keypair().1, public);
}

#[test]
fn handshake_age_ignores_the_epoch() {
    let mut s = PeerStatus {
        key: WgKey([1; 32]),
        endpoint: None,
        last_handshake: None,
        rx_bytes: 0,
        tx_bytes: 0,
        keepalive: 0,
    };
    assert_eq!(s.handshake_age(), None);
    // WireGuard reports "never" as the epoch.
    s.last_handshake = Some(SystemTime::UNIX_EPOCH);
    assert_eq!(s.handshake_age(), None);
    s.last_handshake = Some(SystemTime::now() - Duration::from_secs(5));
    let age = s.handshake_age().unwrap();
    assert!(age >= Duration::from_secs(5) && age < Duration::from_secs(60));
    // A handshake "in the future" (clock step) counts as just now.
    s.last_handshake = Some(SystemTime::now() + Duration::from_secs(60));
    assert_eq!(s.handshake_age(), Some(Duration::ZERO));
}

#[test]
fn the_mock_records_configuration() {
    let config = InterfaceConfig {
        name: "mock0".into(),
        private_key: [1; 32],
        listen_port: 51820,
        addresses: vec!["100.64.0.1/24".parse().unwrap()],
        routes: vec![],
        mtu: None,
    };
    let mut b = open(BackendKind::Mock, &config).unwrap();
    assert_eq!(b.kind(), "mock");
    let with = PeerConfig {
        key: WgKey([2; 32]),
        endpoint: Some("192.0.2.1:51820".parse().unwrap()),
        keepalive: 25,
        allowed_ips: vec!["100.64.0.2/32".parse().unwrap()],
    };
    let without = PeerConfig {
        key: WgKey([3; 32]),
        endpoint: None,
        ..with.clone()
    };
    b.set_peer(&with).unwrap();
    b.set_peer(&without).unwrap();
    let mut status = b.status().unwrap();
    status.sort_by_key(|s| s.key);
    assert_eq!(status.len(), 2);
    assert!(status[0].handshake_age().is_some(), "endpoint: handshaken");
    assert_eq!(status[0].keepalive, 25);
    assert!(status[1].handshake_age().is_none(), "no endpoint: never");
    b.remove_peer(&with.key).unwrap();
    assert_eq!(b.status().unwrap().len(), 1);
    b.down().unwrap();
    assert!(b.status().unwrap().is_empty());
}
