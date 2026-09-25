use super::*;

#[test]
fn classifies_addresses() {
    for ip in ["8.8.8.8", "2606:4700::1111", "::ffff:1.1.1.1"] {
        assert!(is_global(&ip.parse().unwrap()), "{ip}");
    }
    for ip in [
        "10.0.0.1",
        "192.168.1.1",
        "100.64.1.1",
        "127.0.0.1",
        "169.254.1.1",
        "fd00::1",
        "fe80::1",
        "::1",
        "2001:db8::1",
        "0.1.2.3",
    ] {
        assert!(!is_global(&ip.parse().unwrap()), "{ip}");
    }
}

#[test]
fn random_range_avoids_existing_routes() {
    let avoid: Vec<IpNet> = vec!["100.64.0.0/11".parse().unwrap()];
    for _ in 0..50 {
        let r = random_ipv4_range(&avoid).unwrap();
        assert_eq!(r.prefix_len(), 24);
        assert!(CGNAT_RANGE.contains(&r.network()));
        assert!(
            !"100.64.0.0/11"
                .parse::<Ipv4Net>()
                .unwrap()
                .contains(&r.network())
        );
    }
}

#[test]
fn ipv6_is_inside_the_cluster_prefix() {
    let c = ClusterId([1; 32]);
    let a = node_ipv6(&c, &NodeId([2; 32]));
    assert!(ula_prefix(&c).contains(&a));
    assert_eq!(a.segments()[0] >> 8, 0xfd);
    assert_ne!(a, node_ipv6(&c, &NodeId([3; 32])));
}
