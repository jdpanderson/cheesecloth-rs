//! Overlay addressing and address classification.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rand::RngExt;

use crate::{ClusterId, NodeId};

/// The shared address space that cheesecloth picks IPv4 ranges from.
pub const CGNAT_RANGE: Ipv4Net = match Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 10) {
    Ok(net) => net,
    Err(_) => panic!("valid"),
};

/// Picks a random /24 inside 100.64.0.0/10 that overlaps none of `avoid`.
pub fn random_ipv4_range(avoid: &[IpNet]) -> Option<Ipv4Net> {
    let mut rng = rand::rng();
    // 100.64.0.0/10 holds 2^14 /24s.
    for _ in 0..1000 {
        let n: u32 = rng.random_range(0..(1 << 14));
        let base = u32::from(CGNAT_RANGE.network()) + (n << 8);
        let net = Ipv4Net::new(Ipv4Addr::from(base), 24).expect("valid prefix");
        let overlaps = avoid.iter().any(|a| match a {
            IpNet::V4(a) => a.contains(&net.network()) || net.contains(&a.network()),
            IpNet::V6(_) => false,
        });
        if !overlaps {
            return Some(net);
        }
    }
    None
}

/// The cluster's IPv6 ULA /64, derived from the cluster ID (fdXX:XXXX:XXXX::/48,
/// subnet 0).
pub fn ula_prefix(cluster: &ClusterId) -> Ipv6Net {
    let h = blake3::derive_key("cheesecloth/1 ula", &cluster.0);
    let mut o = [0u8; 16];
    o[0] = 0xfd;
    o[1..6].copy_from_slice(&h[..5]);
    Ipv6Net::new(Ipv6Addr::from(o), 64).expect("valid prefix")
}

/// A node's overlay IPv6 address: the cluster prefix plus a hash of its ID.
pub fn node_ipv6(cluster: &ClusterId, node: &NodeId) -> Ipv6Addr {
    let prefix = ula_prefix(cluster).network().octets();
    let h = blake3::derive_key("cheesecloth/1 ula host", &node.0);
    let mut o = prefix;
    o[8..].copy_from_slice(&h[..8]);
    Ipv6Addr::from(o)
}

/// True for addresses that are routable on the public internet.
pub fn is_global(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_global_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_global_v4(&v4);
            }
            let seg0 = v6.segments()[0];
            // Global unicast is 2000::/3; exclude documentation 2001:db8::/32.
            (seg0 & 0xe000) == 0x2000 && !(seg0 == 0x2001 && v6.segments()[1] == 0x0db8)
        }
    }
}

fn is_global_v4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || o[0] == 0
        || o[0] >= 240
        || CGNAT_RANGE.contains(ip)
        // 192.0.0.0/24 (protocol assignments) and 198.18.0.0/15 (benchmarking)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] & 0xfe) == 18))
}

#[cfg(test)]
mod tests {
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
}
