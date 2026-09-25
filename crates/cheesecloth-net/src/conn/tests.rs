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
