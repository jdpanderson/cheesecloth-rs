use super::*;

#[test]
fn control_addrs_fit_in_a_member_record() {
    let public: SocketAddr = "203.0.113.1:51821".parse().unwrap();
    let mut ifaces = Interfaces {
        ips: vec!["192.168.1.2".parse().unwrap()],
        ..Default::default()
    };
    ifaces
        .ips
        .extend((1..40u16).map(|i| IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, i])));
    let addrs = control_addrs(&[public], "::".parse().unwrap(), 51821, &ifaces);
    assert_eq!(addrs.len(), MAX_CONTROL_ADDRS);
    // The advertised address and IPv4 are kept.
    assert_eq!(addrs[0], public);
    assert_eq!(addrs[1], "192.168.1.2:51821".parse().unwrap());

    // A public node's global address is both advertised and on an
    // interface: listed once.
    let global: IpAddr = "203.0.113.1".parse().unwrap();
    let ifaces = Interfaces {
        ips: vec!["192.168.1.2".parse().unwrap(), global],
        ..Default::default()
    };
    let addrs = control_addrs(&[public], "::".parse().unwrap(), 51821, &ifaces);
    assert_eq!(addrs, [public, "192.168.1.2:51821".parse().unwrap()]);
}
