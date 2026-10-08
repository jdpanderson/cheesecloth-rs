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

#[test]
fn idle_interfaces_have_networks_but_no_usable_addresses() {
    let mut ifaces = Interfaces::default();
    ifaces.add("10.0.0.117".parse().unwrap(), 24, true);
    ifaces.add("2600:1:2:3::5".parse().unwrap(), 64, true);
    // An idle Docker bridge.
    ifaces.add("172.17.0.1".parse().unwrap(), 16, false);
    // Never usable.
    ifaces.add("fe80::1".parse().unwrap(), 64, true);
    assert_eq!(
        ifaces.ips,
        [
            "10.0.0.117".parse::<IpAddr>().unwrap(),
            "2600:1:2:3::5".parse().unwrap()
        ]
    );
    assert_eq!(ifaces.global, ["2600:1:2:3::5".parse::<IpAddr>().unwrap()]);
    // The bridge's network still counts, e.g. when choosing an overlay range.
    let nets: Vec<String> = ifaces.nets.iter().map(ToString::to_string).collect();
    assert_eq!(nets, ["10.0.0.0/24", "2600:1:2:3::/64", "172.17.0.0/16"]);
}
