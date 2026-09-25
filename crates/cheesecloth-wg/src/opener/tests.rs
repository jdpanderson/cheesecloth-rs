#[test]
fn builds_udp_header() {
    assert_eq!(
        super::udp_packet(51820, 4242, &[0]),
        vec![0xca, 0x6c, 0x10, 0x92, 0, 9, 0, 0, 0]
    );
}

#[test]
fn ipv6_is_refused() {
    let err = super::send(51820, "[2001:db8::1]:51820".parse().unwrap()).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
}
