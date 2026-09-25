use super::*;

#[test]
fn only_our_raw_ed25519_keys_are_accepted() {
    let id = Identity::generate();
    let spki = [&ED25519_SPKI_PREFIX[..], id.node_id().as_bytes()].concat();
    assert_eq!(presented_key(&spki).unwrap(), id.node_id());
    assert!(presented_key(&spki[1..]).is_err(), "wrong length");
    let mut other = spki.clone();
    other[0] ^= 1;
    assert!(presented_key(&other).is_err(), "not an ed25519 SPKI");

    let server = PinnedServer {
        expected: NodeId([1; 32]),
        provider: provider(),
    };
    let cert = CertificateDer::from(spki);
    let name = ServerName::try_from("cheesecloth").unwrap();
    let now = UnixTime::now();
    assert!(
        server
            .verify_server_cert(&cert, &[], &name, &[], now)
            .is_err()
    );
    let client = AnyEd25519Client {
        provider: provider(),
    };
    assert!(client.verify_client_cert(&cert, &[], now).is_ok());
}
