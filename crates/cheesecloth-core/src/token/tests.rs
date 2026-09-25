use super::*;

#[test]
fn token_round_trips() {
    let t = InviteToken {
        cluster_id: ClusterId([1; 32]),
        secret: [2; 32],
        peers: vec![TokenPeer {
            node_id: NodeId([3; 32]),
            addrs: vec![
                "203.0.113.5:51821".parse().unwrap(),
                "[2001:db8::1]:51821".parse().unwrap(),
            ],
        }],
    };
    let s = t.to_string();
    assert!(s.starts_with("cc1"));
    assert_eq!(s.parse::<InviteToken>().unwrap(), t);
    assert!("cc1garbage".parse::<InviteToken>().is_err());
    assert!(
        "cc1AAAA".parse::<InviteToken>().is_err(),
        "not a token body"
    );
    assert!(s[3..].parse::<InviteToken>().is_err(), "no prefix");
    assert_eq!(format!(" {s}\n").parse::<InviteToken>().unwrap(), t);
}
