use super::*;

#[test]
fn node_id_round_trips_in_json_and_postcard() {
    let id = NodeId([7; 32]);
    let json = serde_json::to_string(&id).unwrap();
    assert_eq!(json, format!("\"{id}\""));
    assert_eq!(serde_json::from_str::<NodeId>(&json).unwrap(), id);
    let bin = postcard::to_stdvec(&id).unwrap();
    assert_eq!(bin.len(), 32);
    assert_eq!(postcard::from_bytes::<NodeId>(&bin).unwrap(), id);
    assert_eq!(id.to_string().parse::<NodeId>().unwrap(), id);
}

#[test]
fn ids_parse_only_64_hex_digits() {
    assert!("zz".parse::<NodeId>().is_err());
    assert!("ab".repeat(31).parse::<ClusterId>().is_err());
    let id: ClusterId = "AB".repeat(32).parse().unwrap();
    assert_eq!(id, ClusterId([0xab; 32]));
    assert_eq!(format!("{id:?}"), format!("ClusterId({})", id.short()));
    // A string in JSON must be hex; postcard wants exactly 32 bytes.
    assert!(serde_json::from_str::<NodeId>("\"nope\"").is_err());
    assert!(postcard::from_bytes::<NodeId>(&[1, 2, 3]).is_err());
}

#[test]
fn wg_keys_are_base64_in_json_and_raw_in_postcard() {
    let key = WgKey([9; 32]);
    let json = serde_json::to_string(&key).unwrap();
    assert_eq!(json, format!("\"{key}\""));
    assert_eq!(serde_json::from_str::<WgKey>(&json).unwrap(), key);
    assert!(serde_json::from_str::<WgKey>("\"AAAA\"").is_err());
    assert!(serde_json::from_str::<WgKey>("\"!!\"").is_err());
    let bin = postcard::to_stdvec(&key).unwrap();
    assert_eq!(bin.len(), 32);
    assert_eq!(postcard::from_bytes::<WgKey>(&bin).unwrap(), key);
    assert_eq!(format!("{key:?}"), format!("WgKey({key})"));
}
