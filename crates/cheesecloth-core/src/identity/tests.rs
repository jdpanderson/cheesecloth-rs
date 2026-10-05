use super::*;

#[test]
fn signatures_are_domain_separated() {
    let id = Identity::generate();
    let sealed = id.seal(Domain::Command, &42u32);
    assert_eq!(sealed.open(Domain::Command).unwrap(), 42);
    assert!(sealed.open(Domain::Forwarded).is_err());

    let mut forged = sealed.clone();
    forged.body = postcard::to_stdvec(&43u32).unwrap();
    assert!(forged.open(Domain::Command).is_err());
}

#[test]
fn envelopes_compare_and_hash_by_content() {
    let id = Identity::generate();
    let a = id.seal(Domain::Command, &1u8);
    let b = a.clone();
    assert_eq!(a, b);
    assert_eq!(a.digest(), b.digest());
    let c = id.seal(Domain::Command, &2u8);
    assert_ne!(a, c);
    assert_ne!(a.digest(), c.digest());
    assert!(format!("{a:?}").contains("body_len: 1"));
    // A body that isn't the promised type fails to decode.
    let wrong = id.seal(Domain::Command, &());
    let wrong: Signed<u64> = Signed {
        signer: wrong.signer,
        body: wrong.body,
        sig: wrong.sig,
        _marker: std::marker::PhantomData,
    };
    assert!(matches!(wrong.open(Domain::Command), Err(Error::Parse(_))));
}

#[test]
fn a_non_key_signer_fails_verification() {
    let id = Identity::generate();
    let sig = id.sign(Domain::Command, b"x");
    // Not a valid ed25519 point.
    let bogus = NodeId([0xff; 32]);
    assert!(verify(&bogus, Domain::Command, b"x", &sig).is_err());
    assert!(verify(&id.node_id(), Domain::Command, b"x", &sig).is_ok());
}

#[test]
fn keys_are_created_once_and_reloaded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sub/identity.key");
    let a = Identity::load_or_create(&path).unwrap();
    let b = Identity::load_or_create(&path).unwrap();
    assert_eq!(a.node_id(), b.node_id());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    std::fs::write(&path, b"short").unwrap();
    let err = Identity::load_or_create(&path).err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    // A directory in the way is some other I/O error, passed through.
    assert!(Identity::load_or_create(dir.path()).is_err());
}

/// Keys, signatures and envelopes are stored on disk and sent between nodes,
/// so their bytes must never change, even with a new ed25519 library.
#[test]
fn signed_envelopes_keep_their_bytes() {
    let id = Identity::from_secret([7; 32]);
    let sealed = id.seal(Domain::Command, &42u32);
    let golden = data_encoding::HEXLOWER
        .decode(
            b"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c\
              012a\
              60b522dbae1c2e3896b9781e31a0c4fd558bb38939e389b41c06877f15ed3a8b\
              1a669fad3acfcf8835e23903ba07c77d848d7d3eaaa63099dcbc1b42028a9705",
        )
        .unwrap();
    assert_eq!(postcard::to_stdvec(&sealed).unwrap(), golden);
    let decoded: Signed<u32> = postcard::from_bytes(&golden).unwrap();
    assert_eq!(decoded, sealed);
    assert_eq!(decoded.open(Domain::Command).unwrap(), 42);
    // A signature that is cut short doesn't decode.
    assert!(postcard::from_bytes::<Signed<u32>>(&golden[..golden.len() - 1]).is_err());
}
