use super::*;

#[test]
fn cluster_files_round_trip_and_are_forgotten() {
    let tmp = tempfile::tempdir().unwrap();
    let files = Files::new(&tmp.path().join("state")).unwrap();
    assert!(files.load_cluster().unwrap().is_none());
    let c = ClusterFile {
        cluster_id: ClusterId([3; 32]),
        pending: Some(PendingJoin {
            proposal: cheesecloth_core::ProposalId([4; 32]),
            peers: vec![],
        }),
    };
    files.save_cluster(&c).unwrap();
    crate::node::StoredAcceptor::create(files.acceptor(), pnyx::Acceptor::default()).unwrap();
    fs::write(files.legacy_acceptor(), b"acceptor").unwrap();
    let back = files.load_cluster().unwrap().unwrap();
    assert_eq!(back.cluster_id, c.cluster_id);
    assert_eq!(
        back.pending.unwrap().proposal,
        cheesecloth_core::ProposalId([4; 32])
    );
    files.delete_cluster().unwrap();
    assert!(files.load_cluster().unwrap().is_none());
    assert!(!crate::testing::has_acceptor(&files));
    assert!(!files.legacy_acceptor().exists());
    // Already gone: fine.
    files.delete_cluster().unwrap();

    // Files without the optional fields still load.
    fs::write(
        files.cluster(),
        format!("{{\"cluster_id\": \"{}\"}}", ClusterId([3; 32])),
    )
    .unwrap();
    let old = files.load_cluster().unwrap().unwrap();
    assert!(old.pending.is_none());
}

#[test]
fn broken_files_are_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let files = Files::new(tmp.path()).unwrap();
    fs::write(files.cluster(), b"{not json").unwrap();
    let e = files.load_cluster().unwrap_err();
    assert!(format!("{e:#}").contains("cluster.json"), "{e:#}");

    // Something other than a file in the way.
    fs::remove_file(files.cluster()).unwrap();
    fs::create_dir(files.cluster()).unwrap();
    assert!(files.load_cluster().is_err());
    assert!(files.delete_cluster().is_err());

    fs::write(files.wg_key(), b"short").unwrap();
    let e = files.load_or_create_wg_key().unwrap_err();
    assert!(e.to_string().contains("32 bytes"), "{e:#}");
    fs::remove_file(files.wg_key()).unwrap();
    let key = files.load_or_create_wg_key().unwrap();
    assert_eq!(files.load_or_create_wg_key().unwrap(), key);
    fs::remove_file(files.wg_key()).unwrap();
    fs::create_dir(files.wg_key()).unwrap();
    assert!(files.load_or_create_wg_key().is_err());
}
