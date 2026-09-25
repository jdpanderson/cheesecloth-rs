use super::*;

#[test]
fn names_fit_in_a_member_record() {
    assert_eq!(cut_name("short".into()), "short");
    // 20 two-byte characters: cut to 16 of them, not in the middle of one.
    assert_eq!(cut_name("é".repeat(20)), "é".repeat(16));
    let opts = Options::new(PathBuf::from("/tmp"), None).unwrap();
    assert!(opts.check().is_ok());
    let opts = Options::new(PathBuf::from("/tmp"), Some("n".repeat(MAX_NAME_LEN + 1))).unwrap();
    let e = opts.check().unwrap_err();
    assert!(e.contains("longer than 32 bytes"), "{e}");
}
