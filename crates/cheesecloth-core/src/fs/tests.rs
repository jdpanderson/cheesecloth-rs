use super::*;

#[test]
fn write_private_writes_and_replaces_a_whole_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sub/secret.key");
    write_private(&path, b"one").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"one");
    write_private(&path, b"two").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"two");
    assert!(!path.with_extension("tmp").exists());
}

#[test]
fn create_private_dir_makes_parents_and_can_run_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a/b");
    create_private_dir(&path).unwrap();
    assert!(path.is_dir());
    create_private_dir(&path).unwrap();
    assert!(path.is_dir());
}

#[test]
fn create_private_dir_refuses_a_file_in_the_way() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file");
    std::fs::write(&path, b"x").unwrap();
    assert!(create_private_dir(&path).is_err());
}

#[test]
fn sync_dir_works_on_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file"), b"x").unwrap();
    sync_dir(dir.path()).unwrap();
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_private_dir_is_0700_even_if_it_existed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        create_private_dir(&path).unwrap();
        assert_eq!(mode(&path), 0o700);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        create_private_dir(&path).unwrap();
        assert_eq!(mode(&path), 0o700);
    }

    #[test]
    fn a_private_file_is_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.key");
        write_private(&path, b"x").unwrap();
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn a_stale_tmp_file_does_not_keep_its_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.key");
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, b"stale").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&path, b"x").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
        assert_eq!(mode(&path), 0o600);
    }
}

#[cfg(windows)]
mod windows {
    #![allow(unsafe_code, reason = "the tests read access lists with windows-sys")]

    use std::{collections::BTreeSet, ptr};

    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
                SDDL_REVISION_1, SE_FILE_OBJECT,
            },
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        },
    };

    use super::*;
    use crate::fs::windows::{SecurityDescriptor, take_local_string, wide};

    /// The owner and the DACL of a descriptor, as SDDL strings.
    #[derive(Debug, PartialEq)]
    struct Security {
        owner: String,
        protected: bool,
        aces: BTreeSet<String>,
    }

    impl Security {
        fn of(sd: PSECURITY_DESCRIPTOR) -> Self {
            let mut s = ptr::null_mut();
            // SAFETY: sd is a valid descriptor and s is a valid place to write.
            let ok = unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    sd,
                    SDDL_REVISION_1,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    &mut s,
                    ptr::null_mut(),
                )
            };
            assert_ne!(ok, 0, "{}", io::Error::last_os_error());
            // SAFETY: the call allocated s with LocalAlloc, and only this
            // code uses it.
            let sddl = unsafe { take_local_string(s) }.unwrap();
            let (owner, dacl) = sddl
                .strip_prefix("O:")
                .and_then(|rest| rest.split_once("D:"))
                .expect(&sddl);
            Self {
                owner: owner.to_owned(),
                protected: dacl.starts_with('P'),
                aces: dacl
                    .split('(')
                    .skip(1)
                    .map(|ace| format!("({ace}"))
                    .collect(),
            }
        }

        /// The owner and DACL of the file or directory at `path`.
        fn of_path(path: &Path) -> Self {
            let mut sd = ptr::null_mut();
            // SAFETY: the path is NUL-terminated and sd is a valid place to
            // write; the other outputs are optional.
            let status = unsafe {
                GetNamedSecurityInfoW(
                    wide(path.as_os_str()).as_ptr(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut sd,
                )
            };
            assert_eq!(status, 0, "{}", io::Error::from_raw_os_error(status as i32));
            let result = Self::of(sd);
            // SAFETY: GetNamedSecurityInfoW allocated sd with LocalAlloc.
            unsafe { LocalFree(sd) };
            result
        }

        /// The private security: owned by this user, a protected DACL with
        /// full access for SYSTEM, Administrators and this user, with
        /// `flags` (such as "OICI") on each entry.
        fn private(flags: &str) -> Self {
            let sd = SecurityDescriptor::private(false).unwrap();
            let Self { owner, aces, .. } = Self::of(sd.as_ptr());
            assert_eq!(aces.len(), 3, "{aces:?}");
            assert!(aces.contains("(A;;FA;;;SY)"), "{aces:?}");
            assert!(aces.contains("(A;;FA;;;BA)"), "{aces:?}");
            assert!(aces.contains(&format!("(A;;FA;;;{owner})")), "{aces:?}");
            Self {
                owner,
                protected: true,
                aces: aces
                    .iter()
                    .map(|ace| ace.replacen("(A;;", &format!("(A;{flags};"), 1))
                    .collect(),
            }
        }
    }

    #[test]
    fn a_new_private_dir_allows_only_system_administrators_and_this_user() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a/state");
        create_private_dir(&path).unwrap();
        assert_eq!(Security::of_path(&path), Security::private("OICI"));
    }

    #[test]
    fn an_existing_dir_loses_the_access_list_of_its_parent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        std::fs::create_dir(&path).unwrap();
        assert!(!Security::of_path(&path).protected);
        create_private_dir(&path).unwrap();
        assert_eq!(Security::of_path(&path), Security::private("OICI"));
    }

    #[test]
    fn a_private_file_allows_only_system_administrators_and_this_user() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.key");
        write_private(&path, b"x").unwrap();
        assert_eq!(Security::of_path(&path), Security::private(""));
    }

    #[test]
    fn a_stale_tmp_file_does_not_keep_its_access_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.key");
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, b"stale").unwrap();
        assert!(!Security::of_path(&tmp).protected);
        write_private(&path, b"x").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
        assert_eq!(Security::of_path(&path), Security::private(""));
    }

    #[test]
    fn files_in_a_private_dir_inherit_its_access_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        create_private_dir(&path).unwrap();
        let file = path.join("transitions.bin");
        std::fs::write(&file, b"x").unwrap();
        // The owner of a file made with std::fs is the token's default
        // owner, which may be Administrators, so only the DACL is checked.
        let got = Security::of_path(&file);
        assert!(!got.protected);
        assert_eq!(got.aces, Security::private("ID").aces);
    }
}
