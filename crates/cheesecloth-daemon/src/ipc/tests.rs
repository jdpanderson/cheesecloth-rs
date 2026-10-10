use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::*;

/// Fails the test instead of hanging when `f` never finishes.
async fn within<F: Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), f)
        .await
        .expect("finished in time")
}

#[tokio::test]
async fn a_client_and_the_server_exchange_lines() {
    let dir = tempfile::tempdir().unwrap();
    let addr = default_address(dir.path()).unwrap();
    let mut listener = Listener::bind(&addr).unwrap();
    let server = tokio::spawn(async move {
        let stream = listener.accept().await.unwrap();
        let (read, mut write) = tokio::io::split(stream);
        let line = BufReader::new(read).lines().next_line().await.unwrap();
        write
            .write_all(format!("{}!\n", line.unwrap()).as_bytes())
            .await
            .unwrap();
    });
    let client = within(connect(&addr)).await.unwrap();
    let (read, mut write) = tokio::io::split(client);
    write.write_all(b"hello\n").await.unwrap();
    let mut lines = BufReader::new(read).lines();
    assert_eq!(
        within(lines.next_line()).await.unwrap().as_deref(),
        Some("hello!")
    );
    within(server).await.unwrap();
}

#[tokio::test]
async fn a_second_listener_on_a_live_address_fails() {
    let dir = tempfile::tempdir().unwrap();
    let addr = default_address(dir.path()).unwrap();
    let _first = Listener::bind(&addr).unwrap();
    let err = Listener::bind(&addr).err().expect("a second bind fails");
    assert!(format!("{err:#}").contains("already listening"), "{err:#}");
}

#[test]
fn the_default_address_is_stable_for_one_directory() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        default_address(dir.path()).unwrap(),
        default_address(dir.path()).unwrap()
    );
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[tokio::test]
    async fn the_socket_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let addr = default_address(dir.path()).unwrap();
        let _listener = Listener::bind(&addr).unwrap();
        let mode = std::fs::metadata(&addr).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[cfg(windows)]
mod windows {
    #![allow(unsafe_code, reason = "the tests read access lists with windows-sys")]

    use std::{
        os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
        path::Path,
        ptr,
    };

    use cheesecloth_core::fs::windows::{
        SecurityDescriptor, TokenUser, current_token, take_local_string,
    };
    use windows_sys::Win32::{
        Foundation::{HANDLE, LocalFree},
        Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo,
                SDDL_REVISION_1, SE_KERNEL_OBJECT,
            },
            CheckTokenMembership, CreateRestrictedToken, CreateWellKnownSid,
            DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SID_AND_ATTRIBUTES, TOKEN_DUPLICATE,
            TOKEN_QUERY, WinBuiltinAdministratorsSid, WinLocalServiceSid,
        },
    };

    use super::*;
    use crate::ipc::windows::{is_trusted, pipe_name};

    #[test]
    fn the_pipe_name_comes_from_a_hash_of_the_directory() {
        let name = pipe_name(Path::new(r"C:\ProgramData\cheesecloth"));
        let name = name.to_str().unwrap();
        let hex = name.strip_prefix(r"\\.\pipe\cheesecloth-").expect(name);
        assert_eq!(hex.len(), 32, "{name}");
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_ne!(
            pipe_name(Path::new(r"C:\ProgramData\cheesecloth")),
            pipe_name(Path::new(r"C:\ProgramData\cheesecloth2"))
        );
    }

    #[test]
    fn one_directory_spelled_two_ways_has_one_pipe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("State");
        std::fs::create_dir(&path).unwrap();
        let expected = default_address(&path).unwrap();
        assert_eq!(default_address(&path.join(".")).unwrap(), expected);
        let lower = dir.path().join("state");
        assert_eq!(default_address(&lower).unwrap(), expected);
        let other = tempfile::tempdir().unwrap();
        assert_ne!(default_address(other.path()).unwrap(), expected);
    }

    #[tokio::test]
    async fn an_address_that_is_not_a_pipe_is_refused() {
        for addr in [r"C:\ProgramData\cheesecloth\control.sock", r"\\.\pipe\"] {
            let err = Listener::bind(Path::new(addr)).err().expect(addr);
            assert!(
                format!("{err:#}").contains("must be a pipe name"),
                "{err:#}"
            );
            let err = connect(Path::new(addr)).await.unwrap_err();
            assert!(
                format!("{err:#}").contains("must be a pipe name"),
                "{err:#}"
            );
        }
    }

    /// The DACL of `sd` as an SDDL string.
    fn dacl(sd: PSECURITY_DESCRIPTOR) -> String {
        let mut s = ptr::null_mut();
        // SAFETY: sd is a valid descriptor and s is a valid place to write.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut s,
                ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        // SAFETY: the call allocated s with LocalAlloc, and only this code
        // uses it.
        unsafe { take_local_string(s) }.unwrap()
    }

    #[tokio::test]
    async fn a_pipe_prefix_in_upper_case_works() {
        let dir = tempfile::tempdir().unwrap();
        let addr = default_address(dir.path()).unwrap();
        let addr = addr.to_str().unwrap().replacen(r"\pipe\", r"\PIPE\", 1);
        let mut listener = Listener::bind(Path::new(&addr)).unwrap();
        let server = tokio::spawn(async move { listener.accept().await.unwrap() });
        within(connect(Path::new(&addr))).await.unwrap();
        within(server).await.unwrap();
    }

    #[tokio::test]
    async fn the_pipe_allows_only_system_administrators_and_this_user() {
        let dir = tempfile::tempdir().unwrap();
        let addr = default_address(dir.path()).unwrap();
        let listener = Listener::bind(&addr).unwrap();
        let mut sd = ptr::null_mut();
        // SAFETY: the handle is open while listener lives, and sd is a valid
        // place to write; the other outputs are optional.
        let status = unsafe {
            GetSecurityInfo(
                listener.next.as_raw_handle(),
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut sd,
            )
        };
        assert_eq!(status, 0, "{}", io::Error::from_raw_os_error(status as i32));
        let got = dacl(sd);
        // SAFETY: GetSecurityInfo allocated sd with LocalAlloc.
        unsafe { LocalFree(sd) };
        // The private descriptor's own tests are in cheesecloth-core.
        let expected = dacl(SecurityDescriptor::private(false).unwrap().as_ptr());
        assert!(expected.starts_with("D:P(A;;FA;;;SY)"), "{expected}");
        assert_eq!(got, expected);
    }

    /// A well-known SID.
    fn well_known(kind: i32) -> [u32; 17] {
        let mut sid = [0u32; 17];
        let mut size = size_of_val(&sid) as u32;
        // SAFETY: sid is valid for size bytes and aligned for a SID.
        let ok = unsafe {
            CreateWellKnownSid(kind, ptr::null_mut(), sid.as_mut_ptr().cast(), &mut size)
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        sid
    }

    #[test]
    fn a_server_that_runs_as_this_user_is_trusted() {
        let me = TokenUser::current().unwrap();
        let token = current_token(TOKEN_QUERY).unwrap();
        assert!(is_trusted(token.as_handle(), me.sid()).unwrap());
    }

    /// The test runs as a user that is not LocalService, so only the
    /// Administrators group can make it trusted. GitHub's Windows runners are
    /// elevated, so there this tests the trusted case.
    #[test]
    fn a_server_with_administrators_enabled_is_trusted() {
        let mut admins = well_known(WinBuiltinAdministratorsSid);
        let mut is_admin = 0;
        // SAFETY: a null token means this thread's token, admins is a valid
        // SID, and is_admin is a valid place to write.
        let ok = unsafe {
            CheckTokenMembership(ptr::null_mut(), admins.as_mut_ptr().cast(), &mut is_admin)
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        let token = current_token(TOKEN_QUERY).unwrap();
        let mut other = well_known(WinLocalServiceSid);
        assert_eq!(
            is_trusted(token.as_handle(), other.as_mut_ptr().cast()).unwrap(),
            is_admin != 0
        );
    }

    #[test]
    fn a_server_that_runs_as_another_user_without_administrators_is_refused() {
        let mut admins = well_known(WinBuiltinAdministratorsSid);
        let disable = SID_AND_ATTRIBUTES {
            Sid: admins.as_mut_ptr().cast(),
            Attributes: 0,
        };
        let token = current_token(TOKEN_DUPLICATE | TOKEN_QUERY).unwrap();
        let mut restricted: HANDLE = ptr::null_mut();
        // SAFETY: the token is open, disable points at one valid entry, and
        // restricted is a valid place to write.
        let ok = unsafe {
            CreateRestrictedToken(
                token.as_raw_handle(),
                0,
                1,
                &disable,
                0,
                ptr::null(),
                0,
                ptr::null(),
                &mut restricted,
            )
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        // SAFETY: the call succeeded, so restricted is an open handle we own.
        let restricted = unsafe { OwnedHandle::from_raw_handle(restricted) };
        // The "user" the client runs as is LocalService, so only the
        // Administrators group could make the server trusted.
        let mut other = well_known(WinLocalServiceSid);
        assert!(!is_trusted(restricted.as_handle(), other.as_mut_ptr().cast()).unwrap());
    }

    #[tokio::test]
    async fn connect_trusts_a_pipe_this_user_serves() {
        let dir = tempfile::tempdir().unwrap();
        let addr = default_address(dir.path()).unwrap();
        let mut listener = Listener::bind(&addr).unwrap();
        let server = tokio::spawn(async move { listener.accept().await.unwrap() });
        within(connect(&addr)).await.unwrap();
        within(server).await.unwrap();
    }
}
