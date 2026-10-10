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
        collections::BTreeSet,
        os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
        path::Path,
        ptr,
    };

    use cheesecloth_core::fs::windows::{SecurityDescriptor, TokenUser};
    use windows_sys::Win32::{
        Foundation::{HANDLE, LocalFree},
        Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo,
                SDDL_REVISION_1, SE_KERNEL_OBJECT,
            },
            CreateRestrictedToken, CreateWellKnownSid, DACL_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, SID_AND_ATTRIBUTES, TOKEN_DUPLICATE, TOKEN_QUERY,
            WinBuiltinAdministratorsSid, WinLocalServiceSid,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
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

    /// Whether the DACL of `sd` is protected, and its entries.
    fn dacl(sd: PSECURITY_DESCRIPTOR) -> (bool, BTreeSet<String>) {
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
        // SAFETY: the call wrote a NUL-terminated UTF-16 string to s.
        let len = (0..).take_while(|&i| unsafe { *s.add(i) } != 0).count();
        // SAFETY: s is valid for len characters.
        let sddl = String::from_utf16(unsafe { std::slice::from_raw_parts(s, len) }).unwrap();
        // SAFETY: the call allocated s with LocalAlloc.
        unsafe { LocalFree(s.cast()) };
        let rest = sddl.strip_prefix("D:").expect(&sddl);
        let protected = rest.starts_with('P');
        let aces = rest
            .split('(')
            .skip(1)
            .map(|ace| format!("({ace}"))
            .collect();
        (protected, aces)
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
        let (protected, aces) = dacl(sd);
        // SAFETY: GetSecurityInfo allocated sd with LocalAlloc.
        unsafe { LocalFree(sd) };
        assert!(protected, "{aces:?}");
        let (_, expected) = dacl(SecurityDescriptor::private(false).unwrap().as_ptr());
        assert_eq!(aces, expected);
        assert_eq!(aces.len(), 3, "{aces:?}");
        assert!(aces.contains("(A;;FA;;;SY)"), "{aces:?}");
        assert!(aces.contains("(A;;FA;;;BA)"), "{aces:?}");
    }

    /// This process's token, with `access`.
    fn my_token(access: u32) -> OwnedHandle {
        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo handle and token is a
        // valid place to write.
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        // SAFETY: the call succeeded, so token is an open handle we now own.
        unsafe { OwnedHandle::from_raw_handle(token) }
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
        assert!(is_trusted(my_token(TOKEN_QUERY).as_handle(), me.sid()).unwrap());
    }

    #[test]
    fn a_server_that_runs_as_another_user_without_administrators_is_refused() {
        let mut admins = well_known(WinBuiltinAdministratorsSid);
        let disable = SID_AND_ATTRIBUTES {
            Sid: admins.as_mut_ptr().cast(),
            Attributes: 0,
        };
        let mut restricted: HANDLE = ptr::null_mut();
        // SAFETY: the token is open, disable points at one valid entry, and
        // restricted is a valid place to write.
        let ok = unsafe {
            CreateRestrictedToken(
                my_token(TOKEN_DUPLICATE | TOKEN_QUERY).as_raw_handle(),
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
