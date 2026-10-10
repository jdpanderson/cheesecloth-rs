//! Windows: private files and directories through access lists that allow
//! only SYSTEM, Administrators and the current user. Also the security
//! helpers behind them (a token's user SID, the private security
//! descriptor), which the daemon's local API pipe uses too, so there is one
//! copy.

use std::{
    ffi::OsStr,
    fs::File,
    io, iter,
    os::windows::{
        ffi::OsStrExt,
        io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr,
};

use windows_sys::{
    Win32::{
        Foundation::{
            ERROR_ALREADY_EXISTS, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
        },
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
            },
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
            GetTokenInformation, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
            TOKEN_ACCESS_MASK, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER,
            TokenUser as TOKEN_USER_CLASS, WinLocalSystemSid,
        },
        Storage::FileSystem::{CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    },
    core::PWSTR,
};

/// Creates the directory with the private access list, which its children
/// inherit. An existing directory gets the same owner and access list, so
/// there is no moment when it has the access list of its parent.
#[allow(unsafe_code, reason = "windows-sys has no safe directory creation")]
pub(super) fn create_private_dir(dir: &Path) -> io::Result<()> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let security = SecurityDescriptor::private(true)?;
    let attributes = security.attributes();
    let path = wide(dir.as_os_str());
    // SAFETY: path is a live, NUL-terminated UTF-16 string, and attributes
    // and its descriptor live until the call returns.
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } != 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) || !dir.is_dir() {
        return Err(err);
    }
    security.apply(&path)
}

/// Creates a new file with the private access list. A file left by an
/// earlier attempt is removed first, because Windows ignores the access list
/// when it opens an existing file.
#[allow(unsafe_code, reason = "windows-sys has no safe file creation")]
pub(super) fn create_private_file(path: &Path) -> io::Result<File> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let security = SecurityDescriptor::private(false)?;
    let attributes = security.attributes();
    let path = wide(path.as_os_str());
    // SAFETY: path is a live, NUL-terminated UTF-16 string, attributes and
    // its descriptor live until the call returns, and no template is given.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_WRITE,
            0,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so handle is an open file handle we now own.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(handle) }))
}

/// Does nothing. Windows has no documented way to sync a directory, so
/// creating, renaming or removing a file is less durable after a power loss.
/// The file data is still synced. `pnyx::store` does the same.
pub(super) fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// The user SID of a token.
pub struct TokenUser(Vec<usize>);

#[allow(unsafe_code, reason = "windows-sys has no safe token calls")]
impl TokenUser {
    /// The user of `token`, which needs `TOKEN_QUERY` access.
    pub fn of(token: BorrowedHandle<'_>) -> io::Result<Self> {
        token_information(token, TOKEN_USER_CLASS).map(Self)
    }

    /// The user this process runs as.
    pub fn current() -> io::Result<Self> {
        Self::of(current_token(TOKEN_QUERY)?.as_handle())
    }

    /// The SID. It points into `self`, so it is valid while `self` lives.
    pub fn sid(&self) -> PSID {
        // SAFETY: the buffer holds the TOKEN_USER that GetTokenInformation
        // wrote, and is aligned for it.
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }

    /// Whether this is LocalSystem.
    pub fn is_system(&self) -> bool {
        // SAFETY: sid() is a valid SID while self lives.
        unsafe { IsWellKnownSid(self.sid(), WinLocalSystemSid) != 0 }
    }
}

/// The token of this process, opened with `access`.
#[allow(unsafe_code, reason = "windows-sys has no safe token calls")]
pub fn current_token(access: TOKEN_ACCESS_MASK) -> io::Result<OwnedHandle> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo handle that needs no
    // closing, and token is a valid place to write.
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so token is an open handle we now own.
    Ok(unsafe { OwnedHandle::from_raw_handle(token) })
}

/// Reads one class of information about `token`, which needs `TOKEN_QUERY`
/// access. The buffer is aligned for the structure that the class returns.
#[allow(unsafe_code, reason = "windows-sys has no safe token calls")]
pub fn token_information(
    token: BorrowedHandle<'_>,
    class: TOKEN_INFORMATION_CLASS,
) -> io::Result<Vec<usize>> {
    let handle = token.as_raw_handle();
    let mut len = 0;
    // SAFETY: a null buffer of length 0 only asks for the needed length,
    // which is written to len.
    unsafe { GetTokenInformation(handle, class, ptr::null_mut(), 0, &mut len) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0usize; (len as usize).div_ceil(size_of::<usize>())];
    // SAFETY: buf is valid for len bytes, and len is valid to write.
    if unsafe { GetTokenInformation(handle, class, buf.as_mut_ptr().cast(), len, &mut len) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(buf)
}

/// A security descriptor built from SDDL.
pub struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is heap memory that this value owns and never
// changes, so any thread may use or free it.
#[allow(unsafe_code, reason = "the raw pointer is owned memory")]
unsafe impl Send for SecurityDescriptor {}

#[allow(unsafe_code, reason = "windows-sys has no safe SDDL calls")]
impl SecurityDescriptor {
    /// Full access for SYSTEM, Administrators and the current user, and for
    /// no one else. Inheritance from the parent is removed, and the owner is
    /// the current user. `inherit` makes children inherit the access list
    /// (for directories).
    pub fn private(inherit: bool) -> io::Result<Self> {
        let user = sid_string(TokenUser::current()?.sid())?;
        let f = if inherit { "OICI" } else { "" };
        Self::from_sddl(&format!(
            "O:{user}D:P(A;{f};FA;;;SY)(A;{f};FA;;;BA)(A;{f};FA;;;{user})"
        ))
    }

    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let sddl = wide(OsStr::new(sddl));
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: sddl is a live, NUL-terminated UTF-16 string and sd is a
        // valid place to write; the size output is optional.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(sd))
    }

    /// Sets the owner and the protected access list of this descriptor on
    /// the file or directory `path` (NUL-terminated UTF-16).
    fn apply(&self, path: &[u16]) -> io::Result<()> {
        let mut defaulted = 0;
        let mut owner: PSID = ptr::null_mut();
        // SAFETY: self.0 is a valid descriptor, and owner and defaulted are
        // valid places to write. owner points into self.0.
        if unsafe { GetSecurityDescriptorOwner(self.0, &mut owner, &mut defaulted) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut present = 0;
        let mut dacl = ptr::null_mut();
        // SAFETY: as above; dacl points into self.0.
        let ok =
            unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: path is NUL-terminated, and owner and dacl are valid while
        // self lives; the call only reads them.
        let status = unsafe {
            SetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                owner,
                ptr::null_mut(),
                dacl,
                ptr::null(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    /// The descriptor itself, valid while `self` lives.
    pub fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0
    }

    /// Attributes that apply this descriptor and make a handle that child
    /// processes do not inherit. They are valid while `self` lives.
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}

impl Drop for SecurityDescriptor {
    #[allow(unsafe_code, reason = "the descriptor came from LocalAlloc")]
    fn drop(&mut self) {
        // SAFETY: ConvertStringSecurityDescriptorToSecurityDescriptorW
        // allocated the descriptor with LocalAlloc, and only self frees it.
        unsafe { LocalFree(self.0) };
    }
}

/// `sid` in its string form, such as "S-1-5-18".
#[allow(unsafe_code, reason = "windows-sys has no safe SID calls")]
fn sid_string(sid: PSID) -> io::Result<String> {
    let mut s: PWSTR = ptr::null_mut();
    // SAFETY: sid is a valid SID and s is a valid place to write.
    if unsafe { ConvertSidToStringSidW(sid, &mut s) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call wrote a NUL-terminated string that it allocated with
    // LocalAlloc, and nothing else uses it.
    unsafe { take_local_string(s) }
}

/// Copies the string `s` into a `String`, then frees `s`.
///
/// # Safety
///
/// `s` must be a NUL-terminated UTF-16 string that Windows allocated with
/// LocalAlloc, and nothing may use it afterwards.
#[allow(unsafe_code, reason = "the string comes from a raw Windows pointer")]
pub unsafe fn take_local_string(s: PWSTR) -> io::Result<String> {
    // SAFETY: the caller promises that s is NUL-terminated.
    let len = (0..).take_while(|&i| unsafe { *s.add(i) } != 0).count();
    // SAFETY: s is valid for len characters.
    let string = String::from_utf16(unsafe { std::slice::from_raw_parts(s, len) });
    // SAFETY: the caller promises that s came from LocalAlloc and is not used
    // again.
    unsafe { LocalFree(s.cast()) };
    string.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// `s` as a NUL-terminated UTF-16 string.
pub(super) fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(iter::once(0)).collect()
}
