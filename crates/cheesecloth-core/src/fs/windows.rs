//! Windows security helpers: a token's user SID and the private security
//! descriptor. The daemon's local API pipe uses them too, so there is one copy.

use std::{
    io, iter,
    os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    ptr,
};

use windows_sys::{
    Win32::{
        Foundation::{HANDLE, LocalFree},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1,
            },
            GetTokenInformation, IsWellKnownSid, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
            TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER, TokenUser as TOKEN_USER_CLASS,
            WinLocalSystemSid,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    },
    core::PWSTR,
};

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
        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo handle that needs no
        // closing, and token is a valid place to write.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the call succeeded, so token is an open handle we now own.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        Self::of(token.as_handle())
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
        let sddl = wide(sddl);
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
    // SAFETY: the call wrote a NUL-terminated UTF-16 string to s.
    let len = (0..).take_while(|&i| unsafe { *s.add(i) } != 0).count();
    // SAFETY: s is valid for len characters.
    let string = String::from_utf16(unsafe { std::slice::from_raw_parts(s, len) });
    // SAFETY: ConvertSidToStringSidW allocated s with LocalAlloc.
    unsafe { LocalFree(s.cast()) };
    string.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// `s` as a NUL-terminated UTF-16 string.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(iter::once(0)).collect()
}
