//! Windows: the local API on a named pipe. Only SYSTEM, Administrators and
//! the daemon's user may open it (the equivalent of a 0600 socket), and the
//! CLI checks who serves it before it sends a request.

use std::{
    io,
    os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    path::{Path, PathBuf},
    ptr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use cheesecloth_core::fs::windows::{SecurityDescriptor, TokenUser, token_information};
use data_encoding::HEXLOWER;
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use windows_sys::Win32::{
    Foundation::{ERROR_ACCESS_DENIED, ERROR_NO_DATA, ERROR_PIPE_BUSY, HANDLE},
    Security::{
        EqualSid, IsWellKnownSid, PSID, SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY, TokenGroups,
        WinBuiltinAdministratorsSid,
    },
    System::{
        Pipes::GetNamedPipeServerProcessId,
        SystemServices::{SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY},
        Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION},
    },
};

pub(crate) type ServerStream = NamedPipeServer;
pub(crate) type ClientStream = NamedPipeClient;

/// Every pipe name starts with this.
const PIPE_PREFIX: &str = r"\\.\pipe\";

pub(super) fn default_address(state_dir: &Path) -> io::Result<PathBuf> {
    Ok(pipe_name(&std::fs::canonicalize(state_dir)?))
}

/// `\\.\pipe\cheesecloth-<hex>`, where hex is from a hash of `canonical`, so
/// that each state directory has its own pipe.
pub(super) fn pipe_name(canonical: &Path) -> PathBuf {
    let hash = blake3::hash(canonical.as_os_str().as_encoded_bytes());
    let hex = HEXLOWER.encode(&hash.as_bytes()[..16]);
    format!("{PIPE_PREFIX}cheesecloth-{hex}").into()
}

/// Refuses an address that is not a pipe name.
fn check_address(addr: &Path) -> Result<()> {
    if !addr
        .to_str()
        .is_some_and(|name| name.len() > PIPE_PREFIX.len() && name.starts_with(PIPE_PREFIX))
    {
        bail!(
            "the local API address on Windows must be a pipe name that starts with {PIPE_PREFIX}, \
             not {}",
            addr.display()
        );
    }
    Ok(())
}

/// The server end of the pipe. It always holds one instance that waits for
/// the next client.
pub(crate) struct Listener {
    name: PathBuf,
    security: SecurityDescriptor,
    /// Visible to the tests, which read its access list.
    pub(super) next: NamedPipeServer,
}

impl Listener {
    /// Creates the pipe `name` as its first instance, so it fails if another
    /// process has the name.
    pub(crate) fn bind(name: &Path) -> Result<Self> {
        check_address(name)?;
        let security =
            SecurityDescriptor::private(false).context("building the pipe's access list")?;
        let next = create(name, &security, true).map_err(|e| {
            if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
                anyhow!(
                    "another cheesecloth daemon is already listening on {}",
                    name.display()
                )
            } else {
                anyhow::Error::new(e).context(format!("creating the pipe {}", name.display()))
            }
        })?;
        Ok(Self {
            name: name.to_owned(),
            security,
            next,
        })
    }

    /// Waits for a client, then makes a new instance for the next one.
    pub(crate) async fn accept(&mut self) -> io::Result<ServerStream> {
        loop {
            match self.next.connect().await {
                Ok(()) => break,
                // The client closed its end before the server saw it connect.
                Err(e) if e.raw_os_error() == Some(ERROR_NO_DATA as i32) => {
                    self.next = create(&self.name, &self.security, false)?;
                }
                Err(e) => return Err(e),
            }
        }
        let next = create(&self.name, &self.security, false)?;
        Ok(std::mem::replace(&mut self.next, next))
    }
}

/// Creates one instance of the pipe `name`, with the access list of
/// `security`, for local clients only.
#[allow(
    unsafe_code,
    reason = "tokio takes the security attributes as a raw pointer"
)]
fn create(name: &Path, security: &SecurityDescriptor, first: bool) -> io::Result<NamedPipeServer> {
    let mut attributes = security.attributes();
    // SAFETY: attributes is a valid SECURITY_ATTRIBUTES, and its descriptor
    // lives as long as security; the call only reads them.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(name, (&raw mut attributes).cast())
    }
}

pub(super) async fn connect(name: &Path) -> Result<ClientStream> {
    check_address(name)?;
    let client = open(name).await.map_err(|e| {
        let hint = if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
            "the CLI needs an elevated shell when the daemon runs as SYSTEM"
        } else {
            "is it running, and do you have permission?"
        };
        anyhow::Error::new(e).context(format!(
            "can't reach the cheesecloth daemon at {} ({hint})",
            name.display()
        ))
    })?;
    check_server(&client, name)?;
    Ok(client)
}

/// Opens the pipe. While all instances are busy, it waits for a free one for
/// up to 2 s, as the named pipe protocol asks.
async fn open(name: &Path) -> io::Result<NamedPipeClient> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match ClientOptions::new().open(name) {
            Err(e)
                if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                    && Instant::now() < deadline => {}
            result => return result,
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Refuses a pipe server that does not run as SYSTEM, an administrator or
/// this user. Another user could otherwise take the pipe name first and read
/// the requests.
#[allow(unsafe_code, reason = "windows-sys has no safe process or token calls")]
fn check_server(pipe: &NamedPipeClient, name: &Path) -> Result<()> {
    let finding = || format!("finding the process that serves {}", name.display());
    let mut pid = 0;
    // SAFETY: the pipe handle is open while pipe lives, and pid is a valid
    // place to write.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
        return Err(io::Error::last_os_error()).with_context(finding);
    }
    // SAFETY: OpenProcess takes no pointers.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error()).with_context(finding);
    }
    // SAFETY: the call succeeded, so process is an open handle we now own.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: process is an open handle and token is a valid place to write.
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error()).with_context(finding);
    }
    // SAFETY: the call succeeded, so token is an open handle we now own.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let me = TokenUser::current().context("finding this process's user")?;
    if !is_trusted(token.as_handle(), me.sid()).with_context(finding)? {
        bail!(
            "the process serving {} (pid {pid}) does not run as SYSTEM, an administrator or this \
             user; refusing to send the request",
            name.display()
        );
    }
    Ok(())
}

/// Whether the token `server` is LocalSystem, the user `me`, or a member of
/// Administrators with that group enabled.
#[allow(unsafe_code, reason = "windows-sys has no safe SID calls")]
pub(super) fn is_trusted(server: BorrowedHandle<'_>, me: PSID) -> io::Result<bool> {
    let user = TokenUser::of(server)?;
    // SAFETY: both SIDs are valid while user and the caller's owner live.
    if user.is_system() || unsafe { EqualSid(user.sid(), me) } != 0 {
        return Ok(true);
    }
    let buf = token_information(server, TokenGroups)?;
    let groups = buf.as_ptr().cast::<TOKEN_GROUPS>();
    // SAFETY: buf holds the TOKEN_GROUPS that GetTokenInformation wrote, with
    // GroupCount entries in a row from Groups, and is aligned for it.
    let groups = unsafe {
        std::slice::from_raw_parts(
            (&raw const (*groups).Groups).cast::<SID_AND_ATTRIBUTES>(),
            (*groups).GroupCount as usize,
        )
    };
    Ok(groups.iter().any(|g| {
        let enabled = g.Attributes & SE_GROUP_ENABLED as u32 != 0
            && g.Attributes & SE_GROUP_USE_FOR_DENY_ONLY as u32 == 0;
        // SAFETY: g.Sid points into buf, which is alive.
        enabled && unsafe { IsWellKnownSid(g.Sid, WinBuiltinAdministratorsSid) } != 0
    }))
}
