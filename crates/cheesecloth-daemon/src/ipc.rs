//! The local API transport: a Unix socket, or a named pipe on Windows. The OS
//! code is in `ipc/unix.rs` and `ipc/windows.rs`; the rest of the crate does
//! not name an OS.

use std::{
    io,
    path::{Path, PathBuf},
};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as os;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as os;

pub(crate) use os::{ClientStream, Listener};

/// The default local API address: `<state_dir>/control.sock`, or on Windows a
/// pipe named after the canonical state directory.
pub(crate) fn default_address(state_dir: &Path) -> io::Result<PathBuf> {
    os::default_address(state_dir)
}

/// Connects to the daemon at `addr`. On Windows it also checks that the pipe
/// server runs as SYSTEM, an administrator or this user.
pub(crate) async fn connect(addr: &Path) -> anyhow::Result<ClientStream> {
    os::connect(addr).await
}

/// The error text when the daemon at `addr` can't be reached.
pub fn unreachable_message(addr: &Path) -> String {
    unreachable_message_with(addr, "is it running, and do you have permission?")
}

/// The error text when the daemon at `addr` can't be reached, with `hint`
/// to say what to check.
fn unreachable_message_with(addr: &Path, hint: &str) -> String {
    format!(
        "can't reach the cheesecloth daemon at {} ({hint})",
        addr.display()
    )
}

#[cfg(test)]
mod tests;
