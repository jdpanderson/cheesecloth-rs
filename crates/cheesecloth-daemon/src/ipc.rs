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

#[cfg(test)]
mod tests;
