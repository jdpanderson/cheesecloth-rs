//! The OS's request to stop the daemon. The OS code is in `stop/unix.rs` and
//! `stop/windows.rs`; the rest of the crate does not name an OS. When the
//! daemon runs as a Windows service (planned), the service manager's stop
//! request will complete `requested` too.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as os;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as os;

/// Completes when the OS asks the daemon to stop: SIGTERM or SIGINT on Unix,
/// Ctrl-C or Ctrl-Break on Windows.
pub(crate) async fn requested() {
    os::requested().await
}
