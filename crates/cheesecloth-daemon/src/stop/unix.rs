//! Unix: SIGTERM or SIGINT.

use tokio::signal::unix::{SignalKind, signal};

pub(super) async fn requested() {
    let mut term = signal(SignalKind::terminate()).expect("signal handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}
