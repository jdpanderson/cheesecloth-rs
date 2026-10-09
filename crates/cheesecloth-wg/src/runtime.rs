//! A tokio runtime on its own thread, owned by one backend.
//!
//! [`Backend`](crate::Backend) is synchronous: the daemon calls it under a
//! lock and relies on each call finishing as a whole. The backends use async
//! libraries, so each one runs its work here and waits for the result. The
//! runtime also keeps userspace WireGuard's packet tasks apart from the
//! daemon's tasks, and dropping it stops them.

use std::{future::Future, sync::mpsc, thread, time::Duration};

use anyhow::{Context, Result, anyhow};
use tokio::sync::oneshot;

/// Enough for userspace WireGuard's packet tasks to run in parallel.
const WORKERS: usize = 2;
/// How long a drop waits for blocking work, such as a TUN read, to end.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct Runtime {
    handle: tokio::runtime::Handle,
    /// Sending on this, or dropping it, makes the thread shut the runtime down.
    stop: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Runtime {
    pub fn new() -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(WORKERS)
            .thread_name("cheesecloth-wg")
            .enable_all()
            .build()
            .context("starting the WireGuard runtime")?;
        let handle = runtime.handle().clone();
        let (stop, stopped) = oneshot::channel();
        // The runtime must not be dropped in an async context, so this
        // thread owns it and shuts it down.
        let thread = thread::Builder::new()
            .name("cheesecloth-wg-owner".into())
            .spawn(move || {
                let _ = runtime.block_on(stopped);
                runtime.shutdown_timeout(SHUTDOWN_TIMEOUT);
            })
            .context("starting the WireGuard runtime thread")?;
        Ok(Self {
            handle,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// Runs `future` on this runtime and waits for its output. Never call
    /// this from a task on this runtime: it would wait for itself.
    pub fn run<F>(&self, future: F) -> Result<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let (done, result) = mpsc::sync_channel(1);
        self.handle.spawn(async move {
            let _ = done.send(future.await);
        });
        result
            .recv()
            .map_err(|_| anyhow!("the WireGuard task ended without a result"))
    }
}

impl Drop for Runtime {
    /// Returns once every task on the runtime has been dropped.
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::error!("the WireGuard runtime thread panicked");
        }
    }
}
