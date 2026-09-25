//! Owns work within a daemon or membership lifetime. Stopping fences every future poll and waits for
//! synchronous work, including disk writes whose async caller was cancelled.

use std::{future::Future, sync::Arc, task::Poll};

use anyhow::{Result, bail};
use parking_lot::Mutex;
use tokio::{
    sync::{Notify, watch},
    task::JoinSet,
};

#[derive(Default)]
struct Work {
    stopped: bool,
    active: usize,
    tasks: JoinSet<()>,
}

pub(crate) struct Lifetime {
    work: Mutex<Work>,
    stopped: watch::Sender<bool>,
    drained: Notify,
}

impl Default for Lifetime {
    fn default() -> Self {
        Self {
            work: Mutex::default(),
            stopped: watch::Sender::new(false),
            drained: Notify::new(),
        }
    }
}

pub(crate) struct Permit(Arc<Lifetime>);

impl Drop for Permit {
    fn drop(&mut self) {
        let mut work = self.0.work.lock();
        work.active -= 1;
        if work.active == 0 {
            self.0.drained.notify_one();
        }
    }
}

impl Lifetime {
    pub fn enter(self: &Arc<Self>) -> Result<Permit> {
        let mut work = self.work.lock();
        if work.stopped {
            bail!("node is stopping");
        }
        work.active += 1;
        Ok(Permit(self.clone()))
    }

    /// Fence each poll, not the entire future. A caller may stop polling a
    /// pending command; it must neither block shutdown nor resume old work.
    pub async fn run<F: Future>(self: &Arc<Self>, future: F) -> Result<F::Output> {
        let mut stopped = self.stopped.subscribe();
        tokio::pin!(future);
        tokio::select! {
            biased;
            _ = stopped.wait_for(|s| *s) => bail!("node is stopping"),
            result = std::future::poll_fn(|cx| {
                let _permit = match self.enter() {
                    Ok(p) => p,
                    Err(e) => return Poll::Ready(Err(e)),
                };
                future.as_mut().poll(cx).map(Ok)
            }) => result,
        }
    }

    /// The permit moves into the blocking task. Dropping its JoinHandle does
    /// not release the fence while the task is still writing.
    pub async fn blocking<T: Send + 'static>(
        self: &Arc<Self>,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T> {
        let permit = self.enter()?;
        Ok(tokio::task::spawn_blocking(move || {
            let _permit = permit;
            f()
        })
        .await?)
    }

    pub fn spawn(self: &Arc<Self>, future: impl Future<Output = ()> + Send + 'static) {
        let mut work = self.work.lock();
        if work.stopped {
            return;
        }
        while let Some(result) = work.tasks.try_join_next() {
            report(result);
        }
        let lifetime = self.clone();
        work.tasks.spawn(async move {
            let _ = lifetime.run(future).await;
        });
    }

    #[cfg(test)]
    pub async fn stop_tasks(&self) {
        let mut tasks = std::mem::take(&mut self.work.lock().tasks);
        tasks.abort_all();
        while let Some(result) = tasks.join_next().await {
            report(result);
        }
    }

    /// Called by the node's serialized stop operation.
    pub async fn stop(&self) {
        let mut tasks = {
            let mut work = self.work.lock();
            work.stopped = true;
            self.stopped.send_replace(true);
            std::mem::take(&mut work.tasks)
        };
        tasks.abort_all();
        while let Some(result) = tasks.join_next().await {
            report(result);
        }
        loop {
            let drained = self.drained.notified();
            if self.work.lock().active == 0 {
                break;
            }
            drained.await;
        }
    }
}

fn report(result: Result<(), tokio::task::JoinError>) {
    if let Err(e) = result
        && !e.is_cancelled()
    {
        tracing::error!("owned task failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_unpolled_command_cannot_hold_up_stop_or_resume_after_it() {
        let lifetime = Arc::new(Lifetime::default());
        let command = lifetime.run(std::future::pending::<()>());
        tokio::pin!(command);
        assert!(futures_util::poll!(&mut command).is_pending());
        lifetime.stop().await;
        assert!(command.await.is_err());
        assert!(
            lifetime
                .run(async { panic!("old work resumed") })
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn stop_drains_a_write_even_when_its_caller_was_cancelled() {
        let lifetime = Arc::new(Lifetime::default());
        let (release, wait) = std::sync::mpsc::channel();
        let (started, running) = tokio::sync::oneshot::channel();
        let l = lifetime.clone();
        let caller = tokio::spawn(async move {
            l.blocking(move || {
                started.send(()).unwrap();
                wait.recv().unwrap();
            })
            .await
        });
        running.await.unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let stop = lifetime.stop();
        tokio::pin!(stop);
        assert!(futures_util::poll!(&mut stop).is_pending());
        release.send(()).unwrap();
        stop.await;
        assert!(lifetime.enter().is_err());
    }
}
