//! Runs one change over a transport, with timeouts and retries.

use std::{fmt::Display, future::Future, time::Duration};

use futures_util::{StreamExt, stream::FuturesUnordered};
use rand::RngExt;
use tokio::time::{Instant, sleep_until, timeout};

use crate::{Agreed, Change, Chosen, Proposer, Reply, Request, Step};

/// Sends requests to acceptors. The proposer's own node may be one of them.
pub trait Transport<N, V>: Sync {
    type Error: Display;

    fn call(
        &self,
        to: &N,
        req: Request<N, V>,
    ) -> impl Future<Output = Result<Reply<N, V>, Self::Error>> + Send;

    /// The latest agreed value the proposer's node has learned in another
    /// way, such as from another proposer. It's checked before each new
    /// round: a change that began before a later configuration was learned
    /// would otherwise keep asking acceptors that may be gone.
    fn learned(&self) -> Option<Chosen<N, V>> {
        None
    }
}

/// Timing for [`propose`].
#[derive(Clone, Debug)]
pub struct Options {
    /// How long one request may take.
    pub request_timeout: Duration,
    /// How long the whole change may take.
    pub deadline: Duration,
    /// The longest random wait before a new round, when another proposer is
    /// active.
    pub max_retry_wait: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            request_timeout: Duration::from_secs(5),
            deadline: Duration::from_secs(30),
            max_retry_wait: Duration::from_millis(200),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no majority of acceptors answered in time{}", last_error(.0))]
    Timeout(Option<String>),
    /// See [`Step::OutOfBallots`].
    #[error("no ballots are left in this configuration")]
    OutOfBallots,
}

fn last_error(e: &Option<String>) -> String {
    e.as_ref()
        .map(|e| format!(" (last error: {e})"))
        .unwrap_or_default()
}

/// Runs one change: reads the current value, calls `change` with it, and has
/// the result agreed. `change` may be called more than once, if a round must
/// be retried; the result of the last call is returned with the agreed value.
pub async fn propose<N, V, T, R>(
    proposer: &mut Proposer<N, V>,
    transport: &T,
    options: &Options,
    mut change: impl FnMut(&Agreed<N, V>) -> (Change<N, V>, R),
) -> Result<(Chosen<N, V>, R), Error>
where
    N: Clone + Ord,
    V: Clone,
    T: Transport<N, V>,
{
    let deadline = Instant::now() + options.deadline;
    let mut last_error = None;
    let mut result = None;
    let mut pending = FuturesUnordered::new();
    let send = |pending: &mut FuturesUnordered<_>, requests: Vec<(N, Request<N, V>)>| {
        for (to, req) in requests {
            pending.push(async move {
                let reply = timeout(options.request_timeout, transport.call(&to, req)).await;
                (to, reply)
            });
        }
    };
    let begin = |proposer: &mut Proposer<N, V>| {
        if let Some(chosen) = transport.learned() {
            proposer.learn(chosen);
        }
        proposer.begin()
    };
    let mut step = begin(proposer);
    // When to start the next round, after a failed one.
    let mut retry_at = None;
    loop {
        if let Step::Read(value) = step {
            let (c, r) = change(&value);
            result = Some(r);
            step = proposer.decide(c);
        }
        match step {
            Step::Wait => {}
            Step::Send(requests) => send(&mut pending, requests),
            Step::Read(_) => unreachable!("decide() doesn't read"),
            Step::Done(chosen) => {
                let result = result.expect("a change is decided before it's done");
                return Ok((chosen, result));
            }
            Step::Retry { wait: false } => {
                step = begin(proposer);
                continue;
            }
            Step::Retry { wait: true } => {
                let max = options.max_retry_wait.as_millis() as u64;
                let wait = Duration::from_millis(rand::rng().random_range(0..=max));
                retry_at = Some(Instant::now() + wait);
            }
            Step::OutOfBallots => return Err(Error::OutOfBallots),
        }
        // Answers to earlier rounds are still received: a stale answer tells
        // the proposer about a later configuration.
        let (from, reply) = tokio::select! {
            Some(answer) = pending.next() => answer,
            _ = sleep_until(retry_at.unwrap_or(deadline)), if retry_at.is_some() => {
                retry_at = None;
                step = begin(proposer);
                continue;
            }
            _ = sleep_until(deadline) => {
                proposer.abort();
                return Err(Error::Timeout(last_error));
            }
        };
        step = match reply {
            Ok(Ok(reply)) => proposer.receive(from, reply),
            Ok(Err(e)) => {
                last_error = Some(e.to_string());
                proposer.unreachable(from)
            }
            Err(_) => {
                last_error = Some("request timed out".into());
                proposer.unreachable(from)
            }
        };
    }
}
