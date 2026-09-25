//! Failures of work that runs again and again, such as the acceptors check:
//! logged when they start or change and when they end, and shown in
//! `cheesecloth status` meanwhile, so that a lasting failure is seen but
//! doesn't fill the log.

use anyhow::Result;
use parking_lot::Mutex;
use tracing::{info, warn};

/// The current failure of one repeated task, if any.
pub struct Problem {
    /// What the task does, for messages.
    what: &'static str,
    /// The failure's message without its causes (to notice a change), and
    /// with them (to show).
    current: Mutex<Option<(String, String)>>,
}

impl Problem {
    pub fn new(what: &'static str) -> Self {
        Problem {
            what,
            current: Mutex::new(None),
        }
    }

    /// Records the outcome of one run. A failure is logged when it starts,
    /// and when its message changes. Its causes are not compared: they often
    /// differ from one run to the next.
    pub fn record(&self, result: Result<()>) {
        let mut current = self.current.lock();
        match result {
            Ok(()) => {
                if current.take().is_some() {
                    info!("{}: working again", self.what);
                }
            }
            Err(e) => {
                let summary = e.to_string();
                let full = format!("{e:#}");
                if current.as_ref().is_none_or(|(s, _)| *s != summary) {
                    warn!("{}: {full}", self.what);
                }
                *current = Some((summary, full));
            }
        }
    }

    /// The failure, as a status warning, while it lasts.
    pub fn warning(&self) -> Option<String> {
        let current = self.current.lock();
        current
            .as_ref()
            .map(|(_, full)| format!("{}: {full}", self.what))
    }
}

#[cfg(test)]
mod tests;
