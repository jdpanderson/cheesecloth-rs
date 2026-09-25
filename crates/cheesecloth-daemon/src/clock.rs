//! Clock checks. Cheesecloth requires synchronised clocks (NTP or similar):
//! the proposer's clock stamps each change, and invites, proposals and the
//! replay windows are timed by it.
//!
//! No extra messages: every control-plane stream and response carries its
//! sender's clock, so the net layer knows how far the members this node talks
//! to are from its own clock. An idle cluster sends few messages, so these
//! measurements may be old.

use std::{sync::Arc, time::Duration};

use cheesecloth_core::NodeId;
use tracing::warn;

use crate::node::Node;

/// Warn when clocks differ by more than this.
pub const MAX_SKEW: Duration = Duration::from_secs(30);

fn median(offsets: &[(NodeId, i64)]) -> Option<i64> {
    let mut v: Vec<i64> = offsets.iter().map(|(_, o)| *o).collect();
    v.sort_unstable();
    v.get(v.len() / 2).copied()
}

fn describe(ms: i64) -> String {
    let secs = ms.unsigned_abs().div_ceil(1000);
    if secs >= 120 {
        format!("{} min", secs / 60)
    } else {
        format!("{secs} s")
    }
}

/// Status warnings about clocks. `offsets` are members' clocks minus ours
/// (ms).
pub fn warnings(offsets: &[(NodeId, i64)]) -> Vec<String> {
    let max = MAX_SKEW.as_millis() as i64;
    if let Some(m) = median(offsets)
        && m.abs() > max
    {
        // Peers ahead of us means our clock is behind.
        let dir = if m > 0 { "behind" } else { "ahead of" };
        return vec![format!(
            "this node's clock is {} {dir} its peers' (median of {}); cheesecloth requires \
             synchronised clocks (NTP)",
            describe(m),
            offsets.len()
        )];
    }
    Vec::new()
}

/// Logs when this node's clock drifts from its peers', once per episode.
pub async fn run(node: Arc<Node>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    let mut warned = false;
    loop {
        tick.tick().await;
        let w = warnings(&node.net.clock_offsets());
        if !w.is_empty() && !warned {
            for line in &w {
                warn!("{line}");
            }
        }
        warned = !w.is_empty();
    }
}

#[cfg(test)]
mod tests;
