//! Soft state sync: publishing our entry when it changes, merging what peers
//! send, and passing new entries on (see `crate::soft`). An entry with a
//! higher agreed state version than ours makes us fetch that state.

use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use cheesecloth_core::{Domain, NodeId, Signed, now_ms};
use tracing::debug;

use super::Node;
use crate::soft::SoftState;

impl Node {
    /// Merges soft state pushed by `from` and passes on what was new to us.
    pub fn merge_soft(self: &Arc<Self>, from: NodeId, body: &[u8]) {
        let Ok(_active) = self.lifetime.enter() else {
            return;
        };
        let Ok(entries) = postcard::from_bytes::<Vec<Signed<SoftState>>>(body) else {
            debug!(peer = %from.short(), "bad soft state");
            return;
        };
        let mut fresh = Vec::new();
        {
            let mut table = self.soft.lock();
            for e in entries {
                if e.signer == self.me {
                    self.note_own_entry(&e);
                } else if table.merge(e.clone(), |n| self.is_member(n)) {
                    fresh.push(e);
                }
            }
        }
        if !fresh.is_empty() {
            self.wake.notify_one();
            self.spread(fresh, Some(from));
            self.catch_up();
        }
    }

    /// Takes in the soft state entries sent by the member that admitted us,
    /// so we know the members' current addresses.
    pub fn take_soft(self: &Arc<Self>, entries: Vec<Signed<SoftState>>) {
        let Ok(_active) = self.lifetime.enter() else {
            return;
        };
        {
            let mut table = self.soft.lock();
            for e in entries.into_iter().filter(|e| e.signer != self.me) {
                table.merge(e, |n| self.is_member(n));
            }
        }
        self.wake.notify_one();
    }

    /// Fetches the agreed state from a live member whose soft state shows a
    /// newer version than ours (see `SoftTable::fetch_source`).
    pub(super) fn catch_up(self: &Arc<Self>) {
        let ours = self.agreed().value.version;
        if !self.soft.lock().all().any(|s| s.version > ours) {
            return;
        }
        let live = self.live();
        let source = self.soft.lock().fetch_source(&live, ours, &mut rand::rng());
        if let Some((node, version)) = source {
            self.fetch_from(node, version);
        }
    }

    /// Peers echo our own entry back when a connection comes up. If it's newer
    /// than anything this process has published (we restarted, and our clock
    /// may have gone back), publish again with a higher sequence number, or
    /// everyone would keep ignoring our entries.
    fn note_own_entry(&self, e: &Signed<SoftState>) {
        let Ok(st) = e.open(Domain::SoftState) else {
            return;
        };
        if st.seq >= self.soft_seq.load(Ordering::Relaxed) {
            self.soft_seq.fetch_max(st.seq, Ordering::Relaxed);
            *self.published.lock() = None;
        }
    }

    /// Pushes soft state entries to every connected member except `skip` and
    /// each entry's own node.
    pub(super) fn spread(self: &Arc<Self>, entries: Vec<Signed<SoftState>>, skip: Option<NodeId>) {
        for c in self.net.connections() {
            if Some(c.node) == skip {
                continue;
            }
            let batches = crate::soft::batches(entries.iter().filter(|e| e.signer != c.node));
            self.push_batches(c.node, batches);
        }
    }

    /// A member connection came up: send it the whole table so it catches up.
    pub fn on_connected(self: &Arc<Self>, peer: NodeId) {
        let batches = crate::soft::batches(&self.soft.lock().signed());
        self.push_batches(peer, batches);
    }

    fn push_batches(&self, peer: NodeId, batches: Vec<Vec<u8>>) {
        if batches.is_empty() {
            return;
        }
        let net = self.net.clone();
        self.lifetime.spawn(async move {
            for body in batches {
                if let Err(e) = net.push_state(peer, &body).await {
                    debug!(peer = %peer.short(), "sending soft state: {e:#}");
                    return;
                }
            }
        });
    }

    pub(super) fn my_soft_state(&self) -> SoftState {
        let facts = self.facts.lock().clone();
        let public_ip = self.public_ip_of(&self.me);
        let observed = self.wg.lock().observed(&self.agreed().state().members);
        let mut connected: Vec<NodeId> =
            self.net.connections().into_iter().map(|c| c.node).collect();
        connected.sort();
        connected.dedup();
        SoftState {
            node: self.me,
            seq: now_ms(),
            public: facts.public,
            relay: facts.relay,
            via_mapping: facts.via_mapping,
            public_ip,
            control_addrs: facts.control_addrs,
            wg_public: facts.wg_public,
            wg_lan: facts.wg_lan,
            connected,
            observed,
            version: self.agreed().value.version,
        }
    }

    /// Checks our own soft state every second, or when a new agreed state is
    /// learned, and publishes it when it changes.
    pub(super) async fn soft_state_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = self.publish.notified() => {}
            }
            self.catch_up();
            let mut now = self.my_soft_state();
            now.bound();
            {
                let mut published = self.published.lock();
                if published.as_ref().is_some_and(|p| p.same_as(&now)) {
                    continue;
                }
                // Strictly increasing, even if the clock goes back.
                let floor = self.soft_seq.load(Ordering::Relaxed).saturating_add(1);
                now.seq = now.seq.max(floor);
                self.soft_seq.store(now.seq, Ordering::Relaxed);
                *published = Some(now.clone());
            }
            debug!("publishing changed soft state");
            let mine = self.identity.seal(Domain::SoftState, &now);
            self.soft.lock().merge(mine.clone(), |n| self.is_member(n));
            self.spread(vec![mine], None);
        }
    }
}
