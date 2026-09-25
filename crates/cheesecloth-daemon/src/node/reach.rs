//! Reachability: interface addresses, router port mappings, the dial-back
//! that confirms a node is public, the relay role, keeping our member record
//! current, and keeping connections to the members we should reach directly.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use cheesecloth_core::{
    Domain, NodeId,
    state::{Command, MemberInfo},
};
use tracing::{debug, info};

use super::Node;
use crate::{
    RelayMode,
    local::{self, Interfaces},
};

/// How often reachability is re-checked with a dial-back.
const PROBE_INTERVAL: Duration = Duration::from_secs(600);

/// What this node has worked out about its own reachability.
#[derive(Clone, Debug, Default)]
pub struct LocalFacts {
    pub ifaces: Interfaces,
    /// Confirmed publicly reachable.
    pub public: bool,
    /// Acting as a relay.
    pub relay: bool,
    pub public_ip: Option<IpAddr>,
    pub control_addrs: Vec<SocketAddr>,
    pub wg_public: Vec<SocketAddr>,
    pub wg_lan: Vec<SocketAddr>,
    /// Control-plane addresses at which we might be publicly reachable.
    pub candidates: Vec<SocketAddr>,
    /// The router's mappings of our WireGuard and control-plane ports.
    pub mapped_wg: Option<SocketAddr>,
    pub mapped_control: Option<SocketAddr>,
    /// Public only through the router's mapping of the control port.
    pub via_mapping: bool,
    last_probe: Option<(Instant, Vec<SocketAddr>, bool)>,
}

impl Node {
    /// Keeps connections to relays (and LAN peers), and drops non-members.
    pub(super) async fn connection_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            for c in self.net.connections() {
                if !self.is_member(&c.node) {
                    info!(peer = %c.node.short(), "closing connection to a non-member");
                    self.net.disconnect(&c.node);
                }
            }
            let agreed = self.agreed();
            for &id in agreed.state().members.keys() {
                if id == self.me || self.net.is_connected(&id) {
                    continue;
                }
                let dir = self.dial_addrs(&id);
                if dir.is_empty() {
                    continue;
                }
                let net = self.net.clone();
                self.lifetime.spawn(async move {
                    if let Err(e) = net.connect(id).await {
                        debug!(peer = %id.short(), "connect: {e:#}");
                    }
                });
            }
        }
    }

    /// Re-reads interfaces, works out public reachability and the relay role,
    /// and keeps our agreed member record up to date.
    pub(super) async fn reachability_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        loop {
            tick.tick().await;
            if let Some(p) = &self.portmaps {
                p.retry();
            }
            self.refresh_facts();
            if let Err(e) = self.maybe_probe().await {
                debug!("reachability probe: {e:#}");
            }
            self.record_problem
                .record(self.update_member_record().await);
        }
    }

    /// Recomputes local facts from interfaces, port mappings and configuration.
    pub fn refresh_facts(&self) {
        let ifaces = self.opts.scan_interfaces(&self.overlay_nets());
        let (mapped_wg, mapped_control) = match &self.portmaps {
            Some(p) => (p.wg(), p.control()),
            None => (None, None),
        };
        let cport = self.opts.listen_port;
        let wport = self.opts.wg_port;
        // Public addresses we may be reachable at: advertised, global on an
        // interface, or mapped by the router.
        let mut public_ips: Vec<IpAddr> = self.opts.advertise.clone();
        public_ips.extend(ifaces.global.iter().copied());
        local::dedup(&mut public_ips);
        let mut candidates: Vec<SocketAddr> = public_ips
            .iter()
            .map(|ip| SocketAddr::new(*ip, cport))
            .collect();
        candidates.extend(mapped_control);
        local::dedup(&mut candidates);

        let mut f = self.facts.lock();
        let probed = f
            .last_probe
            .as_ref()
            .filter(|(_, c, _)| *c == candidates)
            .map(|(_, _, ok)| *ok);
        // Without a dial-back for these candidates yet, keep the previous result.
        f.public = match self.opts.relay {
            RelayMode::Always => true,
            _ => !candidates.is_empty() && probed.unwrap_or(f.public),
        };
        f.relay = match self.opts.relay {
            RelayMode::Always => true,
            RelayMode::Never => false,
            RelayMode::Auto => f.public,
        };
        // Public candidates are published once confirmed (or when bound to a
        // specific address, as in tests).
        let bind_specific = !self.opts.bind_ip.is_unspecified();
        let public: &[SocketAddr] = if f.public || bind_specific {
            &candidates
        } else {
            &[]
        };
        f.control_addrs = local::control_addrs(public, self.opts.bind_ip, cport, &ifaces);
        let mut wg_public: Vec<SocketAddr> = Vec::new();
        // A router mapping makes WireGuard reachable even if the node isn't
        // otherwise public.
        wg_public.extend(mapped_wg);
        if f.public {
            wg_public.extend(public_ips.iter().map(|ip| SocketAddr::new(*ip, wport)));
        }
        local::dedup(&mut wg_public);
        f.wg_public = wg_public;
        f.wg_lan = ifaces
            .ips
            .iter()
            .map(|ip| SocketAddr::new(*ip, wport))
            .collect();
        f.public_ip = if f.public {
            let ips: Vec<IpAddr> = candidates.iter().map(|c| c.ip()).collect();
            ips.iter().find(|ip| ip.is_ipv4()).or(ips.first()).copied()
        } else {
            None
        };
        f.via_mapping = f.public && public_ips.is_empty() && mapped_control.is_some();
        f.candidates = candidates;
        f.mapped_wg = mapped_wg;
        f.mapped_control = mapped_control;
        f.ifaces = ifaces;
    }

    /// Confirms public reachability by asking another member to dial us back.
    pub(super) async fn maybe_probe(&self) -> Result<()> {
        if self.opts.relay == RelayMode::Always {
            return Ok(());
        }
        let candidates: Vec<SocketAddr> = {
            let f = self.facts.lock();
            if f.candidates.is_empty() {
                return Ok(());
            }
            if let Some((when, prev, _)) = &f.last_probe
                && *prev == f.candidates
                && when.elapsed() < PROBE_INTERVAL
            {
                return Ok(());
            }
            f.candidates.clone()
        };
        let others: Vec<NodeId> = self
            .agreed()
            .value
            .value
            .members
            .keys()
            .filter(|n| **n != self.me)
            .copied()
            .collect();
        let connected: Vec<NodeId> = others
            .iter()
            .filter(|n| self.net.is_connected(n))
            .copied()
            .collect();
        if !others.is_empty() && connected.is_empty() {
            // Nobody can dial us back yet (e.g. just after starting). There
            // is no result, so check again on the next tick.
            debug!("reachability check deferred: no member connected");
            return Ok(());
        }
        let ok = if others.is_empty() {
            // Nobody to ask; a lone node with a candidate address counts as public.
            true
        } else {
            let mut ok = false;
            'outer: for via in &connected {
                for addr in &candidates {
                    match self.net.probe(*via, *addr).await {
                        Ok(()) => {
                            ok = true;
                            break 'outer;
                        }
                        Err(e) => debug!(%addr, via = %via.short(), "dial-back failed: {e:#}"),
                    }
                }
            }
            ok
        };
        info!(public = ok, candidates = ?candidates, "reachability checked");
        self.facts.lock().last_probe = Some((Instant::now(), candidates, ok));
        self.refresh_facts();
        Ok(())
    }

    /// Our member record as it should be.
    pub fn my_info(&self) -> MemberInfo {
        let f = self.facts.lock();
        MemberInfo {
            node_id: self.me,
            wg_key: self.wg_public,
            name: self.opts.name.clone(),
            control_addrs: f.control_addrs.clone(),
            wg_port: self.opts.wg_port,
            relay: f.relay,
        }
    }

    pub(super) async fn update_member_record(&self) -> Result<()> {
        let agreed = self.agreed();
        let Some(current) = agreed.state().members.get(&self.me) else {
            return Ok(());
        };
        let want = self.my_info();
        if current.info == want {
            return Ok(());
        }
        info!(relay = want.relay, addrs = ?want.control_addrs, "updating our member record");
        let signed = self.identity.seal(Domain::MemberInfo, &want);
        self.submit(Command::UpdateSelf { info: signed }).await?;
        Ok(())
    }
}
