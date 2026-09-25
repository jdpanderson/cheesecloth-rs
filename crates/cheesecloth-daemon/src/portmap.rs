//! Router port mapping (PCP, NAT-PMP or UPnP, via `portmapper`) for the
//! WireGuard and control-plane ports.
//!
//! A mapped control port makes the node a relay candidate (the dial-back still
//! has to confirm it). A mapped WireGuard port is published as a public
//! WireGuard endpoint, so peers can reach the node directly even behind a NAT
//! where punching fails.

use parking_lot::Mutex;
use std::{
    net::SocketAddr,
    num::NonZeroU16,
    time::{Duration, Instant},
};

use portmapper::{Client, Config};
use tracing::info;

/// How often to ask again for a mapping the router hasn't granted.
const RETRY: Duration = Duration::from_secs(60);

pub struct PortMaps {
    wg: Client,
    control: Client,
    last_retry: Mutex<Instant>,
}

fn client(port: u16) -> Client {
    let c = Client::new(Config::default());
    if let Some(p) = NonZeroU16::new(port) {
        c.update_local_port(p);
    }
    c
}

fn external(c: &Client) -> Option<SocketAddr> {
    (*c.watch_external_address().borrow()).map(SocketAddr::V4)
}

impl PortMaps {
    /// Starts asking the router for mappings of both ports.
    pub fn start(wg_port: u16, control_port: u16) -> Self {
        Self {
            wg: client(wg_port),
            control: client(control_port),
            last_retry: Mutex::new(Instant::now()),
        }
    }

    /// The router's address and port for our WireGuard port, if mapped.
    pub fn wg(&self) -> Option<SocketAddr> {
        external(&self.wg)
    }

    /// The router's address and port for our control-plane port, if mapped.
    pub fn control(&self) -> Option<SocketAddr> {
        external(&self.control)
    }

    /// Asks again for any mapping we don't have, at most once a minute.
    /// (Granted mappings are renewed by `portmapper` itself.)
    pub fn retry(&self) {
        let mut last = self.last_retry.lock();
        if last.elapsed() < RETRY {
            return;
        }
        *last = Instant::now();
        for c in [&self.wg, &self.control] {
            if external(c).is_none() {
                c.procure_mapping();
            }
        }
    }

    /// Releases the mappings on the router.
    pub async fn stop(&self) {
        let had = self.wg().is_some() || self.control().is_some();
        self.wg.deactivate();
        self.control.deactivate();
        if had {
            // Give the release requests a moment before the clients are dropped.
            tokio::time::sleep(Duration::from_secs(1)).await;
            info!("released router port mappings");
        }
    }
}
