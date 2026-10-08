//! Router port mapping (UPnP or PCP, via `port-control-client`) for the
//! WireGuard and control-plane ports.
//!
//! A mapped control port makes the node a relay candidate (the dial-back still
//! has to confirm it). A mapped WireGuard port is published as a public
//! WireGuard endpoint, so peers can reach the node directly even behind a NAT
//! where punching fails.

use std::{net::SocketAddr, num::NonZeroU16};

use port_control_client::{Config, Method, PortMapping, Protocol};
use tracing::info;

use crate::api::{PortMapGrant, PortMapView};

/// Each mapping has a background task that gets it, renews it, and asks again
/// after a minute if the router hasn't granted it.
pub struct PortMaps {
    wg: Option<PortMapping>,
    control: Option<PortMapping>,
}

/// Both ports are UDP: WireGuard, and QUIC for the control plane. UPnP comes
/// first because more routers have it than PCP.
fn start(port: u16) -> Option<PortMapping> {
    let port = NonZeroU16::new(port)?;
    Some(PortMapping::start(
        Config::new(Protocol::Udp, port)
            .description("cheesecloth")
            .methods([Method::Upnp, Method::Pcp]),
    ))
}

fn external(m: &Option<PortMapping>) -> Option<SocketAddr> {
    m.as_ref()?.mapping().map(|m| SocketAddr::V4(m.external))
}

fn view(port: &str, m: &Option<PortMapping>) -> Option<PortMapView> {
    let m = m.as_ref()?;
    let status = m.status();
    Some(PortMapView {
        port: port.into(),
        local_port: m.local_port().get(),
        mapped: status.mapping().map(|g| PortMapGrant {
            external: SocketAddr::V4(g.external),
            method: g.method.to_string(),
        }),
        error: status.error().map(ToString::to_string),
    })
}

async fn stop(m: &Option<PortMapping>) {
    if let Some(m) = m {
        m.stop().await;
    }
}

impl PortMaps {
    /// Starts asking the router for mappings of both ports.
    pub fn start(wg_port: u16, control_port: u16) -> Self {
        Self {
            wg: start(wg_port),
            control: start(control_port),
        }
    }

    /// The state of each mapping, for `status`.
    pub fn views(&self) -> Vec<PortMapView> {
        [view("wireguard", &self.wg), view("control", &self.control)]
            .into_iter()
            .flatten()
            .collect()
    }

    /// The router's address and port for our WireGuard port, if mapped.
    pub fn wg(&self) -> Option<SocketAddr> {
        external(&self.wg)
    }

    /// The router's address and port for our control-plane port, if mapped.
    pub fn control(&self) -> Option<SocketAddr> {
        external(&self.control)
    }

    /// Releases the mappings on the router. Each release waits up to two
    /// seconds for the router to answer.
    pub async fn stop(&self) {
        let had = self.wg().is_some() || self.control().is_some();
        tokio::join!(stop(&self.wg), stop(&self.control));
        if had {
            info!("released router port mappings");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn port_zero_is_not_mapped() {
        let maps = PortMaps::start(0, 0);
        assert!(maps.wg.is_none() && maps.control.is_none());
        assert_eq!((maps.wg(), maps.control()), (None, None));
        assert!(maps.views().is_empty());
        tokio::time::timeout(std::time::Duration::from_millis(100), maps.stop())
            .await
            .expect("nothing to release");
    }
}
