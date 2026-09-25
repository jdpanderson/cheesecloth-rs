//! What a node can see about its own network: interface addresses, the
//! networks it's attached to, and which addresses are globally routable.

use std::net::{IpAddr, SocketAddr};

use cheesecloth_core::{addr::is_global, state::MAX_CONTROL_ADDRS};
use ipnet::IpNet;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Interfaces {
    /// Networks of this node's interfaces (for "same LAN" checks).
    pub nets: Vec<IpNet>,
    /// Usable unicast addresses, excluding loopback, link-local and overlay.
    pub ips: Vec<IpAddr>,
    /// The subset of `ips` that is globally routable.
    pub global: Vec<IpAddr>,
}

/// Reads interface addresses, skipping cheesecloth's own interface and
/// anything inside the overlay ranges.
pub fn scan(own_interface: &str, overlay: &[IpNet]) -> Interfaces {
    let mut out = Interfaces::default();
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return out;
    };
    for iface in ifaces {
        if iface.name == own_interface || iface.is_loopback() {
            continue;
        }
        let (ip, prefix) = match &iface.addr {
            if_addrs::IfAddr::V4(a) => (IpAddr::V4(a.ip), a.prefixlen),
            if_addrs::IfAddr::V6(a) => (IpAddr::V6(a.ip), a.prefixlen),
        };
        if overlay.iter().any(|n| n.contains(&ip)) {
            continue;
        }
        let link_local = match ip {
            IpAddr::V4(v4) => v4.is_link_local(),
            IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
        };
        if link_local || ip.is_unspecified() || ip.is_multicast() {
            continue;
        }
        if let Ok(net) = IpNet::new(ip, prefix) {
            out.nets.push(net.trunc());
        }
        out.ips.push(ip);
        if is_global(&ip) {
            out.global.push(ip);
        }
    }
    out.nets.sort();
    out.nets.dedup();
    out.ips.sort();
    out.ips.dedup();
    out.global.sort();
    out.global.dedup();
    out
}

/// The control-plane addresses a node publishes: `public` first, then the
/// address it's bound to or, when bound to all addresses, the interface
/// addresses (IPv4 first). At most `MAX_CONTROL_ADDRS`, the limit for a
/// member record: a host with many IPv6 addresses loses the last of them.
pub fn control_addrs(
    public: &[SocketAddr],
    bind_ip: IpAddr,
    port: u16,
    ifaces: &Interfaces,
) -> Vec<SocketAddr> {
    let mut out = public.to_vec();
    if bind_ip.is_unspecified() {
        out.extend(ifaces.ips.iter().map(|ip| SocketAddr::new(*ip, port)));
    } else {
        out.push(SocketAddr::new(bind_ip, port));
    }
    dedup(&mut out);
    out.truncate(MAX_CONTROL_ADDRS);
    out
}

/// Removes repeated items, keeping the first of each, in order.
pub fn dedup<T: Eq + std::hash::Hash + Copy>(items: &mut Vec<T>) {
    let mut seen = std::collections::HashSet::new();
    items.retain(|i| seen.insert(*i));
}

/// Existing routes to avoid when choosing an overlay range: the networks of
/// this host's interfaces.
pub fn existing_networks() -> Vec<IpNet> {
    scan("", &[]).nets
}

#[cfg(test)]
mod tests;
