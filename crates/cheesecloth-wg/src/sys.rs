//! Calls into the operating system. Each supported OS implements
//! [`Platform`], and the rest of the crate reaches the OS only through
//! [`Os`], the implementation for the target.

use std::{
    io,
    net::{IpAddr, Ipv4Addr},
};

use anyhow::Result;
use ipnet::IpNet;

use crate::{Backend, InterfaceConfig};

#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "freebsd")]
pub(crate) use freebsd::FreeBsd as Os;
#[cfg(target_os = "linux")]
pub(crate) use linux::Linux as Os;
#[cfg(target_os = "macos")]
pub(crate) use macos::MacOs as Os;
#[cfg(windows)]
pub(crate) use windows::Windows as Os;

/// What this crate needs from an operating system.
pub(crate) trait Platform {
    /// The interface name to use when none is configured.
    const DEFAULT_INTERFACE: &'static str;

    /// Whether this crate can use kernel WireGuard on this OS.
    const KERNEL_WIREGUARD: bool;

    /// Creates the interface with kernel WireGuard, configures it and brings
    /// it up. Fails if `KERNEL_WIREGUARD` is false, or if the kernel lacks
    /// WireGuard.
    fn open_kernel(config: &InterfaceConfig) -> Result<Box<dyn Backend>>;

    /// Deletes a kernel WireGuard interface that an earlier run left behind.
    /// An absent interface is not an error.
    fn remove_kernel(name: &str) -> Result<()>;

    /// Creates a TUN device with `addresses` and `mtu`, and brings it up.
    /// Each address's prefix is routed into the device. Must be called
    /// within a tokio runtime, which then serves the device.
    fn create_tun(name: &str, addresses: &[IpNet], mtu: u16) -> Result<tun_rs::AsyncDevice>;

    /// Whether a network interface with this name exists.
    fn interface_exists(name: &str) -> Result<bool>;

    /// Sends `segment`, a UDP header and its payload, to `dst` through a raw
    /// socket. The OS adds the IP header. This lets a datagram leave from a
    /// port that another socket holds.
    fn send_raw_udp(dst: Ipv4Addr, segment: &[u8]) -> io::Result<()>;
}

/// The tun-rs settings that every OS shares.
fn tun_builder(name: &str, addresses: &[IpNet], mtu: u16) -> Result<tun_rs::DeviceBuilder> {
    let mut builder = tun_rs::DeviceBuilder::new().name(name).mtu(mtu);
    let mut ipv4 = false;
    for address in addresses {
        builder = match address.addr() {
            IpAddr::V4(ip) => {
                // tun-rs keeps a single IPv4 address; a second would replace the first.
                anyhow::ensure!(!ipv4, "a TUN device takes one IPv4 address");
                ipv4 = true;
                builder.ipv4(ip, address.prefix_len(), None)
            }
            IpAddr::V6(ip) => builder.ipv6(ip, address.prefix_len()),
        };
    }
    Ok(builder)
}
