//! Linux: kernel WireGuard over netlink, and TUN devices for userspace.
//! The kernel adds a route for each address's prefix.

mod kernel;

use std::{io, net::Ipv4Addr};

use anyhow::Result;
use ipnet::IpNet;

use super::{Platform, tun_builder, unix};
use crate::{Backend, InterfaceConfig};

pub(crate) struct Linux;

impl Platform for Linux {
    const DEFAULT_INTERFACE: &'static str = "cheesecloth0";
    const KERNEL_WIREGUARD: bool = true;

    fn open_kernel(config: &InterfaceConfig) -> Result<Box<dyn Backend>> {
        Ok(Box::new(kernel::Kernel::open(config)?))
    }

    fn remove_kernel(name: &str) -> Result<()> {
        kernel::remove(name)
    }

    fn create_tun(name: &str, addresses: &[IpNet], mtu: u16) -> Result<tun_rs::AsyncDevice> {
        Ok(tun_builder(name, addresses, mtu)?.build_async()?)
    }

    fn interface_exists(name: &str) -> Result<bool> {
        Ok(unix::interface_index(name)?.is_some())
    }

    fn send_raw_udp(dst: Ipv4Addr, segment: &[u8]) -> io::Result<()> {
        unix::send_raw_udp(dst, segment)
    }
}
