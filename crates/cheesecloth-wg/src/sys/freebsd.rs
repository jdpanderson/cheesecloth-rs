//! FreeBSD: userspace WireGuard on a TUN device. This crate does not drive
//! FreeBSD's kernel WireGuard (if_wg).

use std::{io, net::Ipv4Addr};

use anyhow::{Result, bail};
use ipnet::IpNet;

use super::{Platform, tun_builder, unix};
use crate::{Backend, InterfaceConfig};

pub(crate) struct FreeBsd;

impl Platform for FreeBsd {
    const DEFAULT_INTERFACE: &'static str = "wg77";
    const KERNEL_WIREGUARD: bool = false;

    fn open_kernel(_config: &InterfaceConfig) -> Result<Box<dyn Backend>> {
        bail!("kernel WireGuard is not supported on FreeBSD")
    }

    fn remove_kernel(_name: &str) -> Result<()> {
        bail!("kernel WireGuard is not supported on FreeBSD")
    }

    fn create_tun(name: &str, addresses: &[IpNet], mtu: u16) -> Result<tun_rs::AsyncDevice> {
        Ok(tun_builder(name, addresses, mtu)?
            // A TUN device is point-to-point, so the system adds no route
            // for an address's prefix. tun-rs adds it.
            .with(|b| {
                b.associate_route(true);
            })
            .build_async()?)
    }

    fn interface_exists(name: &str) -> Result<bool> {
        Ok(unix::interface_index(name)?.is_some())
    }

    fn send_raw_udp(dst: Ipv4Addr, segment: &[u8]) -> io::Result<()> {
        unix::send_raw_udp(dst, segment)
    }
}
