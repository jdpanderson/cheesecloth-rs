//! Windows: userspace WireGuard on a Wintun adapter. Windows adds an on-link
//! route for each address's prefix. This crate does not drive WireGuardNT.

use std::{io, iter, net::Ipv4Addr};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use windows_sys::Win32::{
    Foundation::{ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND, NO_ERROR},
    NetworkManagement::{IpHelper::ConvertInterfaceAliasToLuid, Ndis::NET_LUID_LH},
};

use super::Platform;
use crate::{Backend, InterfaceConfig};

pub(crate) struct Windows;

impl Platform for Windows {
    const DEFAULT_INTERFACE: &'static str = "cheesecloth0";
    const KERNEL_WIREGUARD: bool = false;

    fn open_kernel(_config: &InterfaceConfig) -> Result<Box<dyn Backend>> {
        bail!("kernel WireGuard (WireGuardNT) is not supported on Windows")
    }

    fn remove_kernel(_name: &str) -> Result<()> {
        bail!("kernel WireGuard (WireGuardNT) is not supported on Windows")
    }

    fn create_tun(name: &str, addresses: &[IpNet], mtu: u16) -> Result<tun_rs::AsyncDevice> {
        // Load wintun.dll from beside the executable only. A bare name would
        // let the DLL search path, which includes PATH, choose the file.
        let wintun = std::env::current_exe()
            .context("finding the executable")?
            .with_file_name("wintun.dll");
        let wintun = wintun
            .to_str()
            .context("the path to wintun.dll is not valid UTF-8")?
            .to_owned();
        Ok(super::tun_builder(name, addresses, mtu)?
            .with(|b| {
                b.wintun_file(wintun.clone());
            })
            .build_async()?)
    }

    #[allow(unsafe_code, reason = "windows-sys has no safe interface lookup")]
    fn interface_exists(name: &str) -> Result<bool> {
        let alias: Vec<u16> = name.encode_utf16().chain(iter::once(0)).collect();
        let mut luid = NET_LUID_LH { Value: 0 };
        // SAFETY: alias is a live, NUL-terminated UTF-16 string and luid is a
        // valid place to write; the call retains neither pointer.
        let status = unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) };
        match status {
            NO_ERROR => Ok(true),
            // Both pointers are valid, so an invalid parameter is an unknown alias.
            ERROR_NOT_FOUND | ERROR_INVALID_PARAMETER => Ok(false),
            error => Err(io::Error::from_raw_os_error(error as i32).into()),
        }
    }

    fn send_raw_udp(_dst: Ipv4Addr, _segment: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NAT openers aren't supported on this platform",
        ))
    }
}
