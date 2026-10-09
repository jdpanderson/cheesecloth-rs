//! POSIX calls that the Unix platforms share.

use std::{
    ffi::CString,
    io,
    net::{Ipv4Addr, SocketAddr},
};

use anyhow::Result;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// The index of the interface with this name, or `None` if there is none.
#[allow(unsafe_code, reason = "the standard library has no if_nametoindex")]
pub(super) fn interface_index(name: &str) -> Result<Option<u32>> {
    let name = CString::new(name)?;
    // SAFETY: name is a live, NUL-terminated string; this call retains no pointer.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index != 0 {
        return Ok(Some(index));
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENXIO | libc::ENODEV) => Ok(None),
        _ => Err(error.into()),
    }
}

/// See [`super::Platform::send_raw_udp`].
pub(super) fn send_raw_udp(dst: Ipv4Addr, segment: &[u8]) -> io::Result<()> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP))?;
    // For raw sockets the port in the destination address is ignored; the
    // UDP header carries it.
    let to = SockAddr::from(SocketAddr::new(dst.into(), 0));
    socket.send_to(segment, &to)?;
    Ok(())
}
