//! NAT openers: a one-byte UDP packet sent from WireGuard's listen port with a
//! raw socket, so the local NAT creates the same mapping WireGuard will use.
//! The far end's WireGuard drops it as garbage.
//!
//! Needs `CAP_NET_RAW` on Linux and root on FreeBSD and macOS. Windows is not
//! supported yet (see the platform status in README.md).

use std::{io, net::SocketAddr};

/// Sends one opener from `src_port` to `dst`. IPv4 only.
pub fn send(src_port: u16, dst: SocketAddr) -> io::Result<()> {
    let SocketAddr::V4(dst) = dst else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NAT openers are IPv4 only",
        ));
    };
    #[cfg(unix)]
    {
        use socket2::{Domain, Protocol, SockAddr, Socket, Type};
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP))?;
        let packet = udp_packet(src_port, dst.port(), &[0]);
        // For raw sockets the port in the destination address is ignored; the
        // UDP header carries it.
        let to = SockAddr::from(SocketAddr::new((*dst.ip()).into(), 0));
        socket.send_to(&packet, &to)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (src_port, dst);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NAT openers aren't supported on this platform",
        ))
    }
}

/// A UDP header plus payload. The checksum is left at 0, which IPv4 allows.
fn udp_packet(src: u16, dst: u16, payload: &[u8]) -> Vec<u8> {
    let len = (8 + payload.len()) as u16;
    let mut p = Vec::with_capacity(len as usize);
    p.extend_from_slice(&src.to_be_bytes());
    p.extend_from_slice(&dst.to_be_bytes());
    p.extend_from_slice(&len.to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    p
}

#[cfg(test)]
mod tests;
