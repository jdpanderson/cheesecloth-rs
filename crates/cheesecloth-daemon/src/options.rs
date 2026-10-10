//! Daemon configuration.

use std::{
    io,
    net::{IpAddr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::Arc,
};

use cheesecloth_core::state::MAX_NAME_LEN;
use cheesecloth_wg::BackendKind;
use ipnet::IpNet;

use crate::local::{self, Interfaces};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayMode {
    Auto,
    Always,
    Never,
}

impl std::str::FromStr for RelayMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "auto" => Ok(Self::Auto),
            "always" => Ok(Self::Always),
            "never" => Ok(Self::Never),
            _ => Err(format!("expected auto, always or never, not {s:?}")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Options {
    pub state_dir: PathBuf,
    /// Local API address: a socket path, or a pipe name on Windows. See
    /// `socket_path` for the default.
    pub socket: Option<PathBuf>,
    /// Address to bind the control plane to (`::` for all, dual-stack).
    pub bind_ip: IpAddr,
    /// Control-plane (QUIC) UDP port. With 0, the system chooses one, and
    /// `Daemon::start` sets this to it.
    pub listen_port: u16,
    /// WireGuard UDP port.
    pub wg_port: u16,
    pub relay: RelayMode,
    /// WireGuard persistent keepalive; default 300 s when the router maps the
    /// WireGuard port, else 25 s behind NAT and off when public. (The control
    /// plane's QUIC keep-alive is always 25 s.)
    pub keepalive: Option<u16>,
    /// Extra addresses at which this node is reachable (e.g. a 1:1 NAT address).
    pub advertise: Vec<IpAddr>,
    pub interface: String,
    pub backend: BackendKind,
    pub name: String,
    /// Ask the router for port mappings (UPnP or PCP).
    pub port_mapping: bool,
    /// Interfaces to use instead of the host's, so that tests do not depend
    /// on the networks of the machine that runs them.
    pub(crate) interfaces: Option<Arc<parking_lot::Mutex<Interfaces>>>,
}

impl Options {
    /// Uses the host name unless an explicit name is supplied.
    pub fn new(state_dir: PathBuf, name: Option<String>) -> io::Result<Self> {
        let name = match name {
            Some(name) => name,
            None => host_name()?,
        };
        Ok(Self {
            state_dir,
            socket: None,
            bind_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            listen_port: cheesecloth_core::DEFAULT_CONTROL_PORT,
            wg_port: cheesecloth_core::DEFAULT_WG_PORT,
            relay: RelayMode::Auto,
            keepalive: None,
            advertise: Vec::new(),
            interface: cheesecloth_wg::default_interface_name().into(),
            backend: BackendKind::Auto,
            name,
            port_mapping: true,
            interfaces: None,
        })
    }

    /// This node's interfaces, without its own interface or the `overlay`
    /// ranges (see `local::scan`).
    pub(crate) fn scan_interfaces(&self, overlay: &[IpNet]) -> Interfaces {
        match &self.interfaces {
            Some(fixed) => fixed.lock().clone(),
            None => local::scan(&self.interface, overlay),
        }
    }

    /// Checks what can't be checked while parsing.
    pub fn check(&self) -> Result<(), String> {
        if self.name.len() > MAX_NAME_LEN {
            return Err(format!(
                "the name {:?} is longer than {MAX_NAME_LEN} bytes",
                self.name
            ));
        }
        Ok(())
    }

    pub fn socket_path(&self) -> io::Result<PathBuf> {
        socket_path(&self.state_dir, self.socket.as_deref())
    }
}

/// The local API address: `socket` if given, else `<state_dir>/control.sock`,
/// or on Windows a pipe named after the state directory. The CLI uses this
/// too, to find the daemon.
pub fn socket_path(state_dir: &Path, socket: Option<&Path>) -> io::Result<PathBuf> {
    match socket {
        Some(socket) => Ok(socket.to_path_buf()),
        None => crate::ipc::default_address(state_dir),
    }
}

/// The host name, cut to the longest name a member may have.
fn host_name() -> io::Result<String> {
    Ok(cut_name(hostname::get()?.to_string_lossy().into_owned()))
}

/// Cuts `name` to at most `MAX_NAME_LEN` bytes, at a character boundary.
fn cut_name(mut name: String) -> String {
    let mut end = name.len().min(MAX_NAME_LEN);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name.truncate(end);
    name
}

#[cfg(test)]
mod tests;
