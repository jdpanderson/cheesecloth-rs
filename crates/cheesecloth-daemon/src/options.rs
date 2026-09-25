//! Daemon configuration.

use std::{
    io,
    net::{IpAddr, Ipv6Addr},
    path::{Path, PathBuf},
};

use cheesecloth_core::state::MAX_NAME_LEN;
use cheesecloth_wg::BackendKind;

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
    /// Local API socket; defaults to `<state_dir>/control.sock`.
    pub socket: Option<PathBuf>,
    /// Address to bind the control plane to (`::` for all, dual-stack).
    pub bind_ip: IpAddr,
    /// Control-plane (QUIC) UDP port.
    pub listen_port: u16,
    /// WireGuard UDP port.
    pub wg_port: u16,
    pub relay: RelayMode,
    /// WireGuard persistent keepalive; default 25 s behind NAT, off when
    /// public. (The control plane's QUIC keep-alive is always 25 s.)
    pub keepalive: Option<u16>,
    /// Extra addresses at which this node is reachable (e.g. a 1:1 NAT address).
    pub advertise: Vec<IpAddr>,
    pub interface: String,
    pub backend: BackendKind,
    pub name: String,
    /// Ask the router for port mappings (PCP, NAT-PMP or UPnP).
    pub port_mapping: bool,
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
        })
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

    pub fn socket_path(&self) -> PathBuf {
        socket_path(&self.state_dir, self.socket.as_deref())
    }
}

/// The local API socket: `socket` if given, else `<state_dir>/control.sock`.
/// The CLI uses this too, to find the daemon.
pub fn socket_path(state_dir: &Path, socket: Option<&Path>) -> PathBuf {
    socket.map_or_else(|| state_dir.join("control.sock"), Path::to_path_buf)
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
mod tests {
    use super::*;

    #[test]
    fn names_fit_in_a_member_record() {
        assert_eq!(cut_name("short".into()), "short");
        // 20 two-byte characters: cut to 16 of them, not in the middle of one.
        assert_eq!(cut_name("é".repeat(20)), "é".repeat(16));
        let opts = Options::new(PathBuf::from("/tmp"), None).unwrap();
        assert!(opts.check().is_ok());
        let opts = Options::new(PathBuf::from("/tmp"), Some("n".repeat(MAX_NAME_LEN + 1))).unwrap();
        let e = opts.check().unwrap_err();
        assert!(e.contains("longer than 32 bytes"), "{e}");
    }
}
