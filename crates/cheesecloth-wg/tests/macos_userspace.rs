//! Real utun and encrypted packet tests. Run only on a disposable Mac with root.
#![cfg(target_os = "macos")]

mod common;

use std::process::Command;

use anyhow::{Context, Result, ensure};
use cheesecloth_wg::{Backend, BackendKind, InterfaceConfig, PeerConfig, generate_keypair};
use common::*;

#[test]
fn real_userspace_tunnel() -> Result<()> {
    ensure!(is_root(), "this test requires root");
    let dns_before = dns_settings()?;
    let name = (200..256)
        .map(|i| format!("utun{i}"))
        .find(|name| !interface_exists(name))
        .context("no unused test interface")?;
    let (private, public) = generate_keypair();
    let (remote_private, remote_public) = generate_keypair();
    let remote = EchoPeer::start(remote_private, public.0)?;
    let config = InterfaceConfig {
        name: name.clone(),
        private_key: private,
        listen_port: 0,
        addresses: vec![
            format!("{LOCAL_V4}/24").parse()?,
            format!("{LOCAL_V6}/64").parse()?,
        ],
        mtu: Some(1280),
    };
    let peer = PeerConfig {
        key: remote_public,
        endpoint: Some(remote.endpoint),
        keepalive: 0,
        allowed_ips: vec![
            format!("{REMOTE_V4}/32").parse()?,
            format!("{REMOTE_V6}/128").parse()?,
        ],
    };

    // Reuse the same name and addresses to catch leaked interfaces or routes.
    for kind in [BackendKind::Auto, BackendKind::Userspace] {
        println!("checking {kind:?} on {name}");
        let mut interface = Interface(cheesecloth_wg::open(kind, &config)?);
        let backend = &mut interface.0;
        ensure!(backend.kind() == "userspace", "wrong backend selected");
        ensure!(
            command("/sbin/ifconfig", &[&name])?.contains("mtu 1280"),
            "MTU was not applied"
        );
        for address in [REMOTE_V4, REMOTE_V6] {
            ensure!(
                route_interface(address)? == name,
                "missing route to {address}"
            );
        }
        backend.set_peer(&peer)?;
        exchange(LOCAL_V4, REMOTE_V4)?;
        exchange(LOCAL_V6, REMOTE_V6)?;
        let status = backend.status()?;
        ensure!(
            status.len() == 1 && status[0].key == peer.key,
            "incorrect peers: {status:?}"
        );
        ensure!(
            status[0].handshake_age().is_some(),
            "no WireGuard handshake"
        );
        ensure!(
            status[0].rx_bytes > 0 && status[0].tx_bytes > 0,
            "no encrypted traffic"
        );

        // A peer changes in place.
        let updated = PeerConfig {
            keepalive: 25,
            ..peer.clone()
        };
        backend.set_peer(&updated)?;
        let status = backend.status()?;
        ensure!(
            status.len() == 1 && status[0].keepalive == 25,
            "peer was not updated: {status:?}"
        );
        exchange(LOCAL_V4, REMOTE_V4)?;

        backend.remove_peer(&peer.key)?;
        ensure!(
            backend.status()?.is_empty(),
            "removed peer is still present"
        );
        no_exchange(LOCAL_V4, REMOTE_V4)?;
        no_exchange(LOCAL_V6, REMOTE_V6)?;
        backend.set_peer(&peer)?;
        exchange(LOCAL_V4, REMOTE_V4)?;
        exchange(LOCAL_V6, REMOTE_V6)?;
        backend.down().context("removing the interface")?;
        backend.down().context("repeating interface removal")?;
        ensure!(!interface_exists(&name), "interface survived removal");
        ensure!(
            !command("/usr/sbin/netstat", &["-rn"])?
                .split_whitespace()
                .any(|field| field == name),
            "route survived removal"
        );
        cheesecloth_wg::remove_existing(BackendKind::Userspace, &name)?;
    }
    remote.finish()?;
    check_nat_opener()?;
    ensure!(dns_settings()? == dns_before, "DNS settings changed");
    Ok(())
}

// Keep cleanup active when an assertion or packet exchange fails.
struct Interface(Box<dyn Backend>);

impl Drop for Interface {
    fn drop(&mut self) {
        if let Err(error) = self.0.down() {
            eprintln!("interface cleanup failed: {error:#}");
        }
    }
}

#[allow(unsafe_code, reason = "the standard library has no geteuid")]
fn is_root() -> bool {
    // SAFETY: geteuid has no arguments or side effects.
    unsafe { libc::geteuid() == 0 }
}

fn command(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program).args(args).output()?;
    ensure!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn route_interface(address: &str) -> Result<String> {
    let family = if address.contains(':') {
        "-inet6"
    } else {
        "-inet"
    };
    command("/sbin/route", &["-n", "get", family, address])?
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("interface:")
                .map(|s| s.trim().to_owned())
        })
        .context("route has no interface")
}

fn dns_settings() -> Result<Vec<String>> {
    let services = command("/usr/sbin/networksetup", &["-listallnetworkservices"])?;
    let mut settings = Vec::new();
    for service in services.lines().skip(1) {
        let service = service.trim_start_matches('*');
        settings.push(service.to_owned());
        for flag in ["-getdnsservers", "-getsearchdomains"] {
            settings.push(command("/usr/sbin/networksetup", &[flag, service])?);
        }
    }
    Ok(settings)
}
