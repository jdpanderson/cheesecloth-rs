//! Real kernel and userspace WireGuard tests on Linux. They need
//! `CAP_NET_ADMIN` and `CAP_NET_RAW`, and change the network namespace they
//! run in, so run them in a new one: `unshare -rn <test binary>`.
#![cfg(target_os = "linux")]

mod common;

use std::process::Command;

use anyhow::{Context, Result, ensure};
use cheesecloth_wg::{Backend, BackendKind, InterfaceConfig, PeerConfig, generate_keypair};
use common::*;

const NAME: &str = "cctest0";

#[test]
fn real_tunnels() -> Result<()> {
    // A new network namespace starts with loopback down; the echo peer uses it.
    command("ip", &["link", "set", "lo", "up"])?;
    for (kind, expected) in [
        (BackendKind::Kernel, "kernel"),
        (BackendKind::Userspace, "userspace"),
        (BackendKind::Auto, "kernel"),
    ] {
        println!("checking {kind:?}");
        tunnel(kind, expected).with_context(|| format!("{kind:?}"))?;
    }
    check_nat_opener()?;
    Ok(())
}

fn tunnel(kind: BackendKind, expected: &str) -> Result<()> {
    let (private, public) = generate_keypair();
    let (remote_private, remote_public) = generate_keypair();
    let remote = EchoPeer::start(remote_private, public.0)?;
    let config = InterfaceConfig {
        name: NAME.into(),
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

    let mut interface = Interface(cheesecloth_wg::open(kind, &config)?);
    let backend = &mut interface.0;
    ensure!(
        backend.kind() == expected,
        "wrong backend: {}",
        backend.kind()
    );
    // Not /sys/class/net: it shows the namespace that mounted /sys.
    ensure!(
        command("ip", &["link", "show", NAME])?.contains("mtu 1280"),
        "MTU was not applied"
    );
    for address in [REMOTE_V4, REMOTE_V6] {
        ensure!(
            command("ip", &["route", "get", address])?.contains(&format!("dev {NAME}")),
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
    // Kernel WireGuard rounds handshake timestamps down to about 17 ms. If
    // the new peer's first handshake falls in the same step as the last one,
    // the echo peer drops it as a replay, and WireGuard retries after 5 s.
    backend.set_peer(&peer)?;
    exchange(LOCAL_V4, REMOTE_V4)?;
    exchange(LOCAL_V6, REMOTE_V6)?;

    if kind == BackendKind::Kernel {
        // A kernel interface outlives a crashed daemon. The next start
        // replaces it.
        std::mem::forget(interface);
        ensure!(interface_exists(NAME), "the interface did not survive");
        interface = Interface(cheesecloth_wg::open(kind, &config)?);
        ensure!(
            interface.0.status()?.is_empty(),
            "the replaced interface kept its peers"
        );
        interface.0.set_peer(&peer)?;
        exchange(LOCAL_V4, REMOTE_V4)?;
        refuses_foreign_interface(&config)?;
    }

    let backend = &mut interface.0;
    backend.down().context("removing the interface")?;
    backend.down().context("repeating interface removal")?;
    ensure!(!interface_exists(NAME), "interface survived removal");
    ensure!(
        !command("ip", &["route"])?.contains(NAME),
        "route survived removal"
    );
    let actual = match expected {
        "kernel" => BackendKind::Kernel,
        _ => BackendKind::Userspace,
    };
    cheesecloth_wg::remove_existing(actual, NAME)?;
    remote.finish()
}

/// The kernel backend never deletes an interface that is not WireGuard.
fn refuses_foreign_interface(config: &InterfaceConfig) -> Result<()> {
    let name = "cctest1";
    command("ip", &["link", "add", name, "type", "dummy"])?;
    let config = InterfaceConfig {
        name: name.into(),
        ..config.clone()
    };
    let error = match cheesecloth_wg::open(BackendKind::Kernel, &config) {
        Ok(_) => anyhow::bail!("a dummy interface was replaced"),
        Err(e) => format!("{e:#}"),
    };
    ensure!(
        error.contains("not a WireGuard interface"),
        "unexpected error: {error}"
    );
    ensure!(
        cheesecloth_wg::remove_existing(BackendKind::Kernel, name).is_err(),
        "cleanup accepted a dummy interface"
    );
    ensure!(interface_exists(name), "the dummy interface was deleted");
    command("ip", &["link", "del", name])?;
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

fn command(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program).args(args).output()?;
    ensure!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}
