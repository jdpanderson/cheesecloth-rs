//! The `cheesecloth` binary end to end: daemons run as child processes with
//! the mock WireGuard backend on localhost, driven by CLI commands.

use std::{
    net::UdpSocket,
    path::Path,
    process::{Child, Command, Output},
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_cheesecloth");

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Daemon {
    child: Child,
    dir: tempfile::TempDir,
}

impl Daemon {
    fn start(name: &str, relay: &str) -> Daemon {
        Daemon::start_in(tempfile::tempdir().unwrap(), name, relay)
    }

    /// Starts a daemon on an existing state directory.
    fn start_in(dir: tempfile::TempDir, name: &str, relay: &str) -> Daemon {
        let child = Command::new(BIN)
            .arg("--state-dir")
            .arg(dir.path())
            .args(["daemon", "--wireguard", "mock", "--no-port-mapping"])
            .args(["--bind", "127.0.0.1", "--relay", relay, "--name", name])
            .args(["--interface", &format!("mock-{name}"), "--log", "off"])
            .args(["--listen-port", &free_port().to_string()])
            .args(["--wg-port", &free_port().to_string()])
            .args(["--keepalive", "20"])
            .env_remove("CHEESECLOTH_SOCKET")
            .spawn()
            .unwrap();
        let d = Daemon { child, dir };
        // A daemon that ran on this directory before leaves its socket file,
        // so wait for an answer, not for the file.
        wait_until("the local API", || d.cli(&["status"]).status.success());
        d
    }

    fn cli(&self, args: &[&str]) -> Output {
        cli_in(self.dir.path(), args)
    }

    /// Runs a command that must succeed; returns its stdout.
    fn ok(&self, args: &[&str]) -> String {
        let out = self.cli(args);
        assert!(
            out.status.success(),
            "cheesecloth {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    /// Runs a command that may fail (while polling); returns its stdout.
    fn try_ok(&self, args: &[&str]) -> String {
        String::from_utf8(self.cli(args).stdout).unwrap()
    }

    /// Runs a command that must fail; returns its stderr.
    fn err(&self, args: &[&str]) -> String {
        let out = self.cli(args);
        assert!(!out.status.success(), "cheesecloth {args:?} succeeded");
        String::from_utf8(out.stderr).unwrap()
    }

    fn json(&self, args: &[&str]) -> serde_json::Value {
        let mut all = vec!["--json"];
        all.extend_from_slice(args);
        serde_json::from_str(&self.ok(&all)).unwrap()
    }

    /// Stops the daemon the way a service manager does.
    fn stop(mut self) {
        let pid = self.child.id().to_string();
        assert!(
            Command::new("kill")
                .args(["-TERM", &pid])
                .status()
                .unwrap()
                .success()
        );
        self.wait_for_exit();
    }

    /// Waits for the daemon to exit by itself, which it must do cleanly.
    fn wait_for_exit(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "daemon exited with {status}");
                return;
            }
            assert!(Instant::now() < deadline, "daemon didn't stop");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Stops the daemon with `cheesecloth stop` and returns its state
    /// directory.
    fn stop_with_cli(mut self) -> tempfile::TempDir {
        assert_eq!(self.ok(&["stop"]).trim(), "Stopped.");
        self.wait_for_exit();
        let dir = tempfile::tempdir().unwrap();
        std::mem::replace(&mut self.dir, dir)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn cli_in(state_dir: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .arg("--state-dir")
        .arg(state_dir)
        .args(args)
        .env_remove("CHEESECLOTH_SOCKET")
        .output()
        .unwrap()
}

fn wait_until(what: &str, f: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The full proposal token in "... proposal N ..." or "Proposal N ...".
fn proposal_in(s: &str) -> String {
    let lower = s.to_lowercase();
    let rest = &lower[lower.find("proposal ").expect(s) + 9..];
    rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect()
}

#[test]
fn the_cli_drives_a_cluster() {
    let a = Daemon::start("alpha", "always");
    let b = Daemon::start("bravo", "never");
    let c = Daemon::start("charlie", "never");

    // Not in a cluster yet.
    let s = a.ok(&["status"]);
    assert!(s.contains("cluster   none"), "{s}");
    assert!(a.err(&["invite"]).contains("not in a cluster"));

    let s = a.ok(&["init", "--ipv4-range", "100.64.50.0/24"]);
    assert!(s.contains("Created cluster"), "{s}");
    assert!(s.contains("Overlay IPv4 range: 100.64.50.0/24"), "{s}");

    let token = a.ok(&["invite"]).trim().to_string();
    assert!(token.starts_with("cc1"), "{token}");
    let s = b.ok(&["join", &token]);
    assert_eq!(
        s.trim(),
        "Joined; this node's overlay address is 100.64.50.2"
    );

    let wants = [
        "node      ",
        "(alpha)",
        "(2 members)",
        "overlay   100.64.50.1",
        "role      relay",
        "keepalive 20s",
        "consensus state version",
        "wireguard mock on mock-alpha",
        "control   127.0.0.1:",
        "portmap   off",
    ];
    // The role and the interface are filled in by the daemon's loops.
    wait_until("the role and the interface", || {
        let s = a.try_ok(&["status"]);
        wants.iter().all(|w| s.contains(w))
    });
    let s = a.ok(&["status"]);
    for want in wants {
        assert!(s.contains(want), "missing {want:?} in:\n{s}");
    }
    wait_until("both peers listed", || {
        let p = b.try_ok(&["peers"]);
        p.contains("alpha") && p.contains("bravo (this)")
    });
    let p = b.ok(&["peers"]);
    assert!(p.starts_with("NODE"), "{p}");
    assert!(p.contains("(* = acceptor)"), "{p}");

    // Settings.
    let s = a.ok(&["config", "get"]);
    assert!(s.contains("approvals_required = 0"), "{s}");
    assert!(s.contains("ipv4_range = 100.64.50.0/24"), "{s}");
    assert_eq!(a.ok(&["config", "get", "acceptors"]).trim(), "7");
    assert!(
        a.err(&["config", "get", "colour"])
            .contains("unknown setting")
    );
    assert_eq!(
        a.ok(&["config", "set", "approvals_required", "1"]).trim(),
        "Setting changed."
    );

    // A join that needs an approval.
    let token = a.ok(&["invite"]).trim().to_string();
    let s = c.ok(&["join", &token]);
    assert!(s.starts_with("Waiting for approvals"), "{s}");
    let proposal = proposal_in(&s);
    let s = c.ok(&["status"]);
    assert!(s.contains("join waiting for approval"), "{s}");
    let cancelled = c.ok(&["leave"]);
    assert!(
        cancelled.starts_with("Pending join cancelled."),
        "{cancelled}"
    );
    assert_eq!(c.json(&["status"])["phase"], "none");
    // A retry can resume the existing remote proposal, but is a new local
    // attempt. Cancellation never restores the consumed invitation.
    assert_eq!(proposal_in(&c.ok(&["join", &token])), proposal);
    let cancelled = c.json(&["leave", "--force"]);
    assert_eq!(cancelled["outcome"], "join_cancelled");
    assert_eq!(cancelled["proposal"], proposal);
    assert_eq!(proposal_in(&c.ok(&["join", &token])), proposal);
    wait_until("the proposal reaches b", || {
        b.try_ok(&["pending"]).contains("join of charlie")
    });
    let s = b.ok(&["pending"]);
    assert!(s.contains("0/1 approvals"), "{s}");
    let s = b.ok(&["approve", &proposal]);
    assert!(s.starts_with("Approved: ") && s.contains("joined"), "{s}");
    wait_until("b applies the join", || {
        b.try_ok(&["pending"]).trim() == "No proposals waiting."
    });
    wait_until("c becomes a member", || {
        c.try_ok(&["status"]).contains("(3 members)")
    });

    // A removal, rejected.
    let s = a.ok(&["remove", "charlie"]);
    assert!(s.contains("is waiting for approvals"), "{s}");
    let proposal = proposal_in(&s);
    wait_until("the removal reaches b", || {
        b.try_ok(&["pending"]).contains("removal of charlie")
    });
    assert_eq!(
        b.ok(&["reject", &proposal]).trim(),
        format!("Rejected proposal {proposal}.")
    );
    assert!(
        b.err(&["approve", &"ff".repeat(32)])
            .contains("no such proposal")
    );

    // A setting change waits for approval too.
    let s = a.ok(&["config", "set", "acceptors", "1"]);
    let proposal = proposal_in(&s);
    wait_until("the setting reaches b", || {
        b.try_ok(&["pending"]).contains("setting")
    });
    b.ok(&["reject", &proposal]);

    // JSON output.
    let v = a.json(&["status"]);
    assert_eq!(v["phase"], "member");
    assert_eq!(v["members"], 3);
    assert!(a.json(&["peers"]).as_array().unwrap().len() == 3);

    // Leaving never needs approvals.
    assert_eq!(c.ok(&["leave"]).trim(), "Left the cluster.");
    assert!(c.ok(&["status"]).contains("cluster   none"));

    for d in [a, b, c] {
        d.stop();
    }
}

#[test]
fn the_cli_reports_errors() {
    let dir = tempfile::tempdir().unwrap();
    let out = cli_in(dir.path(), &["status"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("error: "));

    let out = Command::new(BIN).arg("--help").output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("Usage"));
    let out = Command::new(BIN)
        .args(["daemon", "--relay", "sometimes"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("expected auto, always or never"));
    let out = Command::new(BIN)
        .args(["daemon", "--log", "cheesecloth=loud"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .starts_with("error: invalid --log filter \"cheesecloth=loud\"")
    );

    let d = Daemon::start("solo", "auto");
    assert!(d.err(&["join", "cc1garbage"]).contains("invite token"));
    assert!(d.err(&["remove", "nobody"]).contains("not in a cluster"));
    // A daemon on a state directory that's in use fails to start.
    let out = Command::new(BIN)
        .arg("--state-dir")
        .arg(d.dir.path())
        .args(["daemon", "--wireguard", "mock", "--no-port-mapping"])
        .args(["--bind", "127.0.0.1", "--listen-port"])
        .arg(free_port().to_string())
        .output()
        .unwrap();
    assert!(!out.status.success());
    d.stop();
}

#[test]
fn the_cli_stops_the_daemon_which_stays_in_its_cluster() {
    let d = Daemon::start("delta", "never");
    d.ok(&["init", "--ipv4-range", "100.64.60.0/24"]);
    let dir = d.stop_with_cli();
    assert!(
        cli_in(dir.path(), &["stop"])
            .stderr
            .starts_with(b"error: can't reach the cheesecloth daemon")
    );

    // A new daemon on the same state directory is still a member.
    let d = Daemon::start_in(dir, "delta", "never");
    let s = d.json(&["status"]);
    assert_eq!(s["phase"], "member", "{s}");
    assert_eq!(s["ipv4"], "100.64.60.1", "{s}");
    assert_eq!(d.json(&["stop"]), serde_json::Value::Null);
    let mut d = d;
    d.wait_for_exit();
}

/// Logs that don't go to a terminal, such as the journal, have no colors.
#[test]
fn logs_to_a_pipe_have_no_colors() {
    let dir = tempfile::tempdir().unwrap();
    let child = Command::new(BIN)
        .arg("--state-dir")
        .arg(dir.path())
        .args(["daemon", "--wireguard", "mock", "--no-port-mapping"])
        .args(["--bind", "127.0.0.1", "--interface", "mock-logs"])
        .args(["--listen-port", &free_port().to_string()])
        .args(["--wg-port", &free_port().to_string()])
        .args(["--log", "cheesecloth_daemon=info"])
        .env_remove("CHEESECLOTH_SOCKET")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    wait_until("the local API", || {
        cli_in(dir.path(), &["status"]).status.success()
    });
    assert!(cli_in(dir.path(), &["stop"]).status.success());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let logs = String::from_utf8(out.stdout).unwrap();
    assert!(logs.contains("cheesecloth daemon starting"), "{logs}");
    assert!(!logs.contains('\x1b'), "{logs:?}");
}
