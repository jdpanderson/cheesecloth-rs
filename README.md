# Cheesecloth

Cheesecloth builds a peer-to-peer WireGuard mesh without a central server.
Members agree on membership and settings through an authenticated, adaptive
CASPaxos protocol. Relays help control messages cross NAT; WireGuard traffic
always travels directly between peers.

**Pre-release.** Linux has end-to-end coverage with kernel WireGuard. macOS
CI tests userspace WireGuard; multi-machine and NAT operation remain unvalidated.
FreeBSD is unvalidated; Windows and mobile support are incomplete. The consensus
security layer has regression tests, but no independent audit or machine-checked
Byzantine proof.

## Quick start on Linux

Use Rust and Cargo 1.91 or later, synchronized clocks, and either running
`systemd-resolved` or a `resolvconf` implementation for interface cleanup.
The daemon needs root, or `CAP_NET_ADMIN` and `CAP_NET_RAW` with suitable file
permissions. These examples use root for the daemon and its private API socket.

Build and install from the repository root:

```sh
cargo build --release --locked
sudo install -m 755 target/release/cheesecloth /usr/local/bin/cheesecloth
```

Start the daemon on each machine and leave it running:

```sh
sudo cheesecloth daemon
```

In another terminal on the first machine:

```sh
sudo cheesecloth init
sudo cheesecloth invite
```

On the next machine, join using the token printed by `invite`:

```sh
sudo cheesecloth join '<token>'
sudo cheesecloth status
sudo cheesecloth peers
```

Invites are single-use and expire after 30 minutes. Create one for each join.
A committed redemption consumes the token even if admission fails.

Defaults are UDP **51821** for control, UDP **51820** for WireGuard, and
`/var/lib/cheesecloth` for state on Linux. Allow both ports where direct
inbound access is intended. Keep the WireGuard interface dedicated to
Cheesecloth; manually added peers are removed.

## Membership and settings

```sh
sudo cheesecloth remove '<name-or-node-id-prefix>'
sudo cheesecloth leave
sudo cheesecloth config get
sudo cheesecloth config set approvals_required 1
sudo cheesecloth pending
sudo cheesecloth approve '<proposal-token>'
sudo cheesecloth reject '<proposal-token>'
```

By default, any member can invite or remove another member and change settings.
`approvals_required` adds approvals from other members for joins, removals and
setting changes. Use the complete proposal token shown by `pending`; check the
joining identity before approving. Leaving never needs approvals.

`leave` also cancels a pending join locally, even while offline. It does not
withdraw the remote proposal or restore the invite. A member may still need
to reject that proposal or remove the admitted identity.

If local cleanup fails, status shows `stopping`; fix the reported problem and
retry `leave`. `leave --force` continues past cluster handoff failures, but
cannot bypass unfinished local cleanup. See [lifecycle and recovery](docs/DESIGN.md#lifecycle-and-recovery).

## Security and availability

With default settings, three voters require two votes and have **no Byzantine
safety guarantee**. Four require three votes and activate protection intended
to tolerate one compromised voter. The installed quorum must approve every
voter change: four voters suddenly reduced to two pause changes. Existing
WireGuard paths continue using the last learned membership.

- `init --strict-security` allows bootstrap, then prevents automatic loss of
  protection. It can also be enabled with `config set strict_security true`.
- `buffer_nodes` reserves unavailable votes. With buffer two, five voters use
  three votes in relaxed mode; six use four in protected mode. All voters vote.
- `status` shows the installed mode, quorum, reachable voters and warnings.

Read [consensus safety](docs/CONSENSUS-SAFETY.md) for assumptions, transitions and
limits. Consensus protection does not restrict actions allowed by the approval
policy, and later protection cannot repair a fork created in relaxed mode.

## Network options

Use `cheesecloth daemon --help` for all options. The usual adjustments are:

| Option | Purpose |
| --- | --- |
| `--advertise IP` | Advertise a reachable address, such as a cloud VM's public IP. Repeatable. |
| `--relay MODE` | `auto` (default) checks reachability; `always` forces relaying; `never` disables it. |
| `--no-port-mapping` | Disable automatic PCP, NAT-PMP and UPnP router mappings. |
| `--wireguard MODE` | Select `auto` (default), `kernel` or `userspace`. |
| `--keepalive SECONDS` | Set WireGuard keepalive; QUIC keepalive remains 25 seconds. |

Without a relay, separate NATs may prevent control-plane communication. If
WireGuard punching and port mapping fail, there is no data relay fallback;
provide a reachable endpoint or port forward. NAT openers and automatic port
mapping currently support IPv4 only.

Each daemon serves one cluster. Separate instances need distinct state
directories, interfaces, control ports and WireGuard ports. Use the same
`--state-dir` or `--socket` when calling that instance's CLI.

## Packages

The **Packages** GitHub Actions workflow builds on pushes to `main`, `v*` tags,
pull requests, and manual runs. Download packages from the run's **Artifacts**:

| Platform | Package |
| --- | --- |
| macOS 14+, Apple Silicon or Intel | `.pkg` installer for each architecture |
| Debian 13, amd64 | `.deb`, plus debugging symbols |
| Arch Linux, x86-64 | `.pkg.tar.zst` |

macOS installers are unsigned and not notarized. They install the command in
`/usr/local/bin`; start it with `sudo cheesecloth daemon`. Linux packages include
the systemd service described below. CI runs the workspace tests before packaging.
Both macOS builds also require real userspace WireGuard tests to pass.

To build a macOS installer locally, use `cargo build --release --locked` followed
by `bash packaging/macos/build.sh`. The script uses your installed Cargo.

As an alternative to manual installation, build from the repository checkout:

```sh
# Arch; run from the repository root
(cd packaging/arch && makepkg -si)

# Debian; run from the repository root with its build dependencies installed
dpkg-buildpackage -us -uc -b
sudo apt install ../cheesecloth_*.deb
```

Package builds fetch dependencies from crates.io. Arch builds the committed
Git checkout. Debian CI uses Debian 13's backported Rust toolchain. Both Linux
packages install a systemd service; start it with
`sudo systemctl enable --now cheesecloth` instead of running a second daemon.
Set daemon options in `/etc/default/cheesecloth` and restart the service.

## Development

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
tests/e2e/run.sh
```

The end-to-end lab needs Podman with Linux kernel WireGuard and container
network privileges. It covers direct paths, NAT, port mapping, restart and
removal. `FIREWALL=0` tests routers without inbound filtering; `SKIP_BUILD=1`
reuses the image; `KEEP=1` keeps the lab for inspection.

On a disposable Mac, run the privileged userspace test with:

```sh
cargo test --release --locked -p cheesecloth-wg \
  --features macos-integration --test macos_userspace \
  --config 'target."cfg(target_os = \"macos\")".runner = ["sudo", "-n"]' \
  -- --nocapture
```

This requires passwordless sudo; only the test executable runs as root. It
creates a temporary `utun` interface and routes in reserved test address ranges.
It checks encrypted IPv4/IPv6 traffic, peer removal, NAT openers, cleanup and
recreation, and verifies that DNS settings stay unchanged. No remote host or
separate WireGuard installation is needed.

See [the design](docs/DESIGN.md) for architecture, settings and recovery, and
[consensus validation limits](docs/CONSENSUS-SAFETY.md#validation-and-limits) for
what the model checks establish.
