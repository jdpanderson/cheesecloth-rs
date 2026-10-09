# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-10-09

### Changed

- Building needs Rust 1.95 or later, which GotaTun requires.
- WireGuard no longer uses the defguard libraries. Kernel WireGuard on Linux
  is configured over netlink directly. Userspace WireGuard is
  [GotaTun](https://github.com/mullvad/gotatun) running inside the daemon on
  every OS, so no `wireguard-go`, `boringtun` or `wg` program is needed.
- Userspace WireGuard changes a peer in place. It no longer removes and adds
  the peer, which reset its session.
- On FreeBSD the daemon uses userspace WireGuard; it no longer drives the
  kernel's `if_wg`.
- When an earlier run left a kernel WireGuard interface with the configured
  name, the daemon replaces it in place of reusing it. It refuses to touch
  an interface with that name that is not WireGuard.

### Added

- Windows userspace WireGuard, on a Wintun adapter. `wintun.dll` must be in
  the same directory as the executable.
- The packages include `THIRD-PARTY-NOTICES.md`: the licenses of the crates
  built into the binary, and where to get their source code. GotaTun is under
  MPL-2.0, and its older code under BoringTun's BSD-3-Clause license.

## [0.2.1] - 2026-10-08

### Fixed

- A node could fail to learn an agreed state with "this node's acceptor
  ignored the agreed state". This happened when an earlier attempt to learn
  the same state was stopped after it was saved, for example by a timeout
  during a slow disk sync. The node now takes in the saved state.

## [0.2.0] - 2026-10-08

### Changed

- The CASPaxos engine moved out of this repository, to the
  [pnyx](https://crates.io/crates/pnyx) crate.
- The acceptor state is now kept in two files with a checksum,
  `acceptor.0` and `acceptor.1`, in place of `acceptor.bin`. The daemon moves
  an existing `acceptor.bin` to the new files when it starts.
- An older version can't read the new files: after a downgrade, it reports
  that there is no cluster state. Putting back an old copy of `acceptor.bin`
  is not safe, because the acceptor would forget promises it made since. To
  downgrade a node, have it leave the cluster first, and join again after.
- If an agreed state can't be saved by this node's acceptor, learning it now
  fails, so the node never reports a state that isn't on disk.

### Fixed

- When a change can't be agreed, the error now gives the cause of each
  failed request to an acceptor, not only its outer message.
- Requests that arrived while the daemon was starting were refused with
  "not ready". The control plane now accepts connections only once it can
  answer them.
- The Debian package has the right version. The 0.1.0 package was labelled
  0.0.0.

## [0.1.0] - 2026-10-07

Initial Release

### Added

- First release: a peer-to-peer WireGuard mesh with membership agreed through
  authenticated CASPaxos, relays for control messages, and packages for
  macOS, Debian 13 and Arch Linux.
