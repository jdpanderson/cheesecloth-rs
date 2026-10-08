# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

## [0.1.0] - 2026-10-07

Initial Release

### Added

- First release: a peer-to-peer WireGuard mesh with membership agreed through
  authenticated CASPaxos, relays for control messages, and packages for
  macOS, Debian 13 and Arch Linux.
