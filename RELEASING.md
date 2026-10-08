# Releasing

1. Set the version in `Cargo.toml` (`[workspace.package]`), then run
   `cargo check` to update `Cargo.lock`.
2. In `CHANGELOG.md`, add `## [X.Y.Z] - YYYY-MM-DD` below `## [Unreleased]`.
3. In `debian/changelog`, add an entry for `X.Y.Z` at the top. The Debian
   package takes its version from there.
4. Check:
   ```sh
   cargo fmt --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   cargo deny check
   ```
5. Commit as `vX.Y.Z`, and push `main`.
6. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.

The tag starts `.github/workflows/packages.yml`. It checks that the tag
matches the version, builds the macOS, Debian and Arch packages, and makes the
GitHub release. A tag with a suffix (`vX.Y.Zpre0`, `vX.Y.Z-rc1`) makes a
pre-release.

The Arch and macOS packages read the version from `Cargo.toml`; they need no
change.
