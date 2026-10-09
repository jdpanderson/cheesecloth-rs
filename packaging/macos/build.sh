#!/usr/bin/env bash
# Package the native release binary. Run after cargo build --release --locked.
set -euo pipefail
cd "$(dirname "$0")/../.."

version=$(cargo metadata --no-deps --locked --format-version 1 | python3 -c '
import json, sys
print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "cheesecloth"))
')
arch=$(uname -m)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

install -d "$stage/root/usr/local/bin" "$stage/root/usr/local/share/doc/cheesecloth/docs"
install -m755 target/release/cheesecloth "$stage/root/usr/local/bin/cheesecloth"
install -m644 README.md LICENSE THIRD-PARTY-NOTICES.md "$stage/root/usr/local/share/doc/cheesecloth/"
install -m644 docs/*.md "$stage/root/usr/local/share/doc/cheesecloth/docs/"
xattr -cr "$stage/root"
strip -x "$stage/root/usr/local/bin/cheesecloth"
lipo "$stage/root/usr/local/bin/cheesecloth" -verify_arch "$arch"
"$stage/root/usr/local/bin/cheesecloth" --version

mkdir -p dist
package="dist/cheesecloth-${version}-macos-${arch}.pkg"
pkgbuild --root "$stage/root" --identifier ca.janderson.cheesecloth \
  --version "$version" --install-location / --ownership recommended "$package"

# Inspect the actual archive without installing it or starting a daemon.
pkgutil --expand-full "$package" "$stage/expanded"
binary="$stage/expanded/Payload/usr/local/bin/cheesecloth"
cmp "$stage/root/usr/local/bin/cheesecloth" "$binary"
"$binary" --version
