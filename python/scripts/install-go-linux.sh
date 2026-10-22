#!/usr/bin/env bash
# Install a pinned Go toolchain inside a cibuildwheel manylinux container.
#
# Used as CIBW_BEFORE_ALL_LINUX by .github/workflows/pygosqlx-release.yml.
# The tarball is downloaded from go.dev and verified against the SHA-256
# pinned below before it is extracted. To bump Go, update GO_VERSION and both
# checksums from https://go.dev/dl/?mode=json (the "sha256" of the
# linux-amd64 and linux-arm64 "archive" files).
set -euo pipefail

GO_VERSION="1.26.10"
GO_SHA256_AMD64="ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5"
GO_SHA256_ARM64="3f4227ce7b206a513e794f1393adb473a07b46e94d18bd15d1c684bbb7319797"

case "$(uname -m)" in
  x86_64) arch=amd64; sha="$GO_SHA256_AMD64" ;;
  aarch64 | arm64) arch=arm64; sha="$GO_SHA256_ARM64" ;;
  *) echo "install-go-linux.sh: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

tarball="go${GO_VERSION}.linux-${arch}.tar.gz"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

curl -fsSL --retry 3 --proto '=https' --tlsv1.2 \
  -o "$workdir/$tarball" "https://go.dev/dl/$tarball"
echo "$sha  $workdir/$tarball" | sha256sum -c -

rm -rf /usr/local/go
tar -C /usr/local -xzf "$workdir/$tarball"
/usr/local/go/bin/go version
