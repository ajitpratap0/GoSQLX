#!/usr/bin/env bash
# Builds the playground WASM (public/wasm/gosqlx.wasm + wasm_exec.js) from the
# Go sources in this repository, so every website build ships the current parser.
#
# Runs as part of `npm run build` (prebuild). On Vercel, whose build image has no
# Go toolchain, a pinned and checksum-verified Go release is downloaded into the
# build cache. Elsewhere the local `go` is used.
#
# Flags:
#   --if-missing  only build when public/wasm/gosqlx.wasm does not exist (predev)
set -euo pipefail

# Pinned toolchain for builds without Go (Vercel). Keep in step with CI's Go 1.26.x.
GO_VERSION="1.26.9"
GO_SHA256="42d158b4d8f7b61ac0a830567c940a86098fb7aac52e467a5ebec03ef5cc2f8d" # linux-amd64

WEBSITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$WEBSITE_DIR/.." && pwd)"
OUT_DIR="$WEBSITE_DIR/public/wasm"

if [[ ${1:-} == "--if-missing" && -f "$OUT_DIR/gosqlx.wasm" ]]; then
  exit 0
fi

if ! command -v go >/dev/null 2>&1; then
  if [[ -z ${VERCEL:-} ]]; then
    echo "build-wasm: Go is not installed; skipping WASM build (the playground will not load)." >&2
    echo "build-wasm: install Go ${GO_VERSION%.*}+ to build it locally." >&2
    exit 0
  fi
  # node_modules/.cache is restored between Vercel builds, so the toolchain and
  # Go build caches are reused instead of downloaded and rebuilt every time.
  CACHE_DIR="$WEBSITE_DIR/node_modules/.cache/gosqlx-go"
  GOROOT_DIR="$CACHE_DIR/go$GO_VERSION"
  if [[ ! -x "$GOROOT_DIR/bin/go" ]]; then
    echo "build-wasm: downloading Go $GO_VERSION"
    mkdir -p "$CACHE_DIR"
    tarball="$CACHE_DIR/go$GO_VERSION.tar.gz"
    curl -fsSL --retry 3 -o "$tarball" "https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz"
    echo "$GO_SHA256  $tarball" | sha256sum -c --quiet -
    rm -rf "$GOROOT_DIR" "$CACHE_DIR/go"
    tar -xzf "$tarball" -C "$CACHE_DIR"
    mv "$CACHE_DIR/go" "$GOROOT_DIR"
    rm -f "$tarball"
  fi
  export PATH="$GOROOT_DIR/bin:$PATH"
  export GOCACHE="$CACHE_DIR/build" GOMODCACHE="$CACHE_DIR/mod"
  export GOTOOLCHAIN=local
fi

echo "build-wasm: building with $(go version)"
mkdir -p "$OUT_DIR"
(cd "$REPO_ROOT" && GOOS=js GOARCH=wasm go build -trimpath -o "$OUT_DIR/gosqlx.wasm" ./wasm/)

# wasm_exec.js must come from the same toolchain that compiled the binary.
goroot="$(go env GOROOT)"
rm -f "$OUT_DIR/wasm_exec.js"
for candidate in "$goroot/lib/wasm/wasm_exec.js" "$goroot/misc/wasm/wasm_exec.js"; do
  if [[ -f $candidate ]]; then
    cp "$candidate" "$OUT_DIR/wasm_exec.js"
    break
  fi
done
[[ -f "$OUT_DIR/wasm_exec.js" ]] || { echo "build-wasm: wasm_exec.js not found in $goroot" >&2; exit 1; }

echo "build-wasm: wrote $OUT_DIR/gosqlx.wasm ($(wc -c <"$OUT_DIR/gosqlx.wasm" | tr -d ' ') bytes)"

# Precompute the homepage demo's sample AST with the same parser (see MiniPlayground).
(cd "$REPO_ROOT" && go run ./website/scripts/gen-sample-ast \
  website/src/components/home/sample.sql website/src/generated/sample-ast.json)
echo "build-wasm: regenerated src/generated/sample-ast.json"
