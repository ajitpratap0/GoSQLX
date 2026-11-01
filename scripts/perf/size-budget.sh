#!/usr/bin/env bash
# Report the size of the three shipped binaries: the playground WASM, the
# C-shared library behind the Python wheel, and the CLI.
#
# Usage: scripts/perf/size-budget.sh [--json] [--check]
#   --json   print one JSON object instead of a table
#   --check  exit 1 when a size exceeds its budget (env WASM_MAX_BYTES,
#            DYLIB_MAX_BYTES, CLI_MAX_BYTES; a budget that is unset is skipped)
# Binaries are built into a temp dir and removed on exit. Sizes are bytes of the
# default `go build` output, plus the gzip size of the WASM (what a CDN without
# brotli ships).
set -euo pipefail

json=0
check=0
for arg in "$@"; do
  case "$arg" in
    --json) json=1 ;;
    --check) check=1 ;;
    -h | --help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

size_of() { wc -c <"$1" | tr -d ' '; }

GOOS=js GOARCH=wasm go build -o "$tmp/gosqlx.wasm" ./wasm/
wasm_bytes="$(size_of "$tmp/gosqlx.wasm")"
wasm_gzip_bytes="$(gzip -9 -c "$tmp/gosqlx.wasm" | wc -c | tr -d ' ')"

CGO_ENABLED=1 go build -buildmode=c-shared -o "$tmp/libgosqlx.so" ./pkg/cbinding/
dylib_bytes="$(size_of "$tmp/libgosqlx.so")"

go build -o "$tmp/gosqlx" ./cmd/gosqlx
cli_bytes="$(size_of "$tmp/gosqlx")"

if [ "$json" -eq 1 ]; then
  printf '{"wasm_bytes":%s,"wasm_gzip_bytes":%s,"dylib_bytes":%s,"cli_bytes":%s}\n' \
    "$wasm_bytes" "$wasm_gzip_bytes" "$dylib_bytes" "$cli_bytes"
else
  printf '%-14s %12s\n' artifact bytes
  printf '%-14s %12s\n' wasm "$wasm_bytes"
  printf '%-14s %12s\n' wasm-gzip "$wasm_gzip_bytes"
  printf '%-14s %12s\n' c-shared "$dylib_bytes"
  printf '%-14s %12s\n' cli "$cli_bytes"
fi

if [ "$check" -eq 1 ]; then
  rc=0
  over() { # name actual max
    if [ -n "$3" ] && [ "$2" -gt "$3" ]; then
      echo "over budget: $1 is $2 bytes, budget $3" >&2
      rc=1
    fi
  }
  over wasm "$wasm_bytes" "${WASM_MAX_BYTES:-}"
  over c-shared "$dylib_bytes" "${DYLIB_MAX_BYTES:-}"
  over cli "$cli_bytes" "${CLI_MAX_BYTES:-}"
  exit "$rc"
fi
