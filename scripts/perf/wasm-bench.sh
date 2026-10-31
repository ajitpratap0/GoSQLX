#!/usr/bin/env bash
# Run the wasm bridge benchmarks in the real GOOS=js GOARCH=wasm engine under
# Node, using the runner that ships with the Go toolchain. Needs `node`.
#
# Usage: scripts/perf/wasm-bench.sh [bench-regexp] [benchtime]
#   defaults: 'WASMBridge/parse' and 10x
set -euo pipefail

pattern="${1:-WASMBridge/parse}"
benchtime="${2:-10x}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

command -v node >/dev/null || { echo "node is required for the wasm benchmark" >&2; exit 1; }
runner="$(go env GOROOT)/lib/wasm/go_js_wasm_exec"
[ -x "$runner" ] || runner="$(go env GOROOT)/misc/wasm/go_js_wasm_exec"

GOOS=js GOARCH=wasm go test -exec "$runner" -run '^$' \
  -bench "$pattern" -benchtime="$benchtime" ./wasm/internal/bridge/
