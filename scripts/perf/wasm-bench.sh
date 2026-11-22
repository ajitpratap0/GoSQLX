#!/usr/bin/env bash
# Run the wasm bridge benchmarks in the real GOOS=js GOARCH=wasm engine under
# Node, using the runner that ships with the Go toolchain. Needs `node`.
#
# Usage: scripts/perf/wasm-bench.sh [bench-regexp] [benchtime] [count]
#   defaults: 'WASMBridge/parse', 1s, count 1
#
# Timing: the default is time-based (1s). A fixed small iteration count such
# as 10x mostly measures wasm tier-up and load noise, so use `10x` only as a
# smoke mode (does it run?), never for comparisons. Pass a count (e.g. 10) and
# feed the output to benchstat for A/B work.
#
# Node pin: NODE_REQUIRED_MAJOR (default 24) is the Node major these numbers are
# attributed to. A mismatch fails unless NODE_ALLOW_MISMATCH=1 (then it warns).
# The node and go versions are printed before the run so results can be
# attributed.
set -euo pipefail

pattern="${1:-WASMBridge/parse}"
benchtime="${2:-1s}"
count="${3:-1}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

command -v node >/dev/null || { echo "node is required for the wasm benchmark" >&2; exit 1; }

required_major="${NODE_REQUIRED_MAJOR:-24}"
node_version="$(node --version)"
node_major="${node_version#v}"
node_major="${node_major%%.*}"
echo "# node $node_version (required major $required_major)"
echo "# $(go version)"
if [ "$node_major" != "$required_major" ]; then
  msg="node major $node_major != required $required_major (set NODE_REQUIRED_MAJOR to the major you intend, or NODE_ALLOW_MISMATCH=1)"
  if [ "${NODE_ALLOW_MISMATCH:-0}" = 1 ]; then
    echo "warning: $msg" >&2
  else
    echo "error: $msg" >&2
    exit 1
  fi
fi

runner="$(go env GOROOT)/lib/wasm/go_js_wasm_exec"
[ -x "$runner" ] || runner="$(go env GOROOT)/misc/wasm/go_js_wasm_exec"

GOOS=js GOARCH=wasm go test -exec "$runner" -run '^$' \
  -bench "$pattern" -benchtime="$benchtime" -count="$count" ./wasm/internal/bridge/
