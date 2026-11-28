#!/usr/bin/env bash
# Run one shard of the race-enabled test suite (`task test:race` split N ways).
#
# Usage: scripts/race-shard.sh SHARD SHARDS
#
# Packages are dealt round-robin with the heaviest race packages first, so no
# two of them share a shard. A single `go test -race ./...` on a 4-vCPU CI
# runner runs them side by side and starves each one; their wall time then
# swings with the runner (tokenizer 79-120s, security 65-104s on identical
# commits) and crosses the per-package -timeout. Sharding keeps the same
# packages, flags and timeout as `task test:race`; only the concurrency
# between heavy packages changes. pkg/cbinding stays excluded (CGO job).
set -euo pipefail

shard=${1:?shard index (0-based)}
shards=${2:?shard count}
if ! [[ $shard =~ ^[0-9]+$ && $shards =~ ^[1-9][0-9]*$ ]] || ((shard >= shards)); then
	echo "race-shard: need 0 <= SHARD < SHARDS, got $shard/$shards" >&2
	exit 2
fi

mod=$(go list -m)
# Heaviest first (CI race wall time, Nov 2026). Unknown packages follow in
# go list order; a heavy package missing from this list still runs.
heavy=(
	pkg/sql/tokenizer
	pkg/sql/security
	pkg/sql/parser
	pkg/transpiler
	pkg/gosqlx
	scripts/perf/gate
)

all=$(go list ./... | grep -v /cbinding)
ordered=()
for h in "${heavy[@]}"; do
	if grep -qx "$mod/$h" <<<"$all"; then
		ordered+=("$mod/$h")
	fi
done
while IFS= read -r p; do
	skip=
	for h in "${heavy[@]}"; do
		[[ $p == "$mod/$h" ]] && skip=1
	done
	[[ -z $skip ]] && ordered+=("$p")
done <<<"$all"

mine=()
for i in "${!ordered[@]}"; do
	((i % shards == shard)) && mine+=("${ordered[$i]}")
done
if ((${#mine[@]} == 0)); then
	echo "race-shard $shard/$shards: no packages"
	exit 0
fi

echo "race-shard $shard/$shards: ${#mine[@]} of ${#ordered[@]} packages"
CGO_ENABLED=1 go test -race -timeout 120s "${mine[@]}"
