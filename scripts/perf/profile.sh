#!/usr/bin/env bash
# profile.sh - CPU profiles of the parse gap queries, the input for the amd64
# profiling task (PLAN W0-14). The perf-gate workflow runs it in "profile"
# mode on a chosen revision; `task bench:profile` runs it locally.
#
# For each query it records a pprof CPU profile of BenchmarkParseE2E/<q> in
# three configurations, and a `go tool pprof -top` listing of each:
#   cpu1   GOMAXPROCS=1, default GC (pinned with taskset when available)
#   gcoff  GOMAXPROCS=1, GOGC=off (the perf gate's primary metric)
#   cpu4   GOMAXPROCS=4, default GC (the competitor-harness CI shape)
# When `perf stat` works it also counts cycles, instructions, branch and
# front-end/i-cache events over cmd/perfdriver -case e2e/<q> (events the
# machine lacks show as <not supported>).
#
# Usage: scripts/perf/profile.sh [-o DIR] [-t BENCHTIME] [-q "join aggregate complex insert"]
# Run it from a checkout of the revision to profile. Output: DIR/{env.txt,
# *.pprof, top-*.txt, perfstat-*.txt, gosqlx.test, perfdriver, summary.md}.
set -euo pipefail
exec "$(dirname "$0")/w014b.sh" "$@"

out="" benchtime=3s queries="join aggregate complex insert"
while getopts ":o:t:q:h" opt; do
	case $opt in
		o) out=$OPTARG ;;
		t) benchtime=$OPTARG ;;
		q) queries=$OPTARG ;;
		h) sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; exit 0 ;;
		*) echo "profile.sh: bad option (see -h)" >&2; exit 2 ;;
	esac
done
root=$(git rev-parse --show-toplevel)
out=${out:-$(mktemp -d "${TMPDIR:-/tmp}/gosqlx-profile.XXXXXX")}
mkdir -p "$out"
out=$(cd "$out" && pwd)
echo "profile.sh: output in $out" >&2

export CGO_ENABLED=0
(cd "$root" && go test -c -o "$out/gosqlx.test" ./pkg/gosqlx)
(cd "$root" && go build -o "$out/perfdriver" ./cmd/perfdriver)

pin=()
if command -v taskset >/dev/null 2>&1; then pin=(taskset -c "$(($(getconf _NPROCESSORS_ONLN) - 1))"); fi
perf_ok=0
if command -v perf >/dev/null 2>&1 && perf stat -x, -e instructions:u -- true 2>&1 | grep -Eq '^[0-9]+,'; then
	perf_ok=1
fi

{
	echo "date:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "revision:    $(git -C "$root" rev-parse HEAD)"
	echo "go:          $(go version)"
	echo "kernel:      $(uname -srm)"
	echo "clocksource: $(cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null || echo n/a)"
	echo "perf stat:   $([ $perf_ok -eq 1 ] && echo available || echo unavailable)"
	if command -v lscpu >/dev/null 2>&1; then echo; lscpu; fi
} >"$out/env.txt"

{
	echo "## Parse profiles of the gap queries"
	echo
	echo "Revision \`$(git -C "$root" rev-parse --short=12 HEAD)\`, benchtime $benchtime. Profiles, the test binary and \`perf stat\` output are in the artifact."
	echo
} >"$out/summary.md"

for q in $queries; do
	for cfg in cpu1 gcoff cpu4; do
		case $cfg in
			cpu1) envs=(-u GOGC GOMAXPROCS=1) cpu=1 p=(${pin[@]+"${pin[@]}"}) ;;
			gcoff) envs=(GOGC=off GOMAXPROCS=1) cpu=1 p=(${pin[@]+"${pin[@]}"}) ;;
			cpu4) envs=(-u GOGC GOMAXPROCS=4) cpu=4 p=() ;;
		esac
		echo "profile.sh: $q $cfg" >&2
		(cd "$root/pkg/gosqlx" && env "${envs[@]}" ${p[@]+"${p[@]}"} "$out/gosqlx.test" \
			-test.run '^$' -test.bench "^BenchmarkParseE2E\$/^$q\$" -test.benchmem \
			-test.benchtime "$benchtime" -test.cpu "$cpu" \
			-test.cpuprofile "$out/cpu-$cfg-$q.pprof") >"$out/bench-$cfg-$q.txt"
		go tool pprof -top -nodecount=40 "$out/gosqlx.test" "$out/cpu-$cfg-$q.pprof" >"$out/top-$cfg-$q.txt" 2>/dev/null
	done
	if [ $perf_ok -eq 1 ]; then
		(cd "$root" && perf stat -x, -o "$out/perfstat-$q.txt" \
			-e cycles:u,instructions:u,branches:u,branch-misses:u \
			-e L1-icache-load-misses,iTLB-load-misses,stalled-cycles-frontend,L1-dcache-load-misses \
			-- env GOGC=off GOMAXPROCS=1 GODEBUG=asyncpreemptoff=1 ${pin[@]+"${pin[@]}"} \
			"$out/perfdriver" -case "e2e/$q" -n 200000) || echo "profile.sh: perf stat failed for $q" >&2
	fi
	{
		echo "<details><summary>$q: top of the -cpu 1 profile</summary>"
		echo
		echo '```'
		grep '^Benchmark' "$out/bench-cpu1-$q.txt" || true
		sed -n '1,25p' "$out/top-cpu1-$q.txt"
		echo '```'
		echo
		echo "</details>"
		echo
	} >>"$out/summary.md"
done
if [ $perf_ok -eq 0 ]; then
	echo "\`perf stat\` is not usable on this machine, so there are no hardware counters." >>"$out/summary.md"
fi
cat "$out/summary.md"
