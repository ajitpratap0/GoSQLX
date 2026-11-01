#!/usr/bin/env bash
# profile.sh - CPU profiles of the parse gap queries, the input for the amd64
# profiling task (PLAN W0-14). The perf-gate workflow runs it in "profile"
# mode on a chosen revision; `task bench:profile` runs it locally.
#
# For each query it records a pprof CPU profile of BenchmarkParseE2E/<q> in
# three configurations, and a `go tool pprof -top` listing of each:
#   cpu1   GOMAXPROCS=1, default GC (pinned with taskset when available)
#   gcoff  GOMAXPROCS=1, GOGC=off with GOMEMLIMIT (the perf gate's primary
#          metric; the limit, default 64MiB from scripts/perf/lib.sh, keeps
#          first-touch page faults out of the profile)
#   cpu4   GOMAXPROCS=4, default GC (the competitor-harness CI shape)
# When `perf stat` works it also counts cycles, instructions, branch and
# front-end/i-cache events over cmd/perfdriver -case e2e/<q> (events the
# machine lacks show as <not supported>). Hosted runners have no hardware
# counters, so when valgrind is installed it also simulates the caches with
# cachegrind over cmd/perfdriver -case e2e/<q>: a 32 KiB 8-way L1i (the L1i of
# Zen 3, Zen 4 and Zen 5), a 32 KiB 8-way L1d and a 32 MiB 16-way LL, the same
# geometry on every runner, so its per-operation counts compare across jobs.
# Two iteration counts are run and differenced, so start-up cancels out.
#
# Usage: scripts/perf/profile.sh [-o DIR] [-t BENCHTIME] [-q "join aggregate complex insert"]
# Run it from a checkout of the revision to profile. Output: DIR/{env.txt,
# *.pprof, top-*.txt, perfstat-*.txt, cachegrind-*.out, cg-top-*.txt,
# gosqlx.test, perfdriver, summary.md}. env.txt and summary.md name the CPU
# model: absolute timings hold for that CPU only.
# Environment: PERF_GOMEMLIMIT (GOMEMLIMIT of the GOGC=off runs; "off" unsets it),
# CG_ITERS ("N1 N2", perfdriver iterations of the two cachegrind runs, default "200 2200").
set -euo pipefail

# shellcheck source=scripts/perf/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
gcoff_env=()
while IFS= read -r kv; do gcoff_env+=("$kv"); done < <(perf_gcoff_env)
cpu_model=$(perf_cpu_model)

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
cg_ok=0
if command -v valgrind >/dev/null 2>&1 && valgrind --tool=cachegrind --help >/dev/null 2>&1; then
	cg_ok=1
fi
read -r cg_n1 cg_n2 <<<"${CG_ITERS:-200 2200}"
case "$cg_n1:$cg_n2" in *[!0-9:]* | :* | *:) echo "profile.sh: CG_ITERS must be two integers, got '${CG_ITERS:-}'" >&2; exit 2 ;; esac
[ "$cg_n2" -gt "$cg_n1" ] || { echo "profile.sh: CG_ITERS: N2 must exceed N1" >&2; exit 2; }
cg_sim=(--cache-sim=yes --I1=32768,8,64 --D1=32768,8,64 --LL=33554432,16,64)

{
	echo "date:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "revision:    $(git -C "$root" rev-parse HEAD)"
	echo "cpu model:   $cpu_model"
	echo "go:          $(go version)"
	echo "gcoff env:   ${gcoff_env[*]}"
	echo "kernel:      $(uname -srm)"
	echo "clocksource: $(cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null || echo n/a)"
	echo "perf stat:   $([ $perf_ok -eq 1 ] && echo available || echo unavailable)"
	echo "cachegrind:  $([ $cg_ok -eq 1 ] && echo "$(valgrind --version) ${cg_sim[*]}, $cg_n1 and $cg_n2 iterations" || echo unavailable)"
	if command -v lscpu >/dev/null 2>&1; then echo; lscpu; fi
} >"$out/env.txt"

{
	echo "## Parse profiles of the gap queries"
	echo
	echo "Revision \`$(git -C "$root" rev-parse --short=12 HEAD)\`, benchtime $benchtime, GOGC=off runs with \`${gcoff_env[*]}\`. Profiles, the test binary, \`perf stat\` and cachegrind output are in the artifact."
	echo
	echo "Runner CPU: \`$cpu_model\`. Absolute ns/op and profile shares hold for this CPU only; compare runs by ratio or by in-job A/B, never by absolute time across jobs."
	echo
} >"$out/summary.md"

for q in $queries; do
	for cfg in cpu1 gcoff cpu4; do
		case $cfg in
			cpu1) envs=(-u GOGC -u GOMEMLIMIT GOMAXPROCS=1) cpu=1 p=(${pin[@]+"${pin[@]}"}) ;;
			gcoff) envs=("${gcoff_env[@]}" GOMAXPROCS=1) cpu=1 p=(${pin[@]+"${pin[@]}"}) ;;
			cpu4) envs=(-u GOGC -u GOMEMLIMIT GOMAXPROCS=4) cpu=4 p=() ;;
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
			-- env "${gcoff_env[@]}" GOMAXPROCS=1 GODEBUG=asyncpreemptoff=1 ${pin[@]+"${pin[@]}"} \
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

# cachegrind_run q n: one simulated run of perfdriver; prints its counts.
cachegrind_run() {
	local q=$1 n=$2 log=$out/cachegrind-$q-$n.log
	(cd "$root" && env "${gcoff_env[@]}" GOMAXPROCS=1 GODEBUG=asyncpreemptoff=1 \
		valgrind --tool=cachegrind "${cg_sim[@]}" --cachegrind-out-file="$out/cachegrind-$q-$n.out" \
		"$out/perfdriver" -case "e2e/$q" -n "$n") >/dev/null 2>"$log" || return 1
	perf_cachegrind_counts "$log"
}

if [ $cg_ok -eq 1 ]; then
	{
		echo "### Simulated caches (cachegrind, per operation)"
		echo
		echo "cmd/perfdriver -case e2e/<q>, ${gcoff_env[*]} GOMAXPROCS=1, \`${cg_sim[*]}\`; counts are (run of $cg_n2 - run of $cg_n1) / $((cg_n2 - cg_n1)) operations. Simulated, so they do not depend on the runner CPU."
		echo
		echo "| query | Ir/op | I1 misses/op | I1 miss % | LLi misses/op | D1 misses/op | LLd misses/op |"
		echo "|---|---:|---:|---:|---:|---:|---:|"
	} >>"$out/summary.md"
	for q in $queries; do
		echo "profile.sh: $q cachegrind" >&2
		if ! c1=$(cachegrind_run "$q" "$cg_n1") || ! c2=$(cachegrind_run "$q" "$cg_n2"); then
			echo "| $q | cachegrind failed (see cachegrind-$q-*.log) | | | | | |" >>"$out/summary.md"
			continue
		fi
		awk -v q="$q" -v d=$((cg_n2 - cg_n1)) -v a="$c1" -v b="$c2" 'BEGIN {
			split(a, x, " "); split(b, y, " ")
			for (i = 1; i <= 6; i++) v[i] = (y[i] - x[i]) / d
			rate = v[1] > 0 ? 100 * v[2] / v[1] : 0
			printf "| %s | %.0f | %.2f | %.4f | %.2f | %.2f | %.2f |\n", q, v[1], v[2], rate, v[3], v[5], v[6]
		}' >>"$out/summary.md"
		# Hottest functions by simulated L1i misses (best effort: cg_annotate's
		# options differ between valgrind releases).
		cg_annotate --show=Ir,I1mr,ILmr --sort=I1mr "$out/cachegrind-$q-$cg_n2.out" >"$out/cg-top-$q.txt" 2>&1 ||
			cg_annotate "$out/cachegrind-$q-$cg_n2.out" >"$out/cg-top-$q.txt" 2>&1 || true
	done
	echo >>"$out/summary.md"
else
	echo "valgrind is not installed, so there is no simulated cache data." >>"$out/summary.md"
fi
cat "$out/summary.md"
