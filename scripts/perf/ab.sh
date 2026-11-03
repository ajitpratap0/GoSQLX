#!/usr/bin/env bash
# ab.sh - interleaved A/B benchmark of two GoSQLX revisions, judged by the perf
# gate rules (scripts/perf/gate). It is what `task bench:ab`, `task bench:gate`
# and .github/workflows/perf-gate.yml run.
#
# Method (PLAN section 2.6, CRITIQUE items 1, 3 and 4):
#   - Base and head test binaries are built from source trees of the two
#     revisions with the same toolchain, in the same job.
#   - Primary metric: GOGC=off GOMAXPROCS=1 (-test.cpu 1), pinned to one CPU
#     with taskset when it exists. GC-free mutator time is low-variance and
#     ranks queries like the -cpu 4 headline does. GOMEMLIMIT (default 64MiB,
#     see scripts/perf/lib.sh) bounds the heap so the runs reuse pages instead
#     of paying first-touch page faults.
#   - Code-layout randomization: every arm is built as K test binaries per
#     package, linked with -ldflags=-randlayout=<seed> (the linker shuffles
#     the order of all Go functions). Base and head use the same K seeds;
#     round r runs layout r mod K, so each arm's samples span K layouts.
#     Where a function lands moves its timing by a few percent (alignment,
#     branch-predictor and cache aliasing), so a change that adds no work but
#     shifts the text can look like a regression in one fixed layout; the
#     gate compares per-layout medians instead, so a regression has to hold
#     across layouts. -k 0 turns this off (one default-layout binary per arm).
#   - Arms run interleaved, one -test.count 1 pass per arm per round, in
#     ABBA order (two arms) or rotating through every permutation (three).
#   - Optional A/A' control (-a): the base revision again, interleaved, built
#     with K further seeds disjoint from the shared set, so it measures the
#     layout variance the A/B comparison is exposed to (with -k 0: a second
#     run of the base binary).
#   - Optional secondary metric (-g): default GC, GOMAXPROCS=1, one round on
#     each of the first min(K, 10) layouts (with -k 0: -r rounds). It is
#     informational, so it gets a smaller share of the time budget.
#   - Optional instruction counts (-i): cmd/perfdriver under `perf stat`,
#     else cachegrind, else macOS `/usr/bin/time -l`, at two iteration counts;
#     the difference divided by the extra iterations is instructions/op.
#   - allocs/op and B/op come from the primary runs. GOMEMLIMIT lets the
#     collector (and with it sync.Pool drains) run about once per limit's
#     worth of allocation, so allocs/op is exact for the gated suite
#     (identical in every A/A and PR run so far) but not for large-input or
#     low-N benchmarks (ParseRW/*/large, Handler_LargeDocument,
#     *SustainedLoad*); docs/PERFORMANCE_METHODOLOGY.md covers this caveat.
#   - env.txt and the report name the CPU model: hosted runners differ from
#     job to job, so only the in-job base/head ratios are reported.
#
# Usage: scripts/perf/ab.sh [options] BASE [HEAD]
#   BASE        git revision of the baseline
#   HEAD        git revision of the candidate; default: the working tree,
#               uncommitted changes included
# Options:
#   -o DIR      output directory (default: a new temporary directory)
#   -r N        interleaved rounds (default 20; at least -k)
#   -t DUR      -test.benchtime of each benchmark run (default 100ms)
#   -k K        randomized code layouts per arm (default 20; 0: no randomization)
#   -S SEED     layout seeds are SEED+1..SEED+K (base, head) and
#               SEED+K+1..SEED+2K (A/A'); default: random, recorded in env.txt
#   -s FILE     suite file (default scripts/perf/gate-suite.txt)
#   -b PKG=RE   run this package/regex instead of the suite (repeatable)
#   -a          add the A/A' control arm
#   -g          add the secondary (default GC) metric
#   -i          measure instructions/op with cmd/perfdriver
#   -G          gate mode: -a -g -i, and when the A/A' is noisy re-link every arm
#               with fresh layout seeds and re-measure once
#   -e          enforce: exit 1 on a regression (default: report only)
#   -A          the regression is accepted (perf-regression-accepted label)
#   -T TITLE    report-only comparison (not a gate): heading "TITLE: VERDICT
#               (report only, not a gate verdict)"; exclusive with -e
#   -h          show this help
# Environment:
#   PIN_CPU     CPU for taskset (default: the last online CPU; "none" disables pinning)
#   BENCHSTAT   benchstat command (default: benchstat on PATH, else the pinned version via go run)
#   IR_SAMPLES  samples per perfdriver case, median taken (default 3, every backend)
#   PERF_GOMEMLIMIT  GOMEMLIMIT of the GOGC=off runs (default 64MiB; "off" unsets
#               it; otherwise digits with an optional B/KiB/MiB/GiB/TiB suffix)
#
# Output: DIR/report.md (also printed), DIR/status (pass, regression,
# inconclusive), DIR/raw/*.txt (raw benchmark output, each binary's results
# preceded by a "layout: <seed>" line), DIR/env.txt.
# Exit codes: 0 done (any verdict unless -e), 1 regression with -e,
#             2 usage, 3 build or measurement failure.
set -euo pipefail

BENCHSTAT_VERSION=v0.0.0-20260908200009-22c9c6c9d4da

# shellcheck source=scripts/perf/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
gcoff_env=()
while IFS= read -r kv; do gcoff_env+=("$kv"); done < <(perf_gcoff_env)
memlimit=$(perf_gomemlimit)

usage() { sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; }
die() { echo "ab.sh: $1" >&2; exit "${2:-3}"; }
log() { echo "ab.sh: $*" >&2; }

out="" rounds=20 benchtime=100ms layouts=20 seed0="" suite="" aa=0 sec=0 ir=0 gate=0 enforce=0 accepted=0 title=""
adhoc=()
while getopts ":o:r:t:k:S:s:b:T:agiGeAh" opt; do
	case $opt in
		o) out=$OPTARG ;;
		r) rounds=$OPTARG ;;
		t) benchtime=$OPTARG ;;
		k) layouts=$OPTARG ;;
		S) seed0=$OPTARG ;;
		s) suite=$OPTARG ;;
		b) adhoc+=("$OPTARG") ;;
		a) aa=1 ;;
		g) sec=1 ;;
		i) ir=1 ;;
		G) gate=1 aa=1 sec=1 ir=1 ;;
		e) enforce=1 ;;
		A) accepted=1 ;;
		T) title=$OPTARG ;;
		h) usage; exit 0 ;;
		:) die "-$OPTARG needs a value" 2 ;;
		*) die "unknown option -$OPTARG (see -h)" 2 ;;
	esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] && [ $# -le 2 ] || { usage >&2; exit 2; }
# Numbers are checked as decimal digits and then read as base 10: bash
# arithmetic would take a leading 0 as octal ("08" fails, "010" is 8).
case $rounds in '' | *[!0-9]*) die "-r must be a positive integer, got '$rounds'" 2 ;; esac
case $layouts in '' | *[!0-9]*) die "-k must be a non-negative integer, got '$layouts'" 2 ;; esac
[ -n "$seed0" ] || seed0=$(((RANDOM << 15 | RANDOM) * 1000))
case $seed0 in *[!0-9]*) die "-S must be a non-negative integer, got '$seed0'" 2 ;; esac
[ ${#rounds} -le 9 ] && [ ${#layouts} -le 9 ] && [ ${#seed0} -le 15 ] || die "-r, -k or -S is too large" 2
rounds=$((10#$rounds)) layouts=$((10#$layouts)) seed0=$((10#$seed0))
[ "$rounds" -gt 0 ] || die "-r must be a positive integer, got '$rounds'" 2
[ "$rounds" -ge "$layouts" ] || die "-r ($rounds) must be at least -k ($layouts): every layout needs a round" 2

# Layout seeds: base and head share seeds, the A/A' arm gets a disjoint set.
# -randlayout=0 means "no randomization", so seeds start at seed0+1. A
# re-measurement after a noisy A/A' (set_seeds with a later block) gets
# seeds disjoint from every earlier set.
set_seeds() { # first-seed-offset
	seed0=$1 seeds=() aa_seeds=()
	local j
	for ((j = 1; j <= layouts; j++)); do
		seeds+=($((seed0 + j)))
		aa_seeds+=($((seed0 + layouts + j)))
	done
	if [ "$layouts" -gt 0 ]; then
		layout_desc="$layouts randomized code layouts per arm (-randlayout seeds $((seed0 + 1))..$((seed0 + layouts)); A/A' $((seed0 + layouts + 1))..$((seed0 + 2 * layouts)))"
	else
		layout_desc="code layout not randomized"
	fi
}
set_seeds "$seed0"
nbin=$layouts # binaries per arm and package
[ "$nbin" -gt 0 ] || nbin=1
[ -z "$title" ] || [ $enforce -eq 0 ] || die "-T (report only) and -e are exclusive" 2
perf_check_gomemlimit || exit 2

root=$(git rev-parse --show-toplevel)
base_ref=$1
head_ref=${2:-}
base_sha=$(git -C "$root" rev-parse --verify "$base_ref^{commit}") || die "unknown base revision '$base_ref'" 2
if [ -n "$head_ref" ]; then
	head_sha=$(git -C "$root" rev-parse --verify "$head_ref^{commit}") || die "unknown head revision '$head_ref'" 2
	head_label=$(git -C "$root" rev-parse --short=12 "$head_sha")
else
	head_sha=""
	head_label="$(git -C "$root" rev-parse --short=12 HEAD)"
	git -C "$root" diff --quiet HEAD -- || head_label="$head_label + working-tree changes"
fi
base_label=$(git -C "$root" rev-parse --short=12 "$base_sha")
suite=${suite:-$root/scripts/perf/gate-suite.txt}

# ---------------------------------------------------------------- suite ----
pkgs=() regexes=()
if [ ${#adhoc[@]} -gt 0 ]; then
	for spec in "${adhoc[@]}"; do
		case $spec in *=*) ;; *) die "-b wants PKG=REGEX, got '$spec'" 2 ;; esac
		pkgs+=("${spec%%=*}") regexes+=("${spec#*=}")
	done
else
	[ -f "$suite" ] || die "suite file $suite not found" 2
	while read -r pkg re rest; do
		case $pkg in '' | \#*) continue ;; esac
		[ -n "$re" ] && [ -z "$rest" ] || die "bad suite line: $pkg $re $rest" 2
		pkgs+=("$pkg") regexes+=("$re")
	done <"$suite"
fi
[ ${#pkgs[@]} -gt 0 ] || die "empty benchmark suite" 2

# ---------------------------------------------------------- source trees ---
out_given=0
[ -z "$out" ] || out_given=1
out=${out:-$(mktemp -d "${TMPDIR:-/tmp}/gosqlx-ab.XXXXXX")}
mkdir -p "$out"
out=$(cd "$out" && pwd)

# On any exit: stop build jobs still running (a failed build must not leave
# the others linking) and, when the caller did not choose the output
# directory, delete the test binaries and source trees (about 3 GB with 20
# layouts) but keep the report and raw results.
build_pids=()
cleanup() {
	local p
	for p in ${build_pids[@]+"${build_pids[@]}"}; do
		pkill -TERM -P "$p" 2>/dev/null || true
		kill -TERM "$p" 2>/dev/null || true
	done
	for p in ${build_pids[@]+"${build_pids[@]}"}; do wait "$p" 2>/dev/null || true; done
	build_pids=()
	if [ "$out_given" -eq 0 ]; then
		rm -rf "$out/bin" "$out/src"
	fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
rm -rf "$out/src" "$out/bin" "$out/raw" "$out"/build-*.log
mkdir -p "$out/src/base" "$out/bin/base" "$out/bin/head" "$out/bin/base2" "$out/raw"
log "output in $out"

git -C "$root" archive --format=tar "$base_sha" | tar -x -C "$out/src/base"
base_tree=$out/src/base
if [ -n "$head_sha" ]; then
	mkdir -p "$out/src/head"
	git -C "$root" archive --format=tar "$head_sha" | tar -x -C "$out/src/head"
	head_tree=$out/src/head
else
	head_tree=$root
fi

# The instruction-count driver must be the same program in both arms, so the
# head's driver is copied over the base tree (only the library differs).
if [ $ir -eq 1 ] && [ -d "$head_tree/cmd/perfdriver" ]; then
	rm -rf "$base_tree/cmd/perfdriver"
	mkdir -p "$base_tree/cmd/perfdriver"
	cp "$head_tree"/cmd/perfdriver/*.go "$base_tree/cmd/perfdriver/"
fi

slug() { printf '%s' "$1" | sed -e 's#^\./##' -e 's#/#_#g'; }

# ---------------------------------------------------------------- build ----
export CGO_ENABLED=0
# build_arm builds layout j (1-based) of an arm: one test binary per package
# in bin/ARM/Lj, linked with -randlayout=SEED (SEED 0: default layout). Only
# the link step differs between layouts; compiled packages come from the
# build cache.
build_arm() { # arm tree j seed
	local arm=$1 tree=$2 j=$3 seed=$4 pkg seen=" " ld=()
	[ "$seed" = 0 ] || ld=("-ldflags=-randlayout=$seed")
	mkdir -p "$out/bin/$arm/L$j"
	for pkg in "${pkgs[@]}"; do
		case $seen in *" $pkg "*) continue ;; esac
		seen="$seen$pkg "
		go -C "$tree" test -c ${ld[@]+"${ld[@]}"} -o "$out/bin/$arm/L$j/$(slug "$pkg").test" "$pkg" ||
			return 1
	done
}

seed_of() { # arm j -> the arm's seed for layout j (0 without randomization)
	if [ "$layouts" -eq 0 ]; then
		echo 0
	elif [ "$1" = base2 ]; then
		echo "${aa_seeds[$(($2 - 1))]}"
	else
		echo "${seeds[$(($2 - 1))]}"
	fi
}

tree_of() { # arm -> source tree
	case $1 in base | base2) echo "$base_tree" ;; head) echo "$head_tree" ;; esac
}

# build_layouts builds every layout of every arm for the current seeds.
build_layouts() {
	local arm j i n jobs=() names=() par t0
	t0=$(date +%s)
	rm -rf "$out"/bin/base/L* "$out"/bin/head/L* "$out"/bin/base2/L* "$out"/build-*.log
	# Layout 1 of base and head first, one at a time: on a cold cache it
	# compiles every package (the logs show progress), so the remaining
	# builds are links only.
	for arm in base head; do
		log "building $arm layout 1 of $nbin (seed $(seed_of $arm 1))"
		build_arm $arm "$(tree_of $arm)" 1 "$(seed_of $arm 1)" 2>&1 | tee "$out/build-$arm-L1.log" >&2 ||
			die "building the $arm test binaries failed (see build-$arm-L1.log)"
	done
	# The rest in parallel batches. The A/A' arm (-a) has its own layouts
	# only when layouts are randomized; otherwise it reuses the base binary.
	for ((j = 1; j <= nbin; j++)); do
		for arm in base head base2; do
			[ "$arm" != base2 ] || { [ $aa -eq 1 ] && [ "$layouts" -gt 0 ]; } || continue
			[ "$j" -gt 1 ] || [ "$arm" = base2 ] || continue
			jobs+=("$arm $j")
		done
	done
	par=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
	[ "$par" -ge 1 ] || par=1
	if [ ${#jobs[@]} -gt 0 ]; then
		log "linking ${#jobs[@]} more layout builds, $par at a time"
	fi
	for ((i = 0; i < ${#jobs[@]}; i += par)); do
		build_pids=() names=()
		for ((n = i; n < i + par && n < ${#jobs[@]}; n++)); do
			read -r arm j <<<"${jobs[$n]}"
			build_arm "$arm" "$(tree_of "$arm")" "$j" "$(seed_of "$arm" "$j")" >"$out/build-$arm-L$j.log" 2>&1 &
			build_pids+=($!) names+=("$arm-L$j")
		done
		for n in "${!build_pids[@]}"; do
			if ! wait "${build_pids[$n]}"; then
				cat "$out/build-${names[$n]}.log" >&2
				# die exits through cleanup, which stops the other jobs.
				die "building the ${names[$n]} test binaries failed"
			fi
		done
		build_pids=()
	done
	log "built the layouts in $(($(date +%s) - t0))s"
}
build_layouts

ir_note=""
if [ $ir -eq 1 ]; then
	if ! (cd "$head_tree" && go build -o "$out/bin/head/perfdriver" ./cmd/perfdriver) 2>"$out/perfdriver-head.log"; then
		ir=0 ir_note="cmd/perfdriver did not build in the head tree (see perfdriver-head.log)"
	elif ! (cd "$base_tree" && go build -o "$out/bin/base/perfdriver" ./cmd/perfdriver) 2>"$out/perfdriver-base.log"; then
		ir=0 ir_note="cmd/perfdriver did not build against the base revision (see perfdriver-base.log)"
	fi
fi

# --------------------------------------------------------------- pinning ---
pin=()
pin_desc="not pinned"
if [ "${PIN_CPU:-}" != none ] && command -v taskset >/dev/null 2>&1; then
	cpu=${PIN_CPU:-$(($(getconf _NPROCESSORS_ONLN) - 1))}
	pin=(taskset -c "$cpu")
	siblings=$(cat "/sys/devices/system/cpu/cpu$cpu/topology/thread_siblings_list" 2>/dev/null || echo "?")
	pin_desc="pinned to CPU $cpu (SMT siblings $siblings) with taskset"
fi

# --------------------------------------------- instruction counter ---
ir_backend=""
if [ $ir -eq 1 ]; then
	if command -v perf >/dev/null 2>&1 &&
		perf stat -x, -e instructions:u -- true 2>&1 | grep -Eq '^[0-9]+,'; then
		ir_backend=perf
	elif command -v valgrind >/dev/null 2>&1; then
		ir_backend=cachegrind
	elif [ "$(uname -s)" = Darwin ] && /usr/bin/time -l true 2>&1 | grep -q 'instructions retired'; then
		ir_backend=time
	else
		ir=0 ir_note="no instruction counter on this machine (perf stat lacks instructions:u, no valgrind)"
	fi
fi

# ----------------------------------------------------------- environment ---
{
	echo "date:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "base:        $base_sha"
	echo "head:        ${head_sha:-working tree of $(git -C "$root" rev-parse HEAD)}"
	echo "cpu model:   $(perf_cpu_model)"
	echo "go:          $(go version)"
	echo "kernel:      $(uname -srm)"
	if [ "$layouts" -gt 0 ]; then
		echo "layouts:     $layouts per arm, -ldflags=-randlayout seeds $((seed0 + 1))..$((seed0 + layouts)) (base, head), $((seed0 + layouts + 1))..$((seed0 + 2 * layouts)) (A/A')"
	else
		echo "layouts:     not randomized (-k 0)"
	fi
	echo "pinning:     $pin_desc"
	echo "gcoff env:   ${gcoff_env[*]}"
	echo "clocksource: $(cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null || echo n/a)"
	echo "load:        $(uptime | sed 's/.*load average[s]*: //')"
	echo "instr count: ${ir_backend:-none}${ir_note:+ ($ir_note)}"
	if command -v perf >/dev/null 2>&1; then
		echo "perf probe:  $(perf stat -x, -e instructions:u -- true 2>&1 | head -n 3 | tr '\n' ' ' | cut -c 1-200)"
	else
		echo "perf probe:  perf not installed"
	fi
	if command -v lscpu >/dev/null 2>&1; then
		echo
		lscpu | grep -E '^(Model name|Architecture|CPU\(s\)|Thread\(s\) per core|Core\(s\) per socket|Socket\(s\)|L1d|L1i|L2|L3|Hypervisor vendor)'
	elif [ "$(uname -s)" = Darwin ]; then
		echo "cpu:         $(sysctl -n machdep.cpu.brand_string) ($(sysctl -n hw.ncpu) CPUs)"
	fi
} >"$out/env.txt"

# --------------------------------------------------------------- measure ---
run_arm() { # arm config outfile round
	local arm=$1 config=$2 file=$3 round=$4 bin tree i j seed
	j=$((round % nbin + 1))
	tree=$(tree_of "$arm")
	seed=$(seed_of "$arm" "$j")
	if [ "$arm" = base2 ] && [ "$layouts" -eq 0 ]; then
		bin=$out/bin/base/L1 # the identical-binary A/A control
	else
		bin=$out/bin/$arm/L$j
	fi
	# The gate groups samples by this benchfmt configuration line.
	[ "$seed" = 0 ] || echo "layout: $seed" >>"$file"
	for i in "${!pkgs[@]}"; do
		local pkg=${pkgs[$i]} re=${regexes[$i]} envs
		if [ "$config" = gcoff ]; then envs=("${gcoff_env[@]}" GOMAXPROCS=1); else envs=(-u GOGC -u GOMEMLIMIT GOMAXPROCS=1); fi
		(cd "$tree/$pkg" && env "${envs[@]}" ${pin[@]+"${pin[@]}"} "$bin/$(slug "$pkg").test" \
			-test.run '^$' -test.bench "$re" -test.benchmem -test.count 1 \
			-test.benchtime "$benchtime" -test.cpu 1) >"$out/run.log" 2>&1 ||
			{ cat "$out/run.log" >&2; die "$arm benchmark run failed: $pkg $re"; }
		grep -E '^(Benchmark|goos:|goarch:|pkg:|cpu:)' "$out/run.log" >>"$file" || true
	done
}

measure() { # config rounds arms...
	local config=$1 nr=$2 r arms order a
	shift 2
	arms=("$@")
	for a in "${arms[@]}"; do : >"$out/raw/$config-$a.txt"; done
	for ((r = 0; r < nr; r++)); do
		if [ ${#arms[@]} -eq 3 ]; then
			# All six orders of three arms, so each arm takes every position.
			case $((r % 6)) in
				0) order="0 1 2" ;; 1) order="1 2 0" ;; 2) order="2 0 1" ;;
				3) order="2 1 0" ;; 4) order="1 0 2" ;; 5) order="0 2 1" ;;
			esac
		elif [ ${#arms[@]} -eq 2 ]; then
			if [ $((r % 2)) -eq 0 ]; then order="0 1"; else order="1 0"; fi
		else
			order=0
		fi
		log "$config round $((r + 1))/$nr (layout $((r % nbin + 1)) of $nbin)"
		for a in $order; do run_arm "${arms[$a]}" "$config" "$out/raw/$config-${arms[$a]}.txt" "$r"; done
	done
}

primary_arms=(base head)
[ $aa -eq 1 ] && primary_arms+=(base2)

sec_rounds=$rounds
if [ "$layouts" -gt 0 ]; then
	sec_rounds=$layouts
	[ "$sec_rounds" -le 10 ] || sec_rounds=10
fi

started=$(date +%s)
measure gcoff "$rounds" "${primary_arms[@]}"
[ $sec -eq 1 ] && measure gcon "$sec_rounds" base head

count_instructions() { # arm case n -> prints the count
	local arm=$1 c=$2 n=$3 tree log=$out/ir.log
	case $arm in base) tree=$base_tree ;; head) tree=$head_tree ;; esac
	# The environment is set outside the counter so that the counted
	# process is perfdriver itself, not env (valgrind does not follow exec).
	local envs=("${gcoff_env[@]}" GOMAXPROCS=1 GODEBUG=asyncpreemptoff=1)
	local drv=("$out/bin/$arm/perfdriver" -case "$c" -n "$n")
	case $ir_backend in
		perf)
			(cd "$tree" && env "${envs[@]}" perf stat -x, -e instructions:u -o "$log" -- "${drv[@]}") >/dev/null || return 1
			awk -F, '/instructions/ {print $1; exit}' "$log" ;;
		cachegrind)
			(cd "$tree" && env "${envs[@]}" valgrind --tool=cachegrind --cache-sim=no --cachegrind-out-file=/dev/null "${drv[@]}") >/dev/null 2>"$log" || return 1
			sed -n 's/.*I *refs: *\([0-9,]*\).*/\1/p' "$log" | tr -d , | head -n 1 ;;
		time)
			(cd "$tree" && env "${envs[@]}" /usr/bin/time -l "${drv[@]}") >/dev/null 2>"$log" || return 1
			awk '/instructions retired/ {print $1; exit}' "$log" ;;
	esac
}

# measure_ir writes raw/ir-{base,head}.txt; it returns 1 (with ir_note set)
# when a count fails, so the timing verdict is still produced.
measure_ir() {
	local samples cases c s arm n1 n2 i1 i2
	samples=${IR_SAMPLES:-3}
	cases=$(cd "$head_tree" && "$out/bin/head/perfdriver" -list)
	: >"$out/raw/ir-base.txt"
	: >"$out/raw/ir-head.txt"
	log "instructions/op via $ir_backend, $samples sample(s) per case"
	for c in $cases; do
		# Iteration counts: no counter is fully deterministic for Go (map
		# hash seeds change per process, so start-up and keyword lookups vary
		# a little), so every backend takes the median of several samples
		# and runs enough operations to bury the start-up jitter. Cachegrind
		# is slow, so it runs fewer. Real-world operations parse up to 64
		# statements each.
		if [ $ir_backend = cachegrind ]; then
			case $c in rw/*) n1=10 n2=110 ;; *) n1=500 n2=5500 ;; esac
		else
			case $c in rw/*) n1=40 n2=440 ;; *) n1=2000 n2=22000 ;; esac
		fi
		for ((s = 0; s < samples; s++)); do
			for arm in base head; do
				if ! i1=$(count_instructions $arm "$c" $n1) || ! i2=$(count_instructions $arm "$c" $n2) ||
					[ -z "$i1" ] || [ -z "$i2" ]; then
					ir_note="$ir_backend gave no count for $arm $c (see ir.log in the artifact)"
					log "$ir_note"
					tail -n 20 "$out/ir.log" >&2 || true
					return 1
				fi
				if [ "$i2" -le "$i1" ]; then
					ir_note="$ir_backend counted fewer instructions for $n2 than for $n1 operations of $arm $c"
					log "$ir_note"
					return 1
				fi
				echo "BenchmarkPerfdriver/$c 1 $(((i2 - i1) / (n2 - n1))) instructions/op" >>"$out/raw/ir-$arm.txt"
			done
		done
	done
}

if [ $ir -eq 1 ] && ! measure_ir; then ir=0; fi

# ------------------------------------------------------------------ judge ---
benchstat_cmd() {
	if [ -n "${BENCHSTAT:-}" ]; then
		$BENCHSTAT "$@"
	elif command -v benchstat >/dev/null 2>&1; then
		benchstat "$@"
	else
		(cd "$root" && go run "golang.org/x/perf/cmd/benchstat@$BENCHSTAT_VERSION" "$@")
	fi
}

judge() { # extra gate flags...
	benchstat_cmd -alpha 0.01 -ignore layout "base=$out/raw/gcoff-base.txt" "head=$out/raw/gcoff-head.txt" >"$out/benchstat.txt" 2>&1 ||
		log "benchstat failed; the report embeds its error output"
	local args=(-base "$out/raw/gcoff-base.txt" -head "$out/raw/gcoff-head.txt"
		-md "$out/report.md" -status "$out/status" -env "$out/env.txt" -benchstat "$out/benchstat.txt"
		-base-ref "$base_label" -head-ref "$head_label"
		-settings "$rounds interleaved rounds, $layout_desc, benchtime $benchtime, -cpu 1, GOMEMLIMIT $memlimit, $pin_desc.")
	[ $aa -eq 1 ] && args+=(-aa "$out/raw/gcoff-base2.txt")
	[ $sec -eq 1 ] && args+=(-sec-base "$out/raw/gcon-base.txt" -sec-head "$out/raw/gcon-head.txt")
	if [ $ir -eq 1 ]; then
		args+=(-ir-base "$out/raw/ir-base.txt" -ir-head "$out/raw/ir-head.txt")
	elif [ -n "$ir_note" ]; then
		args+=(-ir-note "$ir_note")
	else
		args+=(-ir-note "not requested (-i)")
	fi
	[ $enforce -eq 1 ] && args+=(-enforce)
	[ $accepted -eq 1 ] && args+=(-accepted)
	[ -n "$title" ] && args+=(-report-only -title "$title")
	(cd "$gate_src" && go run ./scripts/perf/gate "${args[@]}" "$@")
}

# The gate tool comes from the head tree; an older head (bench:ab of an
# arbitrary revision pair) may not have it, so fall back to this checkout's.
gate_src=$head_tree
[ -d "$gate_src/scripts/perf/gate" ] || gate_src=$root

gate_rc=0
judge || gate_rc=$?
log "gate exited $gate_rc"
if [ $gate_rc -le 1 ] && [ $gate -eq 1 ] && [ "$(cat "$out/status")" = noisy ]; then
	mkdir -p "$out/raw/attempt1"
	mv "$out"/raw/gcoff-*.txt "$out/raw/attempt1/"
	cp "$out/report.md" "$out/status" "$out/benchstat.txt" "$out/raw/attempt1/"
	if [ "$layouts" -gt 0 ]; then
		# Measuring the same binaries again would repeat whatever made the
		# A/A' noisy if it was the layouts. Link every arm afresh with the
		# next block of seeds (links only, compiles are cached), so the
		# re-measurement is an independent draw of layouts.
		set_seeds $((seed0 + 2 * layouts))
		log "A/A' control noisy; re-linking with fresh layouts ($layout_desc) and measuring the primary metric once more"
		echo "retry:       $layout_desc" >>"$out/env.txt"
		build_layouts
	else
		log "A/A control noisy; measuring the primary metric once more"
	fi
	measure gcoff "$rounds" "${primary_arms[@]}"
	gate_rc=0
	judge -final || gate_rc=$?
	log "gate exited $gate_rc"
fi
log "measured in $(($(date +%s) - started))s; verdict $(cat "$out/status" 2>/dev/null || echo unknown)"
[ -f "$out/report.md" ] && cat "$out/report.md"
case $gate_rc in 0 | 1) exit $gate_rc ;; *) die "gate failed (exit $gate_rc)" ;; esac
