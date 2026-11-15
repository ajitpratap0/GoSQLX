# lib.sh - settings and helpers shared by the perf scripts (ab.sh, profile.sh).
# Source it; it defines functions and one default and runs nothing.
#
# GOMEMLIMIT next to GOGC=off
#   Every GOGC=off measurement also sets GOMEMLIMIT (PERF_GOMEMLIMIT, default
#   below; "off" leaves the limit unset). With GOGC=off and no limit the heap
#   only grows, so every allocated byte lands on a fresh page and pays a
#   first-touch page fault plus kernel zeroing. That cost is not mutator work,
#   scales with B/op and lands on whichever benchmark first grows the heap in a
#   process: in the C0 A/A run (EPYC 9V45) ParseE2E/simple_select, the first
#   benchmark of its binary, gained nothing from GOGC=off while every other
#   query gained 21-25%, and the GOGC=off profiles spent 6-11% in page-touching
#   memclr. With a limit the collector runs only when the heap reaches it and
#   the freed pages are reused. The limit must sit below what one 200ms
#   benchmark run allocates (about 100 MB for simple_select), or it changes
#   nothing; each collection of the tiny live heap costs about 0.5 ms of one
#   CPU, so 64MiB keeps the collector to about 1% of a GOMAXPROCS=1 run.
#   The default-GC arms unset GOMEMLIMIT so an inherited value cannot leak in.
#   benchmarks/compare/cmd/publish uses the same default (a test keeps them
#   equal).
PERF_GOMEMLIMIT_DEFAULT=64MiB

# perf_gomemlimit prints the GOMEMLIMIT that GOGC=off runs use, or "off".
perf_gomemlimit() {
	printf '%s\n' "${PERF_GOMEMLIMIT:-$PERF_GOMEMLIMIT_DEFAULT}"
}

# perf_check_gomemlimit fails with a message on stderr unless the limit is
# "off" or a value the Go runtime accepts (digits, optional B, KiB, MiB, GiB
# or TiB suffix). A bad value would otherwise make every benchmark binary
# panic at startup.
perf_check_gomemlimit() {
	local limit
	limit=$(perf_gomemlimit)
	case $limit in
		off) return 0 ;;
		'' | *[!0-9A-Za-z]*) ;;
		*)
			local n=$limit
			case $n in *B) n=${n%B} n=${n%[KMGT]i} ;; esac
			case $n in '' | *[!0-9]*) ;; *) return 0 ;; esac
			;;
	esac
	echo "PERF_GOMEMLIMIT must be off or digits with an optional B/KiB/MiB/GiB/TiB suffix (e.g. 64MiB), got '$limit'" >&2
	return 1
}

# perf_gcoff_env prints the env(1) arguments of a GOGC=off measurement, one
# per line: GOGC=off and GOMEMLIMIT=<limit>, or, when the limit is off,
# "-u" "GOMEMLIMIT" first (env options must precede assignments) and then
# GOGC=off. Read it into an array with a while-read loop (macOS ships bash
# 3.2, which has no mapfile).
perf_gcoff_env() {
	local limit
	limit=$(perf_gomemlimit)
	if [ "$limit" = off ]; then
		printf '%s\n' -u GOMEMLIMIT GOGC=off
	else
		printf '%s\n' GOGC=off "GOMEMLIMIT=$limit"
	fi
}

# perf_cpu_model prints the CPU model of this machine and its architecture,
# for example "AMD EPYC 7763 64-Core Processor (x86_64)". Hosted runners hand
# out different CPU models from one job to the next, so every artifact records
# it and absolute timings are only compared within one job.
perf_cpu_model() {
	local m=""
	if [ -r /proc/cpuinfo ]; then
		m=$(sed -n 's/^model name[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -n 1)
	fi
	if [ -z "$m" ] && command -v lscpu >/dev/null 2>&1; then
		m=$(lscpu | sed -n 's/^Model name:[[:space:]]*//p' | head -n 1)
	fi
	if [ -z "$m" ] && [ "$(uname -s)" = Darwin ]; then
		m=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || true)
	fi
	m=$(printf '%s' "$m" | sed -e 's/[[:space:]]\{1,\}/ /g' -e 's/^ //' -e 's/ $//')
	printf '%s (%s)\n' "${m:-unknown}" "$(uname -m)"
}

# perf_cachegrind_counts reads the summary that `valgrind --tool=cachegrind`
# writes to stderr and prints "Ir I1mr ILmr Dr D1mr DLmr" as plain integers
# (0 for a counter the summary lacks; with --cache-sim=no only Ir is there).
# It fails when the summary has no "I refs" line.
perf_cachegrind_counts() {
	local f=$1 key ir
	ir=$(sed -nE 's/.*[[:space:]]I[[:space:]]+refs:[[:space:]]+([0-9,]+).*/\1/p' "$f" | head -n 1 | tr -d ,)
	[ -n "$ir" ] || return 1
	printf '%s' "$ir"
	for key in 'I1[[:space:]]+misses' 'LLi[[:space:]]+misses' 'D[[:space:]]+refs' 'D1[[:space:]]+misses' 'LLd[[:space:]]+misses'; do
		local v
		v=$(sed -nE "s/.*[[:space:]]${key}:[[:space:]]+([0-9,]+).*/\\1/p" "$f" | head -n 1 | tr -d ,)
		printf ' %s' "${v:-0}"
	done
	printf '\n'
}

# perf_ext_seed keeps extension layouts disjoint from both stage-one arms.
perf_ext_seed() { awk -v seed="$1" -v k="$2" -v j="$3" 'BEGIN { printf "%.0f\n", seed+k+j }'; }

# The plan readers use only portable awk (including macOS /usr/bin/awk).
perf_plan_max() { awk -F '\t' '$1 == "need" && $3 > m { m=$3 } END { print m+0 }' "$1"; }
perf_plan_lines() {
	awk -F '\t' -v r="$2" '$1 == "need" && $3 > r { lines[$2]=1; if ($2 > max) max=$2 } END { for (i=0; i<=max; i++) if (i in lines) print i }' "$1"
}
perf_plan_regex() {
	awk -F '\t' -v line="$2" -v r="$3" '
		$1 == "warmup" && $2 == line { warm=$3 }
		$1 == "need" && $2 == line && $3 > r { regex[++n]=$6; selected[$6]=1 }
		END {
			if (!n) exit
			if (warm != "" && !(warm in selected)) out=warm
			for (i=1; i<=n; i++) out=out (out == "" ? "" : "|") regex[i]
			print out
		}' "$1"
}
