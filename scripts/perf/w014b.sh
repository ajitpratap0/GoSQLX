#!/usr/bin/env bash
# W0-14b scratch profiler (not for merge): amd64 numbers and CPU profiles of
# the real-world losses (MySQL/SQLite common-accept sets, ORM DDL, backtick
# identifiers, compact render, Normalize) from the benchmarks/compare harness.
set -euo pipefail

out="" benchtime=4s
while getopts ":o:t:q:" opt; do
	case $opt in
		o) out=$OPTARG ;;
		t) benchtime=$OPTARG ;;
		q) ;;
		*) ;;
	esac
done
root=$(git rev-parse --show-toplevel)
out=${out:-$(mktemp -d)}
mkdir -p "$out"
out=$(cd "$out" && pwd)

# The harness module needs Go 1.26.9 (the bench-compare toolchain); the
# workflow pins GOTOOLCHAIN=local to the root module's 1.26.1.
export GOTOOLCHAIN=go1.26.9
export CGO_ENABLED=1
cd "$root/benchmarks/compare"
go version
go build ./... >/dev/null
go test -c -o "$out/compare.test" .
pin=()
if command -v taskset >/dev/null 2>&1; then pin=(taskset -c "$(($(getconf _NPROCESSORS_ONLN) - 1))"); fi

{
	echo "date:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "revision:    $(git -C "$root" rev-parse HEAD)"
	echo "go:          $(go version)"
	echo "kernel:      $(uname -srm)"
	echo "clocksource: $(cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null || echo n/a)"
	if command -v lscpu >/dev/null 2>&1; then echo; lscpu; fi
} >"$out/env.txt"
cat "$out/env.txt" | head -30

T="$out/compare.test"
gcoff=(env GOGC=off GOMEMLIMIT=1GiB GOMAXPROCS=1)

echo "== per-statement TSVs" >&2
GOMAXPROCS=4 W014B_OUT="$out/perstmt-cpu4.tsv" W014B_DIALECTS="mysql sqlite mariadb" "$T" -test.run '^TestW014bPerStmt$' -test.count=1 -test.timeout 20m
"${gcoff[@]}" ${pin[@]+"${pin[@]}"} env W014B_OUT="$out/perstmt-gcoff.tsv" W014B_DIALECTS="mysql sqlite" "$T" -test.run '^TestW014bPerStmt$' -test.count=1 -test.timeout 20m

bench() { # name regex cpu file extra-env...
	local re=$1 cpu=$2 file=$3
	shift 3
	env "$@" "$T" -test.run '^$' -test.bench "$re" -test.benchmem -test.benchtime 150ms -test.count 5 -test.cpu "$cpu" -test.timeout 30m >>"$file" 2>&1 || echo "bench $re failed" >&2
}
echo "== benchmarks" >&2
for cfg in cpu4 gcoff; do
	f="$out/bench-$cfg.txt"
	: >"$f"
	if [ $cfg = cpu4 ]; then cpu=4 envs=(GOMAXPROCS=4); else cpu=1 envs=(GOGC=off GOMEMLIMIT=1GiB GOMAXPROCS=1); fi
	bench 'BenchmarkParseDialect/(mysql|sqlite|mariadb)/(gosqlx|vitess|tidb|rqlite_sql)$' $cpu "$f" "${envs[@]}"
	bench 'BenchmarkW014bKind/(mysql|sqlite)/(CREATE_TABLE|ALTER_TABLE|SELECT|SHOW|SET|INSERT|UPDATE|WITH|CREATE_INDEX|BEGIN|COMMIT)/(gosqlx|vitess|rqlite_sql)$' $cpu "$f" "${envs[@]}"
	bench 'BenchmarkW014bLexSet' $cpu "$f" "${envs[@]}"
	bench 'BenchmarkW014bShape' $cpu "$f" "${envs[@]}"
	bench 'BenchmarkParseORM/orm_.*/(gosqlx|gosqlx_norelease|vitess|rqlite_sql|tidb)$' $cpu "$f" "${envs[@]}"
	if [ $cfg = cpu4 ]; then
		bench 'BenchmarkRender/.*/(gosqlx_compact|gosqlx_sql|vitess_string)$' $cpu "$f" "${envs[@]}"
		bench 'BenchmarkNormalize/.*/(gosqlx|gosqlx_fingerprint|tidb_digest|vitess_redact)$' $cpu "$f" "${envs[@]}"
	fi
done

echo "== profiles" >&2
cells=(
	'BenchmarkParseDialect/mysql/gosqlx$'
	'BenchmarkParseDialect/mysql/vitess$'
	'BenchmarkParseDialect/sqlite/gosqlx$'
	'BenchmarkParseDialect/sqlite/rqlite_sql$'
	'BenchmarkW014bKind/mysql/CREATE_TABLE/gosqlx$'
	'BenchmarkW014bKind/mysql/CREATE_TABLE/vitess$'
	'BenchmarkW014bKind/mysql/ALTER_TABLE/gosqlx$'
	'BenchmarkW014bKind/mysql/SHOW/gosqlx$'
	'BenchmarkW014bKind/mysql/SELECT/gosqlx$'
	'BenchmarkW014bKind/sqlite/SELECT/gosqlx$'
	'BenchmarkW014bKind/sqlite/SELECT/rqlite_sql$'
	'BenchmarkW014bKind/sqlite/CREATE_TABLE/gosqlx$'
	'BenchmarkParseORM/orm_ddl_create/gosqlx$'
	'BenchmarkParseORM/orm_ddl_index/gosqlx$'
	'BenchmarkParseORM/orm_quoted_mysql/gosqlx$'
	'BenchmarkW014bShape/commit/gosqlx_mysql$'
	'BenchmarkW014bShape/select1/gosqlx$'
	'BenchmarkRender/cte/gosqlx_compact$'
	'BenchmarkRender/aggregate/gosqlx_compact$'
	'BenchmarkRender/complex/gosqlx_compact$'
	'BenchmarkRender/aggregate/gosqlx_sql$'
	'BenchmarkRender/cte/vitess_string$'
	'BenchmarkNormalize/simple_select/gosqlx$'
	'BenchmarkNormalize/aggregate/gosqlx$'
	'BenchmarkNormalize/complex/gosqlx$'
	'BenchmarkNormalize/complex/tidb_digest$'
)
mkdir -p "$out/prof"
for c in "${cells[@]}"; do
	name=$(echo "$c" | sed -e 's/^Benchmark//' -e 's/\$$//' -e 's#/#_#g')
	for cfg in cpu4 gcoff; do
		if [ $cfg = cpu4 ]; then cpu=4 envs=(GOMAXPROCS=4) p=(); else cpu=1 envs=(GOGC=off GOMEMLIMIT=1GiB GOMAXPROCS=1) p=(${pin[@]+"${pin[@]}"}); fi
		echo "profile $name $cfg" >&2
		env "${envs[@]}" ${p[@]+"${p[@]}"} "$T" -test.run '^$' -test.bench "$c" -test.benchmem -test.benchtime "$benchtime" \
			-test.cpu $cpu -test.cpuprofile "$out/prof/cpu-$cfg-$name.pprof" >"$out/prof/bench-$cfg-$name.txt" 2>&1 || echo "profile $c failed" >&2
		go tool pprof -top -nodecount=60 "$T" "$out/prof/cpu-$cfg-$name.pprof" >"$out/prof/top-$cfg-$name.txt" 2>/dev/null || true
		go tool pprof -top -cum -nodecount=80 "$T" "$out/prof/cpu-$cfg-$name.pprof" >"$out/prof/cum-$cfg-$name.txt" 2>/dev/null || true
	done
done
echo "W0-14b profile run done" | tee "$out/summary.md"
