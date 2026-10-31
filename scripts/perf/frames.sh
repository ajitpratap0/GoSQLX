#!/usr/bin/env bash
# frames.sh - list the largest stack frames among the parse hot path functions.
#
# Large frames make goroutine stacks grow earlier (each doubling copies the
# stack) and spread hot code over more cache lines, so a frame that grows is a
# performance regression even when the benchmarks have not caught it yet.
#
# The frame size is the "locals=" field the compiler prints for every function
# under `go build -gcflags=-S`; that output has the same shape on amd64 and
# arm64. Sizes are architecture dependent, so only compare runs on one arch.
#
# Usage: scripts/perf/frames.sh [-n TOP] [-m MAX_BYTES] [PACKAGE...]
#   -n TOP        number of frames to list (default 15)
#   -m MAX_BYTES  exit 1 when the largest frame exceeds MAX_BYTES (default: report only)
#   PACKAGE       packages to inspect (default: tokenizer, parser, ast, gosqlx)
set -euo pipefail

top=15
max=""
while getopts "n:m:h" opt; do
  case "$opt" in
    n) top="$OPTARG" ;;
    m) max="$OPTARG" ;;
    h|*) sed -n '2,/^set /p' "$0" | sed '$d;s/^# \{0,1\}//' ; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

mod=github.com/ajitpratap0/GoSQLX
pkgs=("$@")
if [ ${#pkgs[@]} -eq 0 ]; then
  pkgs=("$mod/pkg/sql/tokenizer" "$mod/pkg/sql/parser" "$mod/pkg/sql/ast" "$mod/pkg/gosqlx")
fi

cd "$(git rev-parse --show-toplevel)"

flags=()
for p in "${pkgs[@]}"; do
  flags+=("-gcflags=$p=-S")
done

out=$(mktemp)
trap 'rm -f "$out" "$out.all" "$out.top"' EXIT

# -S prints the assembly listing of each function to stderr. The build cache
# replays that output, so repeated runs stay cheap.
go build "${flags[@]}" -o /dev/null ./pkg/gosqlx 2> "$out"

# Lines look like:
#   pkg.(*Parser).parseSelect STEXT size=1234 args=0x10 locals=0x1f8 funcid=0x0 align=0x0
awk '
  / STEXT / {
    name = $1
    for (i = 2; i <= NF; i++) {
      if ($i ~ /^locals=0x/) {
        v = substr($i, 10)
        n = 0
        for (j = 1; j <= length(v); j++) {
          n = n * 16 + index("0123456789abcdef", substr(v, j, 1)) - 1
        }
        print n, name
      }
    }
  }
' "$out" | sort -u | sort -k1,1nr -k2,2 > "$out.all"
head -n "$top" "$out.all" > "$out.top"

printf 'Top %s frames (bytes of locals) on %s/%s:\n' "$top" "$(go env GOOS)" "$(go env GOARCH)"
printf '%8s  %s\n' "BYTES" "FUNCTION"
largest=0
while read -r size name; do
  printf '%8d  %s\n' "$size" "$name"
  if [ "$size" -gt "$largest" ]; then largest=$size; fi
done < "$out.top"

if [ "$largest" -eq 0 ]; then
  echo "frames.sh: no STEXT lines found; did the compiler output change?" >&2
  exit 3
fi

if [ -n "$max" ] && [ "$largest" -gt "$max" ]; then
  echo "frames.sh: largest frame $largest bytes exceeds limit $max" >&2
  exit 1
fi
