#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: refresh-benchmarks.sh <compare|parse|verify|all> vX.Y.Z [--prev vA.B.C] [--rounds 20] [--dry-run]
EOF
}

if (($# < 2)); then
  usage
  exit 1
fi

mode=$1
tag=$2
shift 2
repo=${GH_REPO:-ajitpratap0/GoSQLX}
temp_dirs=()
worktrees=()
prev_override=
rounds=20
dry_run=false
while (($#)); do
  case "$1" in
    --prev)
      (($# >= 2)) || { usage; exit 1; }
      prev_override=$2
      shift 2
      ;;
    --rounds)
      (($# >= 2)) || { usage; exit 1; }
      rounds=$2
      [[ $rounds =~ ^[1-9][0-9]*$ ]] || { echo "--rounds must be a positive integer" >&2; exit 1; }
      shift 2
      ;;
    --dry-run)
      dry_run=true
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "tag must match vX.Y.Z" >&2; exit 1; }
case "$mode" in compare|parse|verify|all) ;; *) usage; exit 1 ;; esac

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

cleanup() {
  local worktree temp_dir
  for worktree in "${worktrees[@]}"; do
    git worktree remove --force "$worktree" >/dev/null 2>&1 || true
  done
  for temp_dir in "${temp_dirs[@]}"; do
    rm -rf "$temp_dir"
  done
}
trap cleanup EXIT

hint() {
  echo "gh workflow run bench-compare.yml -R $repo --ref $tag" >&2
  echo "gh run watch -R $repo" >&2
}

compare() {
  local sha runs selected run_id event url artifact tmp file
  sha=$(git rev-parse "$tag^{commit}") || { echo "tag $tag is not available locally" >&2; exit 1; }
  runs=$(gh run list -R "$repo" --workflow bench-compare.yml --branch "$tag" -L 50 --json databaseId,event,headSha,status,conclusion,createdAt,url) || {
    echo "listing bench-compare runs failed" >&2
    exit 1
  }
  selected=$(jq -c --arg sha "$sha" '[.[] | select(.headSha == $sha and .status == "completed" and .conclusion == "success")] | sort_by(.createdAt) | reverse | (map(select(.event == "push")) | .[0]) // (map(select(.event == "workflow_dispatch")) | .[0])' <<<"$runs")
  if [[ $selected == null || -z $selected ]]; then
    echo "no successful completed bench-compare run found for $tag at $sha" >&2
    hint
    exit 2
  fi
  run_id=$(jq -r '.databaseId' <<<"$selected")
  event=$(jq -r '.event' <<<"$selected")
  url=$(jq -r '.url' <<<"$selected")
  artifact="bench-compare-$sha"
  if $dry_run; then
    printf 'run: %s (%s, %s)\nartifact: %s\ncopy: benchmarks/compare/results/latest.json\ncopy: benchmarks/compare/results/latest*.txt\ncopy: website/src/data/competitor-benchmarks.json\n' "$run_id" "$event" "$url" "$artifact"
    return
  fi
  tmp=$(mktemp -d)
  temp_dirs+=("$tmp")
  if ! gh run download "$run_id" -R "$repo" -n "$artifact" -D "$tmp"; then
    echo "artifact $artifact is missing or expired" >&2
    hint
    exit 2
  fi
  file=$(find "$tmp" -type f -name latest.json -print -quit)
  if [[ -z $file ]]; then
    echo "artifact $artifact does not contain latest.json" >&2
    exit 1
  fi
  mkdir -p benchmarks/compare/results
  cp "$file" benchmarks/compare/results/latest.json
  while IFS= read -r file; do
    cp "$file" benchmarks/compare/results/
  done < <(find "$tmp" -type f -name 'latest*.txt' -print)
  cp benchmarks/compare/results/latest.json website/src/data/competitor-benchmarks.json
  printf 'refreshed results from run %s (%s): %s\n' "$run_id" "$event" "$url"
}

resolve_previous() {
  if [[ -n $prev_override ]]; then
    printf '%s\n' "$prev_override"
    return
  fi
  local found=false previous=
  while IFS= read -r candidate; do
    if $found; then
      printf '%s\n' "$candidate"
      return
    fi
    if [[ $candidate == "$tag" ]]; then
      found=true
    fi
  done < <(git tag -l 'v*' --sort=-v:refname)
  echo "could not find a previous v* tag before $tag; pass --prev" >&2
  return 1
}

parse() {
  local prev tmp prev_dir tag_dir sha cpu_model go_version cpu_count load1 prev_median published
  prev=$(resolve_previous)
  sha=$(git rev-parse "$tag^{commit}") || { echo "tag $tag is not available locally" >&2; exit 1; }
  if $dry_run; then
    printf 'previous tag: %s\ntag: %s (%s)\nworktrees: detached %s and %s\nbuild prev: go -C <prev-worktree> test -c -o <temp>/parser-prev.test ./pkg/sql/parser/\nbuild tag: go -C <tag-worktree> test -c -o <temp>/parser-tag.test ./pkg/sql/parser/\nrounds: %s (prev, tag interleaved; -test.count 1 per round)\n' "$prev" "$tag" "$sha" "$prev" "$tag" "$rounds"
    return
  fi
  tmp=$(mktemp -d)
  temp_dirs+=("$tmp")
  prev_dir="$tmp/prev"
  tag_dir="$tmp/tag"
  worktrees+=("$prev_dir" "$tag_dir")
  git worktree add --detach "$prev_dir" "$prev"
  git worktree add --detach "$tag_dir" "$tag"
  go -C "$prev_dir" test -c -o "$tmp/parser-prev.test" ./pkg/sql/parser/
  go -C "$tag_dir" test -c -o "$tmp/parser-tag.test" ./pkg/sql/parser/
  : >"$tmp/prev.txt"
  : >"$tmp/tag.txt"
  uptime
  if command -v sysctl >/dev/null 2>&1 && sysctl -n hw.ncpu >/dev/null 2>&1; then
    cpu_count=$(sysctl -n hw.ncpu)
  else
    cpu_count=$(nproc)
  fi
  load1=$(uptime | sed -E 's/.*load averages?:? ([0-9]+\.[0-9]+).*/\1/' | awk '{print $1}')
  if awk -v load="$load1" -v cpus="$cpu_count" 'BEGIN { exit !(load > cpus / 2) }'; then
    echo "warning: load1 $load1 exceeds half of $cpu_count CPUs" >&2
  fi
  for ((round = 1; round <= rounds; round++)); do
    "$tmp/parser-prev.test" -test.run '^$' -test.bench '^BenchmarkPerformanceBaseline$' -test.benchmem -test.count 1 >>"$tmp/prev.txt"
    "$tmp/parser-tag.test" -test.run '^$' -test.bench '^BenchmarkPerformanceBaseline$' -test.benchmem -test.count 1 >>"$tmp/tag.txt"
  done
  uptime
  prev_median=$(awk '$1 ~ /^BenchmarkPerformanceBaseline\/SimpleSelect-[0-9]+$/ && $4 == "ns/op" {print $3}' "$tmp/prev.txt" | sort -n | awk '{a[NR]=$1} END {if (NR%2) print a[(NR+1)/2]; else if (NR) print (a[NR/2]+a[NR/2+1])/2}')
  published=$(jq -r '.parse_ns_per_op' scripts/gen-readme-metrics/metrics.json)
  printf 'previous-tag SimpleSelect median: %s ns/op; published parse_ns_per_op: %s ns/op\n' "$prev_median" "$published"
  source scripts/perf/lib.sh
  cpu_model=$(perf_cpu_model | sed -E 's/ \([^()]*\)$//')
  go_version=$(go env GOVERSION | sed 's/^go//' | cut -d. -f1,2)
  go run ./scripts/gen-readme-metrics --record "$tmp/tag.txt" --tag "$tag" --version "${tag#v}" --hardware "$cpu_model" --go-version "$go_version"
}

verify() {
  go run ./scripts/gen-readme-metrics --check
  description=$(gh api "repos/$repo" --jq '.description // ""')
  go run ./scripts/gen-readme-metrics --claims --about "$description"
  if [[ -d website/node_modules ]]; then
    (cd website && npm run check:metrics)
  else
    echo "skip website metric check: website/node_modules is not installed"
  fi
}

case "$mode" in
  compare) compare ;;
  parse) parse ;;
  verify) verify ;;
  all)
    parse
    compare
    if $dry_run; then
      echo "dry-run: skipped verification commands"
    else
      verify
    fi
    ;;
esac
