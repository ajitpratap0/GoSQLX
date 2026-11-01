#!/usr/bin/env bash
# Readable diff mode for the behaviour goldens (testdata/goldens).
#
# The committed goldens hold one hash per corpus file and column, so a
# mismatch names the cell but not the statement. This script dumps every
# golden output of a base revision (default origin/main) from a temporary
# git worktree, then runs the goldens of the working tree against that dump:
# each mismatching cell prints its first differing statements with the input
# SQL and a line diff of the output.
#
# Usage: scripts/goldens-diff.sh [BASE_REF]    (or: task goldens:diff BASE=ref)

set -euo pipefail

base="${1:-origin/main}"
root="$(git rev-parse --show-toplevel)"
pkgs=(./pkg/sql/tokenizer ./pkg/sql/parser ./pkg/formatter ./pkg/fingerprint
      ./pkg/linter ./pkg/sql/security ./pkg/transpiler ./pkg/lsp)

tmp="$(mktemp -d "${TMPDIR:-/tmp}/goldens-diff.XXXXXX")"
cleanup() {
  git -C "$root" worktree remove --force "$tmp/base" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

git -C "$root" worktree add --detach --quiet "$tmp/base" "$base"
echo "goldens-diff: dumping golden outputs of $base ($(git -C "$root" rev-parse --short "$base"))"
# Only the dump matters here; the base run's own pass/fail is irrelevant.
(cd "$tmp/base" && go test -count=1 -run '^TestGolden' "${pkgs[@]}" \
  -args -goldens.dump="$tmp/dump" >/dev/null 2>&1) || true
if [ ! -d "$tmp/dump" ]; then
  echo "goldens-diff: $base produced no golden dump (does it predate the goldens?)" >&2
  exit 2
fi

echo "goldens-diff: comparing the working tree against it"
cd "$root"
go test -count=1 -run '^TestGolden' "${pkgs[@]}" -args -goldens.base="$tmp/dump"
