#!/usr/bin/env bash
# check-dialect-migration.sh
#
# Counts `p.dialect ==` occurrences in production parser code (non-test).
# Fails the build if the count exceeds the agreed ceiling -- preventing new
# direct dialect string comparisons from being introduced.
#
# Contributors should prefer the capability-based helpers instead:
#   - p.Capabilities()            -- for feature-flag style gating
#   - p.IsPostgreSQL() / p.IsMySQL() / p.IsSQLServer() / etc.
#
# This enforces the strangler migration away from scattered `p.dialect == X`
# branches. The count is allowed to go DOWN (migration progress) but not UP.
#
# Usage:
#   scripts/check-dialect-migration.sh [ceiling]
#
# The ceiling defaults to the current post-Sprint-D baseline. Update the
# default below as migration progresses.

set -euo pipefail

CEILING="${1:-54}"  # Current baseline (Sprint D). Lower as migration progresses.

# Resolve repo root so the script works from any cwd (including CI).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PARSER_DIR="${REPO_ROOT}/pkg/sql/parser"

if [ ! -d "${PARSER_DIR}" ]; then
    echo "ERROR: parser directory not found: ${PARSER_DIR}" >&2
    exit 2
fi

# Count p.dialect == in non-test .go files in the parser package.
# Using `|| true` so a zero-match grep (exit 1) does not abort set -e.
MATCHES="$(grep -rn 'p\.dialect ==' "${PARSER_DIR}"/*.go 2>/dev/null | grep -v _test.go || true)"
COUNT="$(printf '%s\n' "${MATCHES}" | grep -c . || true)"

echo "Current p.dialect == sites: ${COUNT}"
echo "Allowed ceiling:            ${CEILING}"

if [ "${COUNT}" -gt "${CEILING}" ]; then
    echo ""
    echo "FAIL: New p.dialect == comparison introduced."
    echo "      Use p.Capabilities() or p.Is<Dialect>() helpers for new dialect gating."
    echo ""
    echo "Offending sites:"
    printf '%s\n' "${MATCHES}"
    exit 1
fi

if [ "${COUNT}" -lt "${CEILING}" ]; then
    echo ""
    echo "PASS: Migration progress -- current count is below ceiling."
    echo "      Consider lowering the default ceiling in this script to lock in the gain."
    exit 0
fi

echo "PASS: Dialect migration gate held at ceiling."
