#!/usr/bin/env bash
# Regenerates format-before-after.png and format-before-after-dark.png from the
# REAL formatter output (default flags), from the repository root:
#
#   .github/assets/build-format-image.sh
#
# Requires: go, python3 with Pillow (pip install pillow).
# Also writes demo.formatted.sql so formatter drift shows up in `git diff`.
set -euo pipefail

cd "$(dirname "$0")/../.."
A=.github/assets
go run ./cmd/gosqlx format "$A/demo.sql" > "$A/demo.formatted.sql"
python3 "$A/render-format-image.py" "$A/demo.sql" "$A/demo.formatted.sql" "$A"
