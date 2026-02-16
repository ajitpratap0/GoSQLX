#!/usr/bin/env bash
# GoSQLX GitHub Action Entrypoint — thin wrapper around `gosqlx action`.
# All logic now lives in the Go CLI (cmd/gosqlx/cmd/action.go).
set -euo pipefail

GOSQLX_BIN="${GOSQLX_BIN:-gosqlx}"

# Resolve gosqlx binary
if ! command -v "$GOSQLX_BIN" &>/dev/null; then
  if [ -x "$HOME/go/bin/gosqlx" ]; then
    GOSQLX_BIN="$HOME/go/bin/gosqlx"
  elif [ -x "./gosqlx" ]; then
    GOSQLX_BIN="./gosqlx"
  else
    echo "::error::gosqlx binary not found. Build it first: go build -o gosqlx ./cmd/gosqlx"
    exit 1
  fi
fi

exec "$GOSQLX_BIN" action
