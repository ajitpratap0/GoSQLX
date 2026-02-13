#!/usr/bin/env bash
# GoSQLX GitHub Action Entrypoint
# Finds SQL files, runs gosqlx lint + validate, outputs GitHub Actions annotations.
#
# Environment variables (set by action.yml or manually for local testing):
#   SQL_FILES    - glob pattern for SQL files (default: **/*.sql)
#   RULES        - comma-separated lint rules (optional)
#   SEVERITY     - severity threshold: error, warning, info (default: warning)
#   CONFIG       - path to .gosqlx.yml config file (optional)
#   GOSQLX_BIN   - path to gosqlx binary (default: gosqlx)

set -euo pipefail

SQL_FILES="${SQL_FILES:-**/*.sql}"
RULES="${RULES:-}"
SEVERITY="${SEVERITY:-warning}"
CONFIG="${CONFIG:-}"
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

echo "Using gosqlx: $GOSQLX_BIN"
echo "SQL file pattern: $SQL_FILES"
echo "Severity threshold: $SEVERITY"

# --- Find SQL files ---
FILES=()
if [[ "$SQL_FILES" == "**/*.sql" ]]; then
  while IFS= read -r -d '' f; do
    FILES+=("$f")
  done < <(find . -type f -name "*.sql" -print0 2>/dev/null | sort -z)
elif [[ "$SQL_FILES" == "*.sql" ]]; then
  while IFS= read -r -d '' f; do
    FILES+=("$f")
  done < <(find . -maxdepth 1 -type f -name "*.sql" -print0 2>/dev/null | sort -z)
else
  # Use find with sanitized pattern to avoid command injection
  shopt -s globstar nullglob 2>/dev/null || true
  # Sanitize: only allow safe glob characters
  SAFE_PATTERN=$(echo "$SQL_FILES" | sed 's/[^a-zA-Z0-9_.*/?\/\-]//g')
  while IFS= read -r -d '' f; do
    FILES+=("$f")
  done < <(find . -type f -path "./$SAFE_PATTERN" -print0 2>/dev/null | sort -z)
fi

if [ ${#FILES[@]} -eq 0 ]; then
  echo "::warning::No SQL files found matching pattern: $SQL_FILES"
  exit 0
fi

echo "Found ${#FILES[@]} SQL file(s)"

# --- Build common flags ---
LINT_FLAGS=()
VALIDATE_FLAGS=()

if [ -n "$CONFIG" ] && [ -f "$CONFIG" ]; then
  echo "Using config: $CONFIG"
  export GOSQLX_CONFIG="$CONFIG"
fi

if [ -n "$RULES" ]; then
  # Pass rules as repeated --rule flags if supported, otherwise log
  IFS=',' read -ra RULE_LIST <<< "$RULES"
  for rule in "${RULE_LIST[@]}"; do
    LINT_FLAGS+=(--rule "$(echo "$rule" | xargs)")
  done
fi

LINT_ERRORS=0
LINT_WARNINGS=0
VALIDATE_ERRORS=0
TOTAL_VALID=0
EXIT_CODE=0

# --- Run lint + validate on each file ---
for file in "${FILES[@]}"; do
  # Strip leading ./
  display_file="${file#./}"

  # --- Validate ---
  if output=$("$GOSQLX_BIN" validate "$file" 2>&1); then
    TOTAL_VALID=$((TOTAL_VALID + 1))
  else
    VALIDATE_ERRORS=$((VALIDATE_ERRORS + 1))
    # Parse output for line-level annotations if possible
    while IFS= read -r line; do
      if [[ "$line" =~ [Ll]ine[[:space:]]*([0-9]+) ]]; then
        lineno="${BASH_REMATCH[1]}"
        echo "::error file=${display_file},line=${lineno}::${line}"
      else
        echo "::error file=${display_file}::${line}"
      fi
    done <<< "$output"
  fi

  # --- Lint ---
  lint_output=$("$GOSQLX_BIN" lint "$file" 2>&1) || true
  if [ -n "$lint_output" ] && ! echo "$lint_output" | grep -qi "no violations\|no issues\|0 violation"; then
    while IFS= read -r line; do
      if [ -z "$line" ]; then continue; fi

      # Determine annotation level
      level="warning"
      if echo "$line" | grep -qi "error"; then
        level="error"
        LINT_ERRORS=$((LINT_ERRORS + 1))
      elif echo "$line" | grep -qi "warning"; then
        LINT_WARNINGS=$((LINT_WARNINGS + 1))
      else
        level="notice"
      fi

      # Extract line number if present
      if [[ "$line" =~ [Ll]ine[[:space:]]*([0-9]+) ]]; then
        lineno="${BASH_REMATCH[1]}"
        echo "::${level} file=${display_file},line=${lineno}::${line}"
      else
        echo "::${level} file=${display_file}::${line}"
      fi
    done <<< "$lint_output"
  fi
done

# --- Summary ---
echo ""
echo "=============================="
echo "  GoSQLX Results Summary"
echo "=============================="
echo "  Files scanned:      ${#FILES[@]}"
echo "  Validation passed:  ${TOTAL_VALID}"
echo "  Validation errors:  ${VALIDATE_ERRORS}"
echo "  Lint errors:        ${LINT_ERRORS}"
echo "  Lint warnings:      ${LINT_WARNINGS}"
echo "=============================="

# Write GitHub Actions step summary if available
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat >> "$GITHUB_STEP_SUMMARY" <<EOF

## GoSQLX Lint + Validation Results

| Metric | Count |
|--------|-------|
| Files Scanned | ${#FILES[@]} |
| Validation Passed | ${TOTAL_VALID} |
| Validation Errors | ${VALIDATE_ERRORS} |
| Lint Errors | ${LINT_ERRORS} |
| Lint Warnings | ${LINT_WARNINGS} |
EOF
fi

# --- Exit code based on severity threshold ---
case "$SEVERITY" in
  error)
    [ $VALIDATE_ERRORS -gt 0 ] || [ $LINT_ERRORS -gt 0 ] && EXIT_CODE=1
    ;;
  warning)
    [ $VALIDATE_ERRORS -gt 0 ] || [ $LINT_ERRORS -gt 0 ] || [ $LINT_WARNINGS -gt 0 ] && EXIT_CODE=1
    ;;
  info)
    # Fail on anything
    [ $VALIDATE_ERRORS -gt 0 ] || [ $LINT_ERRORS -gt 0 ] || [ $LINT_WARNINGS -gt 0 ] && EXIT_CODE=1
    ;;
esac

exit $EXIT_CODE
