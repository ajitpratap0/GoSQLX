#!/usr/bin/env bash
# validate.sh — Run gosqlx validate on discovered SQL files.
# Inputs (env): INPUT_CONFIG, INPUT_DIALECT, INPUT_STRICT, INPUT_SHOW_STATS,
#               INPUT_FAIL_ON_ERROR, INPUT_TIMEOUT
# Outputs: validated-files, invalid-files, validation-time (GITHUB_OUTPUT)
set -euo pipefail

TIMEOUT="${INPUT_TIMEOUT:-600}"

# Build validation command
CMD="$HOME/go/bin/gosqlx validate"

if [ -n "${INPUT_CONFIG:-}" ] && [ -f "$INPUT_CONFIG" ]; then
  echo "Using config file: $INPUT_CONFIG"
  export GOSQLX_CONFIG="$INPUT_CONFIG"
elif [ -n "${INPUT_CONFIG:-}" ]; then
  echo "::warning::Config file not found: $INPUT_CONFIG"
fi

DIALECT="${INPUT_DIALECT:-}"
if [ -n "$DIALECT" ]; then
  if [[ "$DIALECT" =~ ^(postgresql|mysql|sqlserver|oracle|sqlite)$ ]]; then
    CMD="$CMD --dialect $DIALECT"
  else
    echo "::warning::Invalid dialect '$DIALECT', skipping dialect flag"
  fi
fi

if [ "${INPUT_STRICT:-false}" = "true" ]; then
  CMD="$CMD --strict"
fi

if [ "${INPUT_SHOW_STATS:-false}" = "true" ]; then
  CMD="$CMD --stats"
fi

CMD="$CMD --verbose"

START_TIME=$(date +%s%3N)
VALIDATED=0
INVALID=0

while IFS= read -r file; do
  SAFE_FILE="${file//[^a-zA-Z0-9\/._-]/}"
  echo "Validating: $file"

  if timeout "$TIMEOUT" $CMD "$file" 2>&1; then
    echo "✓ Valid: $file"
    VALIDATED=$((VALIDATED + 1))
  else
    EXIT=$?
    if [ "$EXIT" -eq 124 ]; then
      echo "::error file=$SAFE_FILE::Validation timed out after ${TIMEOUT}s"
    else
      echo "::error file=$SAFE_FILE::SQL validation failed"
    fi
    echo "✗ Invalid: $file"
    INVALID=$((INVALID + 1))
  fi
done < "$RUNNER_TEMP/gosqlx-files.txt"

END_TIME=$(date +%s%3N)
DURATION=$((END_TIME - START_TIME))

echo "::notice::Validation complete: $VALIDATED valid, $INVALID invalid files (${DURATION}ms)"

echo "validated-files=$VALIDATED" >> "$GITHUB_OUTPUT"
echo "invalid-files=$INVALID" >> "$GITHUB_OUTPUT"
echo "validation-time=$DURATION" >> "$GITHUB_OUTPUT"

# Job summary
{
  echo "## SQL Validation Results"
  echo ""
  echo "| Metric | Value |"
  echo "|--------|-------|"
  echo "| Files Validated | $VALIDATED |"
  echo "| Validation Errors | $INVALID |"
  echo "| Duration | ${DURATION}ms |"
  echo "| Throughput | $(awk "BEGIN {printf \"%.2f\", $VALIDATED * 1000 / ($DURATION + 1)}") files/sec |"
} >> "$GITHUB_STEP_SUMMARY"

if [ "$INVALID" -gt 0 ] && [ "${INPUT_FAIL_ON_ERROR:-true}" = "true" ]; then
  echo "::error::Validation failed with $INVALID invalid file(s)"
  exit 1
fi
