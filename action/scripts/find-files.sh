#!/usr/bin/env bash
# find-files.sh — Locate SQL files matching the given glob pattern.
# Inputs (env): INPUT_FILES, INPUT_WORKING_DIRECTORY
# Outputs: file-count (GITHUB_OUTPUT), file list (RUNNER_TEMP/gosqlx-files.txt)
set -euo pipefail

WORKDIR="${INPUT_WORKING_DIRECTORY:-.}"

# Validate working-directory exists and is within repo
if [ ! -d "$WORKDIR" ]; then
  echo "::error::Working directory does not exist: $WORKDIR"
  exit 1
fi

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "$GITHUB_WORKSPACE")
WORKDIR_ABS=$(cd "$WORKDIR" && pwd)
if [[ "$WORKDIR_ABS" != "$REPO_ROOT"* ]]; then
  echo "::error::Working directory must be within repository: $WORKDIR_ABS"
  exit 1
fi

# Sanitize file pattern to prevent command injection
PATTERN="${INPUT_FILES:-**/*.sql}"
if echo "$PATTERN" | grep -qE '[;&|`$()]'; then
  echo "::error::File pattern contains invalid characters: $PATTERN"
  exit 1
fi

echo "Finding SQL files matching pattern: $PATTERN"

if [[ "$PATTERN" == "**/*.sql" ]]; then
  FILES=$(find . -type f -name "*.sql" 2>/dev/null | sort || true)
elif [[ "$PATTERN" == "*.sql" ]]; then
  FILES=$(find . -maxdepth 1 -type f -name "*.sql" 2>/dev/null | sort || true)
elif [[ "$PATTERN" =~ ^(.+)/\*\*/(.+)$ ]]; then
  BASE_DIR="${BASH_REMATCH[1]}"
  FILE_PATTERN="${BASH_REMATCH[2]}"
  FILES=$(find "./$BASE_DIR" -type f -name "$FILE_PATTERN" 2>/dev/null | sort || true)
else
  FILES=$(find . -type f -path "./$PATTERN" 2>/dev/null | sort || true)
fi

if [ -z "$FILES" ]; then
  echo "WARNING: No SQL files found matching pattern: $PATTERN"
  echo "file-count=0" >> "$GITHUB_OUTPUT"
  exit 0
fi

FILE_COUNT=$(echo "$FILES" | wc -l)
echo "Found $FILE_COUNT SQL file(s)"
echo "$FILES" | head -10
if [ "$FILE_COUNT" -gt 10 ]; then
  echo "... and $((FILE_COUNT - 10)) more files"
fi

echo "$FILES" > "$RUNNER_TEMP/gosqlx-files.txt"
echo "file-count=$FILE_COUNT" >> "$GITHUB_OUTPUT"
