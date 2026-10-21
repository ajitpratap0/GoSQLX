#!/bin/sh
# GoSQLX PostToolUse hook: validate a .sql file after Claude writes or edits it.
#
# Best-effort by design: it never blocks a tool call. It exits 0 silently when
# the edited file is not a .sql file, when the gosqlx CLI is not installed, or
# when the hook input cannot be read. When gosqlx reports a syntax error it
# exits 2 so the message on stderr is shown to Claude (the edit has already
# been applied; PostToolUse cannot undo it).
#
# Disable it with GOSQLX_HOOK_DISABLE=1.

[ "${GOSQLX_HOOK_DISABLE:-0}" = "1" ] && exit 0
command -v gosqlx >/dev/null 2>&1 || exit 0

input=$(cat 2>/dev/null) || exit 0
[ -n "$input" ] || exit 0

file=""
if command -v jq >/dev/null 2>&1; then
  file=$(printf '%s' "$input" | jq -r '.tool_input.file_path // empty' 2>/dev/null) || exit 0
else
  # Fallback without jq: take the last "file_path":"..." value in the input
  # (the leading .* is greedy). Give up on paths containing JSON escapes
  # rather than risk reading the wrong file.
  file=$(printf '%s' "$input" | tr -d '\n' |
    sed -n 's/.*"file_path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  case $file in *\\*) exit 0 ;; esac
fi

[ -n "$file" ] || exit 0
case $file in
  *.sql|*.SQL) ;;
  *) exit 0 ;;
esac
[ -f "$file" ] || exit 0

if output=$(gosqlx validate -- "$file" 2>&1); then
  exit 0
fi

{
  printf 'GoSQLX validation failed for %s:\n' "$file"
  printf '%s\n' "$output" | head -n 40
  printf 'If this file targets a specific dialect, re-check with: gosqlx validate --dialect <dialect> "%s"\n' "$file"
} >&2
exit 2
