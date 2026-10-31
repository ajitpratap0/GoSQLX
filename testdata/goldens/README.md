# Behaviour goldens

These files pin the observable output of GoSQLX over the whole benchmark
corpus (`internal/benchcorpus`, pinned by `testdata/bench/MANIFEST.sha256`),
so performance work cannot change behaviour silently.

| Golden | Test | Rows x columns | What each cell covers |
|---|---|---|---|
| `tokens` | `pkg/sql/tokenizer` `TestGoldenTokens` | corpus file x 11 dialects | every token: type, value, span, quote, Long, Word |
| `parse` | `pkg/sql/parser` `TestGoldenParse` | corpus file x 11 dialects | `ParseWithDialect` `SQL()` or error code, location, hint and message; every AST `models.Location`; `ValidateWithDialect` |
| `format` | `pkg/formatter` `TestGoldenFormat` | corpus file x 6 renderings | `FormatWithDialect` (2 option sets), `FormatASTChecked` compact, readable, lower, compact without dialect |
| `fingerprint` | `pkg/fingerprint` `TestGoldenFingerprint` | corpus file x 2 | `Normalize`, `Fingerprint` |
| `lint` | `pkg/linter` `TestGoldenLint` | corpus file x 2 | every violation of `LintWithDialect` (own dialect) and `Lint` |
| `security` | `pkg/sql/security` `TestGoldenSecurity` | corpus file x 2 | `ScanSQL` and `Scan` (AST) findings and counts |
| `transpile` | `pkg/transpiler` `TestGoldenTranspile` | corpus file x 9 targets | `Transpile` from the corpus dialect to each target, identity included |
| `lsp` | `pkg/lsp` `TestGoldenLSP` | document@dialect x 3 | published diagnostics, decoded semantic tokens, document symbols |

Each line is `<row> <statements> <hash per column>`; a hash covers the full
output of every statement of the row, and `=` means "same as the column to
the left".

- Run: `task goldens` (they also run in `task test` and `task test:race`).
- Inspect a mismatch: `task goldens:diff BASE=origin/main` dumps the base
  revision's outputs and prints, for each changed cell, the first differing
  statements with their input and a line diff.
- Accept an intended change: `task goldens:update`, then list every changed
  cell and the reason in the PR (AC-STD 2).
