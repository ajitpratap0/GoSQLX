---
title: "Linting SQL in CI with a single Go binary"
description: "Validate, lint and format-check .sql files in CI with one static Go binary: no Python runtime, pinned versions, PR annotations and gradual adoption."
date: 2026-10-18
tags: [sql, ci, linting, github-actions]
---

Most codebases treat SQL files as second-class code. Application code goes through a compiler, a linter and a formatter on every pull request, while migrations and report queries are merged on the strength of a reviewer's eyes. The first sign of a typo is often a failed deploy.

This post shows how to give SQL files the same treatment with one static Go binary, and why the shape of the tool matters as much as its rules.

## Why a single binary

SQL linters exist in several ecosystems. The most popular, SQLFluff, is a Python package with a rich rule set. In CI, a Python linter means a Python runtime, a virtual environment or a container image, and a dependency tree that has to be cached and kept in sync with developers' machines.

A Go binary removes most of that:

- **One file.** `go install` produces a single executable with no runtime dependencies. In CI it is one cached download.
- **Exact pinning.** `@v1.15.0` in the install command pins every rule and every parser decision. A new release cannot change your build overnight.
- **Same binary everywhere.** Developers run the same version in a pre-commit hook that CI runs on the pull request, so "passes locally, fails in CI" stops happening.
- **Fast start-up.** There is no interpreter to boot, which matters when a hook runs on every commit.

GoSQLX is a SQL parser first, supporting eight dialects, so validation means a real parse and lint rules can look at the syntax tree rather than only at lines of text. If you are coming from SQLFluff, the [migration guide](/docs/migration/from-sqlfluff/) maps its rules and configuration to GoSQLX.

## Three checks, three exit codes

Linting SQL in CI is really three separate checks, and it helps to keep them apart because they fail for different reasons:

| Check | Command | Fails when |
|---|---|---|
| Syntax | `gosqlx validate` | A file does not parse in the chosen dialect |
| Style | `gosqlx lint` | A rule reports a violation, such as lowercase keywords or trailing whitespace |
| Formatting | `gosqlx format --check` | A file differs from the formatter's output |

Each exits with a non-zero status on failure, so they work in any CI system:

```bash
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@v1.15.0

gosqlx validate -r --dialect postgresql ./sql
gosqlx lint -r ./sql
gosqlx format --check $(git ls-files '*.sql')
```

A syntax error points at the exact position and links to the error code reference:

```text
sql/bad.sql: parsing failed: Error E2002 at line 1, column 16: expected identifier, got WHERE

Hint: expected identifier here
Help: https://github.com/ajitpratap0/GoSQLX/blob/main/docs/ERROR_CODES.md#E2002
```

A lint violation shows the rule, the line and column, and a suggested fix:

```text
[L007] Keyword Case Consistency at line 1, column 1
  Severity: warning
  Keyword 'select' should be uppercase: 'SELECT'

     1 | select id, name from users where active = true
       | ^

  Suggestion: Change 'select' to 'SELECT'
```

## Annotations on the pull request

On GitHub, `gosqlx action` combines validation and linting and prints its findings as workflow commands, so they appear inline on the pull request diff rather than buried in a log:

```yaml
# .github/workflows/sql.yml
name: SQL
on:
  pull_request:
    paths: ['**/*.sql']
permissions:
  contents: read
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.26'
      - run: go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@v1.15.0
      - run: gosqlx action --files '**/*.sql' --severity warning
      - run: gosqlx format --check $(git ls-files '*.sql')
```

The output is a stream of annotations followed by a summary:

```text
::warning file=sql/a.sql,line=1::[L007] Keyword 'select' should be uppercase: 'SELECT'
::error file=sql/bad.sql,line=1::Error E2002 at line 1, column 16: expected identifier, got WHERE
```

`--severity` decides what fails the job: with `warning`, warnings and errors both fail; with `error`, warnings are annotated but the job passes. Syntax errors always fail. If you prefer code scanning dashboards, `gosqlx validate --output-format sarif --output-file results.sarif` writes SARIF instead.

## Going further in a Go project

The CLI applies the style rules (L001 to L010). The Go library exposes all 30 built-in rules through `gosqlx.Lint`, including safety rules such as a `DELETE` without a `WHERE` clause and performance rules such as `SELECT *`. If your project is written in Go, the simplest way to apply them is a test, because CI already runs `go test`:

```go
func TestSQLFiles(t *testing.T) {
	files, err := filepath.Glob("../db/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		t.Run(path, func(t *testing.T) {
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			result, err := gosqlx.Lint(string(src))
			if err != nil {
				t.Fatalf("lint: %v", err)
			}
			for _, v := range result.Violations {
				if v.Severity == linter.SeverityInfo {
					continue
				}
				t.Errorf("%s:%d [%s] %s", path, v.Location.Line, v.Rule, v.Message)
			}
		})
	}
}
```

The [Lint SQL in CI guide](/docs/guides/lint-sql-in-ci/) has a complete version that walks nested directories and validates syntax first.

## Adopting it on an existing codebase

Turning every rule on at once over a large SQL directory produces hundreds of findings and a pull request nobody wants to review. A gradual path works better:

1. **Start with `validate`.** Broken SQL is never intentional, so this check has no false positives worth arguing about.
2. **Format once, then enforce.** Run `gosqlx format -i` over the tree in one dedicated pull request, then add `format --check`. Note that the formatter drops SQL comments, so review that pull request with care.
3. **Add lint rules a few at a time** with `gosqlx action --rules L001,L007`, fixing existing findings as you go. `gosqlx lint --auto-fix` fixes the whitespace and keyword-case rules automatically.
4. **Add the security scanner** with `gosqlx lint --security` once the style noise is gone. The [next article](/blog/blocking-sql-injection-with-ast-analysis/) explains what it detects.

Further reading:

- [Linting rules reference](/docs/reference/linting-rules/): every rule with examples
- [CLI guide](/docs/cli-guide/): all commands and flags
- [Configuration](/docs/reference/configuration/): set defaults in `.gosqlx.yml`
