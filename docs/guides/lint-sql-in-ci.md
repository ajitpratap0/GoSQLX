# Lint SQL in CI

This guide shows how to lint and validate SQL files in continuous integration with GoSQLX, so a pull request with broken or badly formatted SQL fails before it is merged. It covers GitHub Actions with inline annotations, a plain-shell setup for any CI system, and a Go test that applies every built-in rule.

Pick one of three setups:

| Setup | Rules applied | Best for |
|---|---|---|
| `gosqlx action` in GitHub Actions | Syntax validation plus the style rules L001 to L010, with annotations on the pull request diff | GitHub repositories |
| `gosqlx validate`, `lint` and `format --check` | The same checks, plain exit codes | GitLab, CircleCI, Jenkins, pre-commit hooks |
| A Go test using `gosqlx.Lint` | Syntax validation plus all 30 rules (L001 to L030), including safety and performance rules | Go projects that already run `go test` in CI |

## Pin the version

Install a specific release so that a new GoSQLX version cannot change your CI results overnight:

```bash
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@v1.15.0
```

Bump the version deliberately, in its own pull request, the same way you would bump any other linter.

## GitHub Actions

`gosqlx action` finds SQL files by glob, validates and lints each one, and prints the results as GitHub annotations, so problems show up inline on the pull request diff.

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
      - name: Install gosqlx
        run: go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@v1.15.0
      - name: Validate and lint SQL
        run: gosqlx action --files '**/*.sql' --severity warning
      - name: Check formatting
        run: gosqlx format --check $(git ls-files '*.sql')
```

What the flags do:

- `--files` is a glob. `**` matches any number of directories.
- `--severity` sets the level that fails the job. With `warning`, warnings and errors fail; with `error`, warnings are annotated but the job passes. Syntax errors always fail.
- `--rules L001,L007` limits linting to the listed rules, which is a gentle way to adopt the linter on an existing codebase.

A failing run prints annotations such as:

```text
::warning file=db/migrations/001.sql,line=1::[L007] Keyword 'select' should be uppercase: 'SELECT'
::error file=db/queries/report.sql,line=1::Error E2002 at line 1, column 8: expected column expression, got FROM
```

followed by a summary and a non-zero exit status.

The GoSQLX repository also publishes a composite action, `ajitpratap0/GoSQLX@v1`, that installs the CLI for you. Its `validate` and `format-check` inputs cover syntax and formatting:

```yaml
      - uses: ajitpratap0/GoSQLX@v1
        with:
          files: '**/*.sql'
          validate: true
          format-check: true
```

## Any CI system

The same checks are three commands that exit with a non-zero status on failure:

```bash
gosqlx validate -r --dialect postgresql ./sql      # syntax
gosqlx lint -r ./sql                               # style rules L001 to L010
gosqlx format --check $(git ls-files '*.sql')      # formatting
```

Useful flags:

- `validate --dialect` and `lint --dialect` select the SQL dialect: `postgresql`, `mysql`, `mariadb`, `sqlserver`, `oracle`, `sqlite`, `snowflake` or `clickhouse`.
- `lint --security` also runs the SQL injection scanner; see [Detect SQL injection in Go](detect-sql-injection-in-go.md).
- `lint --max-length 120` sets the line length for rule L005.
- `validate --output-format sarif --output-file results.sarif` writes SARIF for code scanning dashboards.

The same commands work as a pre-commit hook, which catches problems before they reach CI:

```bash
#!/bin/sh
# .git/hooks/pre-commit
files=$(git diff --cached --name-only --diff-filter=ACM -- '*.sql')
[ -z "$files" ] && exit 0
gosqlx validate $files && gosqlx lint $files
```

## A Go test with all 30 rules

The CLI commands above run the style rules. `gosqlx.Lint` in the Go library runs all 30 built-in rules, including safety rules (such as a `DELETE` without `WHERE`) and performance rules (such as `SELECT *` or a `LIKE` pattern with a leading wildcard). If your project is written in Go, a test is the simplest way to apply them, because CI already runs `go test`:

```go
package sqlcheck_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
)

// sqlRoot is the directory that holds the SQL files to check.
const sqlRoot = "../db"

func TestSQLFiles(t *testing.T) {
	err := filepath.WalkDir(sqlRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".sql") {
			return nil
		}
		t.Run(path, func(t *testing.T) {
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			sql := string(src)

			if err := gosqlx.Validate(sql); err != nil {
				t.Fatalf("invalid SQL: %v", err)
			}

			result, err := gosqlx.Lint(sql)
			if err != nil {
				t.Fatalf("lint: %v", err)
			}
			for _, v := range result.Violations {
				if v.Severity == linter.SeverityInfo {
					continue // report errors and warnings only
				}
				t.Errorf("%s:%d [%s] %s: %s", path, v.Location.Line, v.Rule, v.RuleName, v.Message)
			}
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
```

A failing file produces one subtest failure per file, with each violation on its own line:

```text
--- FAIL: TestSQLFiles/../db/q/bad.sql
    sql_lint_test.go:44: ../db/q/bad.sql:1 [L007] Keyword Case Consistency: Keyword 'select' should be uppercase: 'SELECT'
    sql_lint_test.go:44: ../db/q/bad.sql:0 [L016] Select Star: SELECT * fetches all columns; specify only needed columns
```

Rules that look at the whole statement, rather than a single line, report line `0`.

To apply only some rules or change their settings, build a linter from `pkg/linter` and the rule packages instead of calling `gosqlx.Lint`; the [linter package reference](../api/linter.md) shows how.

## Adopting the linter on an existing codebase

Turning on every rule at once on a large SQL directory usually produces hundreds of findings. A gradual path:

1. Start with validation only (`gosqlx validate`). Broken SQL is never intentional.
2. Add `gosqlx format --check` after one pull request that runs `gosqlx format -i` over the whole tree. Note that the formatter drops SQL comments; see [Format SQL in Go](format-sql-in-go.md#comments-are-not-preserved).
3. Enable lint rules a few at a time with `--rules`, fixing existing findings as you go. `gosqlx lint --auto-fix` fixes the whitespace and keyword-case rules automatically.

## Next steps

- [Linting Rules](../LINTING_RULES.md): the style rules in detail, with examples and fixes
- [CLI Guide](../CLI_GUIDE.md): every command and flag
- [Tutorial: SQL validator in CI/CD](../tutorials/01-sql-validator-cicd.md): build your own validator binary
- [Configuration](../CONFIGURATION.md): set defaults in `.gosqlx.yml`
