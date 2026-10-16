# Detect SQL injection in Go

This guide shows how to detect SQL injection patterns in Go with the GoSQLX security scanner: scan a SQL string or a parsed AST, read findings by severity, pick a threshold that suits your service, and run the same checks on `.sql` files from the command line.

## Detection is not prevention

Parameterized queries (`db.QueryContext(ctx, "... WHERE id = $1", id)`) prevent SQL injection. A scanner cannot make string-built SQL safe. What it can do is flag queries that already look tampered with, which is useful for:

- auditing SQL that reaches a proxy, gateway or query log
- reviewing SQL files and generated queries in CI
- adding a second check in front of tools that accept raw SQL, such as admin consoles or AI agents

Keep parameterized queries and least-privilege database roles as the real defence, and use the scanner as an extra layer.

## Install

```bash
go get github.com/ajitpratap0/GoSQLX
```

## Scan a SQL string

`security.NewScanner()` returns a scanner that is safe to share between goroutines. `ScanSQL` checks raw SQL text with pattern matching, so it also works on SQL that does not parse.

```go
package main

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/security"
)

func main() {
	scanner := security.NewScanner()

	inputs := []string{
		"SELECT * FROM users WHERE id = 1 OR 1=1",
		"SELECT name FROM products WHERE id = 5 UNION SELECT password FROM users",
		"SELECT * FROM users WHERE id = 1; DROP TABLE users; --",
		"SELECT * FROM users WHERE name = 'x' AND SLEEP(5)",
		"SELECT id, email FROM users WHERE id = $1",
	}

	for _, sql := range inputs {
		result := scanner.ScanSQL(sql)
		if result.IsClean() {
			fmt.Println("clean:", sql)
			continue
		}
		for _, f := range result.Findings {
			fmt.Printf("[%s] %s: %s\n", f.Severity, f.Pattern, f.Description)
		}
	}
}
```

Output:

```text
[CRITICAL] TAUTOLOGY: Always-true condition detected (tautology): 1=1
[HIGH] UNION_GENERIC: Pattern detected: UNION SELECT
[MEDIUM] COMMENT_BYPASS: Trailing SQL comment may indicate injection
[HIGH] COMMENT_BYPASS: Statement terminator followed by comment
[CRITICAL] STACKED_QUERY: Pattern detected: ; DROP
[HIGH] TIME_BASED: Pattern detected: SLEEP(
clean: SELECT id, email FROM users WHERE id = $1
```

The parameterized query at the end is clean.

## What the scanner looks for

Each finding has a `Pattern` that names the technique:

| Pattern | What it catches |
|---|---|
| `TAUTOLOGY` | Always-true conditions such as `OR 1=1` or `OR 'a'='a'` |
| `UNION_GENERIC`, `UNION_BASED`, `UNION_INJECTION` | `UNION SELECT` used to pull data from other tables; system-table access and `NULL` padding raise the severity |
| `STACKED_QUERY` | A second, destructive statement such as `; DROP TABLE users` |
| `COMMENT_BYPASS` | A trailing `--`, `#` or `/* */` that cuts off the rest of the query |
| `TIME_BASED` | Delay functions for blind injection: `SLEEP`, `pg_sleep`, `WAITFOR DELAY`, `BENCHMARK` |
| `BOOLEAN_BASED` | Conditional logic used to extract data one bit at a time |
| `OUT_OF_BAND` | Exfiltration functions such as `xp_cmdshell`, `LOAD_FILE` and `UTL_HTTP` |
| `DANGEROUS_FUNCTION` | Dynamic SQL execution such as `EXEC`, `sp_executesql` and `PREPARE ... FROM` |

The [security package reference](../api/security.md) lists every pattern and severity.

## Read a finding

A `security.Finding` carries more than the pattern:

```go
for _, f := range result.Findings {
	fmt.Println(f.Severity)    // CRITICAL, HIGH, MEDIUM or LOW
	fmt.Println(f.Pattern)     // e.g. TAUTOLOGY
	fmt.Println(f.Description) // what was matched
	fmt.Println(f.Risk)        // the potential impact
	fmt.Println(f.Suggestion)  // how to fix it
}
```

`ScanResult` also has per-severity counts (`CriticalCount`, `HighCount`, `MediumCount`, `LowCount`, `TotalCount`) and three helpers for quick decisions: `IsClean()`, `HasCritical()` and `HasHighOrAbove()`. Findings and results have JSON tags, so you can log them as structured data.

## Scan a parsed query

If you already parse the SQL, scan the AST with `Scan`. The AST scan understands the query structure, for example a tautology inside a `WHERE` clause:

```go
tree, err := gosqlx.Parse("SELECT * FROM users WHERE username = 'admin' OR 'a'='a'")
if err != nil {
	return err
}
result := scanner.Scan(tree)
fmt.Println(result.HasHighOrAbove()) // true
```

`ScanSQL` works on any string, including fragments and SQL that does not parse; `Scan` needs a parsed `*ast.AST`. Using both is reasonable when you have the AST anyway.

## Choose a threshold

`NewScannerWithSeverity` drops findings below a minimum severity, which keeps noisy `LOW` and `MEDIUM` findings out of alerts:

```go
scanner, err := security.NewScannerWithSeverity(security.SeverityHigh)
if err != nil {
	return err
}
```

A typical policy for a service that accepts raw SQL:

```go
result := scanner.ScanSQL(sql)
switch {
case result.HasCritical():
	return fmt.Errorf("query rejected: %d critical finding(s)", result.CriticalCount)
case result.HasHighOrAbove():
	logger.Warn("suspicious query", "findings", result.Findings)
}
```

Expect false positives on legitimate SQL that uses the same shapes, such as a reporting query with `UNION SELECT` or a test fixture with `WHERE 1=1`. Start by logging, look at what fires on your real traffic, then decide what to block.

## Scan SQL files from the CLI

`gosqlx lint --security` runs the scanner on files alongside the style rules:

```bash
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest

gosqlx lint --security queries/report.sql
```

```text
  [CRITICAL] queries/report.sql:0:0 - OR condition with tautology detected (e.g., OR 1=1) (TAUTOLOGY)
  [CRITICAL] queries/report.sql:0:0 - Always-true condition detected (tautology) (TAUTOLOGY)
Error: 2 security finding(s) detected
```

The command exits with a non-zero status when it finds issues, so it can gate a CI job. See [Lint SQL in CI](lint-sql-in-ci.md).

## Next steps

- [Security overview](../SECURITY.md): the security model of GoSQLX itself
- [Lint SQL in CI](lint-sql-in-ci.md)
- [Extract table names from SQL in Go](extract-table-names-from-sql-in-go.md): restrict which tables a query may touch
