---
title: "Blocking SQL injection with AST analysis in Go"
description: "Build a Go gate that parses raw SQL before it runs: one statement, SELECT only, allow-listed tables, and injection checks on the syntax tree and the text."
date: 2026-10-18
tags: [security, sql-injection, go, ast]
---

Parameterized queries prevent SQL injection. If every query in your service is a fixed string with `$1` placeholders, you do not need anything in this post.

But more and more systems accept SQL that was not written by the developer: admin consoles, BI tools, internal query APIs, and now AI agents that write SQL on a user's behalf. You cannot parameterize a query you did not write. What you can do is decide, before the query reaches the database, whether it is the kind of query you are willing to run.

This post builds that decision as a Go function, using the GoSQLX parser and its security scanner, and explains why parsing the query beats pattern-matching its text.

## Why regular expressions are not enough

The classic injection test is a tautology: `' OR 1=1 --`. A regular expression for `OR 1=1` catches that exact string. It is less reliable on the variations an attacker or a confused model can produce:

```sql
SELECT id FROM orders WHERE customer_id = 42 OR (1 = 1)
SELECT id FROM orders WHERE customer_id = 42 Or 'x'   =   'x'
```

Whitespace, case, quoting and parentheses are noise to the database, so each one is something a regex has to anticipate. A parser removes that noise before you look. In the syntax tree, both queries above contain the same shape: an `OR` node whose operand is a `BinaryExpression` comparing two equal literals. Grouping parentheses are unwrapped, keyword case is gone and whitespace never existed.

Parsing also answers structural questions that text matching cannot answer reliably at all: how many statements are there, what kind of statement is it, and which tables does it read, including tables inside subqueries and joins.

## The gate

Here is a complete gate for a read-only query endpoint. It allows exactly one plain `SELECT`, over an allow-list of tables, with no injection findings of high severity or above:

```go
package querygate

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/security"
)

var scanner = security.NewScanner() // safe to share between goroutines

var allowedTables = map[string]bool{
	"orders":    true,
	"customers": true,
}

// CheckReadOnlyQuery decides whether a raw SQL string may run.
func CheckReadOnlyQuery(sql string) error {
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		return fmt.Errorf("rejected: does not parse: %w", err)
	}
	defer ast.ReleaseAST(tree)

	// 1. Exactly one statement: no stacked queries.
	if len(tree.Statements) != 1 {
		return fmt.Errorf("rejected: %d statements, exactly one allowed", len(tree.Statements))
	}

	// 2. A plain SELECT: no writes, no DDL, no UNION.
	if _, ok := tree.Statements[0].(*ast.SelectStatement); !ok {
		return fmt.Errorf("rejected: only a plain SELECT is allowed, got %T", tree.Statements[0])
	}

	// 3. Only allow-listed tables, wherever they appear.
	for _, table := range gosqlx.ExtractTables(tree) {
		if !allowedTables[strings.ToLower(table)] {
			return fmt.Errorf("rejected: table %q is not allowed", table)
		}
	}

	// 4. Injection patterns in the tree: tautologies, UNION padding, delay and dangerous functions.
	if result := scanner.Scan(tree); result.HasHighOrAbove() {
		return errors.New("rejected: " + result.Findings[0].Description)
	}

	// 5. Injection patterns in the text: comment bypasses and other textual tricks.
	if result := scanner.ScanSQL(sql); result.HasHighOrAbove() {
		return errors.New("rejected: " + result.Findings[0].Description)
	}
	return nil
}
```

Run against a handful of inputs, it produces:

```text
SELECT id, total FROM orders WHERE customer_id = 42                => <nil>
SELECT id FROM orders WHERE customer_id = 42 OR (1 = 1)            => rejected: OR condition with tautology detected (e.g., OR 1=1)
SELECT id FROM orders WHERE customer_id = 42 Or 'x'   =   'x'      => rejected: OR condition with tautology detected (e.g., OR 1=1)
SELECT id FROM orders; DROP TABLE orders                           => rejected: 2 statements, exactly one allowed
SELECT id FROM orders UNION SELECT NULL, NULL FROM users           => rejected: only a plain SELECT is allowed, got *ast.SetOperation
SELECT email FROM users                                            => rejected: table "users" is not allowed
DELETE FROM orders                                                 => rejected: only a plain SELECT is allowed, got *ast.DeleteStatement
SELECT id FROM orders WHERE name = 'x'--' AND tenant_id = 7        => rejected: Comment after quote/bracket (potential bypass)
SELECT id FROM orders WHERE id = 1 AND SLEEP(5) = 0                => rejected: Time-based blind injection function detected: SLEEP
SELECT o.id FROM orders o JOIN (SELECT id FROM pg_shadow) s ON ... => rejected: table "pg_shadow" is not allowed
```

## Why each step is there

**Steps 1 to 3 are allow-lists, and they do most of the work.** A query that is a single `SELECT` over approved tables cannot drop a table, cannot read `pg_shadow` through a subquery and cannot pull another table in with `UNION`. Allow-lists fail closed: a new attack technique still has to get past "one SELECT over these tables". Notice that the last example is stopped by the table check, not by any injection pattern.

**Step 4 looks for intent inside an allowed query.** A tautology such as `OR 1=1` is a legal `SELECT` over an allowed table, but it turns "orders for customer 42" into "all orders". The AST scan finds equality tautologies on either side of an `OR`, `UNION SELECT` operands padded with `NULL` columns or reading system tables, delay functions used for blind injection such as `SLEEP` and `pg_sleep`, and dangerous functions that reach outside the database, wherever they are nested in the tree.

**Step 5 covers what the tree cannot see.** Comments are discarded during parsing, so a `--` that cuts off the rest of a `WHERE` clause, the tenant filter in the example above, leaves no trace in the AST. The text scan matches comment tricks, MySQL conditional comments and other patterns directly on the SQL. Running both scans is cheap, and each covers the other's blind spots.

## Choosing what to block

Every finding has a severity (`CRITICAL`, `HIGH`, `MEDIUM` or `LOW`), and the scanner can drop findings below a threshold with `security.NewScannerWithSeverity`. A sensible rollout:

1. **Log first.** Run the gate in report-only mode on real traffic. Legitimate SQL sometimes matches attack shapes; a reporting query may use `UNION`, and a test fixture may contain `WHERE 1=1`.
2. **Block on structure.** Enforce steps 1 to 3 as soon as you know your allow-list; they have no false positives you did not choose.
3. **Block on critical findings,** and alert on high ones, once the logs show what fires.

## What this does not replace

A gate like this reduces risk; it does not remove it. Keep the real defences in place:

- Run gated queries as a database role that can only read the allowed tables. If the gate has a bug, the database still says no.
- Set statement timeouts, so a query that is technically allowed cannot run for an hour.
- Prefer parameterized queries everywhere you write the SQL yourself.

The parser is the part that makes the gate trustworthy: it reads the query the way the database will, instead of guessing from its text.

Further reading:

- [Detect SQL injection in Go](/docs/guides/detect-sql-injection-in-go/): the scanner's patterns and API in detail
- [Extract table names from SQL in Go](/docs/guides/extract-table-names-from-sql-in-go/)
- [Security model](/docs/concepts/security/)
- Try it on your own queries in the [playground](/playground/)
