# Feature Tour

This page walks through short examples of GoSQLX features: PostgreSQL extensions, security scanning, linting, formatting that keeps comments, transforms, fingerprinting and transpilation. Install GoSQLX first by following [Getting Started](GETTING_STARTED.md).

The formatting, transform, fingerprinting and transpilation examples show behaviour that is on the main branch and ships in the next release; the outputs below were produced from the main branch.

## Feature Examples

### PostgreSQL Extensions

```go
package main

import (
    "fmt"
    "log"

    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func main() {
    // Parse PostgreSQL JSON operators
    jsonQuery := `
        SELECT data->>'name' AS name,
               data->'address'->>'city' AS city
        FROM users
        WHERE profile @> '{"role": "admin"}'
    `
    ast, err := gosqlx.Parse(jsonQuery)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Parsed JSON operator query successfully!")

    // Parse LATERAL JOIN (correlated subquery in FROM clause)
    lateralQuery := `
        SELECT u.name, r.order_date
        FROM users u,
        LATERAL (
            SELECT * FROM orders
            WHERE user_id = u.id
            ORDER BY order_date DESC
            LIMIT 3
        ) r
    `
    ast, err = gosqlx.Parse(lateralQuery)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Parsed LATERAL JOIN successfully!")

    // Parse DISTINCT ON (PostgreSQL-specific)
    distinctOnQuery := `
        SELECT DISTINCT ON (dept_id) dept_id, name, salary
        FROM employees
        ORDER BY dept_id, salary DESC
    `
    ast, err = gosqlx.Parse(distinctOnQuery)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Parsed DISTINCT ON successfully!")

    // Parse FILTER clause (SQL:2003 conditional aggregation)
    filterQuery := `
        SELECT
            COUNT(*) FILTER (WHERE status = 'active') AS active_count,
            SUM(amount) FILTER (WHERE type = 'credit') AS total_credits
        FROM transactions
    `
    ast, err = gosqlx.Parse(filterQuery)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Parsed FILTER clause successfully!")
}
```

### Security Scanning

```go
package main

import (
    "fmt"
    "log"

    "github.com/ajitpratap0/GoSQLX/pkg/sql/security"
)

func main() {
    // Scan SQL for injection vulnerabilities
    suspiciousSQL := "SELECT * FROM users WHERE id = '" + userInput + "'"

    scanner := security.NewScanner()
    result := scanner.Scan(suspiciousSQL)

    if len(result.Threats) > 0 {
        fmt.Printf("Found %d security threats:\n", len(result.Threats))
        for _, threat := range result.Threats {
            fmt.Printf("  [%s] %s at line %d\n",
                threat.Severity, threat.Description, threat.Location.Line)
        }
    } else {
        fmt.Println("No security threats detected!")
    }
}
```

### Linting SQL

```go
package main

import (
    "fmt"
    "log"

    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func main() {
    sql := "select * from users where name='john'"

    // Run all 30 built-in lint rules (L001-L030)
    result, err := gosqlx.Lint(sql)
    if err != nil {
        log.Fatal(err)
    }

    if len(result.Violations) > 0 {
        fmt.Printf("Found %d violations:\n", len(result.Violations))
        for _, v := range result.Violations {
            fmt.Printf("  [%s] %s at line %d\n", v.Rule, v.Message, v.Location.Line)
        }
    } else {
        fmt.Println("No violations found!")
    }
}
```

### Formatting That Keeps Comments

`gosqlx.Format` keeps comments. A comment inside a statement moves to the line above it, and optimizer hints (`/*+ ... */`) after a statement's first keyword stay in place. Input whose hints cannot be put back faithfully returns an error wrapping `formatter.ErrUnplaceableComment` instead of losing them. See [Format SQL in Go](guides/format-sql-in-go.md).

```go
package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func main() {
	sql := "-- active users\nselect id, /* primary key */ email from users where active = true; -- first query\nselect count(*) from orders"

	out, err := gosqlx.Format(sql, gosqlx.DefaultFormatOptions())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(out)
}
```

Output:

```sql
-- active users
/* primary key */
SELECT id, email
FROM users
WHERE active = true; -- first query
SELECT count(*)
FROM orders
```

### Transforms

The `pkg/transform` package rewrites parsed statements with composable rules. `SetLimit` and `SetOffset` edit an existing SQL Server `TOP` or a `FETCH FIRST/NEXT` clause instead of adding `LIMIT` (a `PERCENT` or `WITH TIES` row limit returns an error), and `AddTableAlias` rewrites the qualifiers that used the table name.

```go
package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/transform"
)

func main() {
	// SetLimit edits an existing SQL Server TOP instead of adding LIMIT.
	tree, err := transform.ParseSQLWithDialect("SELECT TOP 10 * FROM users", keywords.DialectSQLServer)
	if err != nil {
		log.Fatal(err)
	}
	if err := transform.Apply(tree.Statements[0], transform.SetLimit(5)); err != nil {
		log.Fatal(err)
	}
	fmt.Println(transform.FormatSQLWithDialect(tree.Statements[0], keywords.DialectSQLServer))

	// AddTableAlias also rewrites the qualifiers that use the table name.
	tree, err = transform.ParseSQL("SELECT users.name FROM users WHERE users.id = 1")
	if err != nil {
		log.Fatal(err)
	}
	if err := transform.Apply(tree.Statements[0], transform.AddTableAlias("users", "u")); err != nil {
		log.Fatal(err)
	}
	fmt.Println(transform.FormatSQL(tree.Statements[0]))
}
```

Output:

```text
SELECT TOP 5 * FROM users
SELECT u.name FROM users u WHERE u.id = 1
```

### Fingerprinting

`fingerprint.Normalize` replaces literals with `?`, and `fingerprint.Fingerprint` hashes the normalized text, so queries that differ only in their values share a fingerprint. Identifier quotes are kept: `SELECT "A" FROM "T"` is no longer folded to `SELECT A FROM T`, so fingerprints of queries with quoted identifiers differ from those of earlier releases. Re-compute stored fingerprints after upgrading.

```go
package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/fingerprint"
)

func main() {
	a, err := fingerprint.Fingerprint(`SELECT "A" FROM "T" WHERE id = 5`)
	if err != nil {
		log.Fatal(err)
	}
	b, err := fingerprint.Fingerprint(`SELECT "A" FROM "T" WHERE id = 42`)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(a == b) // same query shape, different literal

	normalized, err := fingerprint.Normalize(`SELECT "A" FROM "T" WHERE id = 5`)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(normalized)
}
```

Output:

```text
true
SELECT "A" FROM "T" WHERE id = ?
```

### Transpilation

`gosqlx.Transpile` parses SQL in one dialect and writes it for another. Strings and quoted identifiers use the target's escape rules and delimiters, and operators are mapped by meaning: `^` is exponentiation in PostgreSQL but bitwise XOR in MySQL, MariaDB and SQL Server, and PostgreSQL `@` and `|/` become `ABS()` and `SQRT()`. The same engine runs behind `gosqlx transpile` in the [CLI](CLI_GUIDE.md#gosqlx-transpile---convert-sql-between-dialects).

```go
package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func main() {
	examples := []struct {
		sql      string
		from, to keywords.SQLDialect
	}{
		{"SELECT `Order Id` FROM t WHERE n = 'it\\'s'", keywords.DialectMySQL, keywords.DialectPostgreSQL},
		{"SELECT 2 ^ 3", keywords.DialectPostgreSQL, keywords.DialectMySQL},
		{"SELECT a ^ b FROM t", keywords.DialectMySQL, keywords.DialectPostgreSQL},
		{"SELECT a ^ b FROM t", keywords.DialectMySQL, keywords.DialectClickHouse},
		{"SELECT @ x, |/ y FROM t", keywords.DialectPostgreSQL, keywords.DialectMySQL},
	}
	for _, e := range examples {
		out, err := gosqlx.Transpile(e.sql, e.from, e.to)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(out)
	}

	// SQL the target cannot express is an error, not a silent change.
	_, err := gosqlx.Transpile("SELECT a ^ b FROM t", keywords.DialectMySQL, keywords.DialectOracle)
	fmt.Println(err)
}
```

Output:

```text
SELECT "Order Id" FROM t WHERE n = 'it''s'
SELECT POWER(2, 3)
SELECT a # b FROM t
SELECT bitXor(a, b) FROM t
SELECT ABS(x), SQRT(y) FROM t
rewrite: the bitwise XOR operator ^ has no equivalent in oracle
```

### More Quick Examples

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func main() {
    // Validate SQL without parsing
    if err := gosqlx.Validate("SELECT * FROM users"); err != nil {
        fmt.Println("Invalid SQL:", err)
    } else {
        fmt.Println("Valid SQL!")
    }

    // Parse multiple queries efficiently (reuses internal resources)
    queries := []string{
        "SELECT * FROM users",
        "SELECT * FROM orders",
        "SELECT * FROM products",
    }
    asts, err := gosqlx.ParseMultiple(queries)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Parsed %d queries\n", len(asts))

    // Parse with timeout for long queries
    sql := "SELECT * FROM large_table"
    ast, err := gosqlx.ParseWithTimeout(sql, 5*time.Second)
    if err == context.DeadlineExceeded {
        fmt.Println("Query took too long to parse")
    }

    // Parse from byte slice (zero-copy optimization)
    sqlBytes := []byte("SELECT * FROM users")
    ast, err = gosqlx.ParseBytes(sqlBytes)
}
```

> **Performance Note:** The simple API has < 1% overhead compared to the low-level API. Use it everywhere unless you need fine-grained control over resource management.
