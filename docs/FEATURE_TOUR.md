# Feature Tour

This page walks through the feature examples from the Getting Started guide: PostgreSQL extensions, security scanning, and linting. Install GoSQLX first by following [Getting Started](GETTING_STARTED.md).

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
