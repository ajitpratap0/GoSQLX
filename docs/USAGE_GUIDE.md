# GoSQLX Usage Guide

**Version**: v1.6.0 | **Last Updated**: December 2025

## Table of Contents
- [Getting Started](#getting-started)
- [Simple API (Recommended)](#simple-api-recommended)
- [Basic Usage](#basic-usage)
- [Advanced SQL Features (v1.6.0)](#advanced-sql-features-v160)
- [PostgreSQL Features (v1.6.0)](#postgresql-features-v160)
- [SQL Standards Compliance (v1.6.0)](#sql-standards-compliance-v160)
- [SQL Injection Detection](#sql-injection-detection)
- [SQL Linter Usage (v1.6.0)](#sql-linter-usage-v160)
- [LSP Integration (v1.6.0)](#lsp-integration-v160)
- [CLI Tool Usage (v1.6.0)](#cli-tool-usage-v160)
- [Advanced Patterns](#advanced-patterns)
- [Real-World Examples](#real-world-examples)
- [SQL Dialect Support](#sql-dialect-support)
- [Unicode and International Support](#unicode-and-international-support)
- [Performance Optimization](#performance-optimization)
- [Common Patterns](#common-patterns)

## Getting Started

### Installation

```bash
go get github.com/ajitpratap0/GoSQLX
```

### Minimum Go Version
Go 1.21+ or higher is required.

### Import Packages

```go
import (
    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
    "github.com/ajitpratap0/GoSQLX/pkg/models"
)
```

## Simple API (Recommended)

The simplest way to use GoSQLX is through the high-level API that handles all complexity for you:

```go
package main

import (
    "fmt"
    "log"

    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func main() {
    // Parse SQL in one line - that's it!
    ast, err := gosqlx.Parse("SELECT * FROM users WHERE active = true")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Successfully parsed %d statement(s)\n", len(ast.Statements))
}
```

### More Simple API Examples

```go
// Validate SQL without full parsing
if err := gosqlx.Validate("SELECT * FROM users"); err != nil {
    fmt.Println("Invalid SQL:", err)
}

// Parse multiple queries efficiently
queries := []string{
    "SELECT * FROM users",
    "SELECT * FROM orders",
}
asts, err := gosqlx.ParseMultiple(queries)

// Parse with timeout for long queries
ast, err := gosqlx.ParseWithTimeout(sql, 5*time.Second)

// Parse from byte slice (zero-copy)
ast, err := gosqlx.ParseBytes([]byte("SELECT * FROM users"))
```

> **Note:** The simple API has < 1% performance overhead compared to the low-level API. Use the simple API unless you need fine-grained control.

## Basic Usage

### Simple Tokenization

The most basic operation is tokenizing SQL text:

```go
package main

import (
    "fmt"
    "log"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func main() {
    // SQL to tokenize
    sql := "SELECT id, name FROM users WHERE age > 18"
    
    // Get tokenizer from pool
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz) // CRITICAL: Always return to pool
    
    // Tokenize
    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        log.Fatal(err)
    }
    
    // Process tokens
    for _, token := range tokens {
        if token.Token.Type == models.TokenTypeEOF {
            break
        }
        fmt.Printf("Token: %s (Type: %d)\n", 
            token.Token.Value, token.Token.Type)
    }
}
```

### Parsing to AST

Convert tokens to an Abstract Syntax Tree:

```go
package main

import (
    "fmt"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

func ParseSQL(sql string) error {
    // Step 1: Tokenize
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        return err
    }

    // Step 2: Convert to parser tokens using the proper converter
    converter := parser.NewTokenConverter()
    result, err := converter.Convert(tokens)
    if err != nil {
        return fmt.Errorf("token conversion failed: %w", err)
    }

    // Step 3: Parse
    p := parser.NewParser()
    defer p.Release()

    ast, err := p.Parse(result.Tokens)
    if err != nil {
        return err
    }

    fmt.Printf("Parsed: %T\n", ast)
    return nil
}
```

## Advanced Patterns

### Batch Processing

Process multiple SQL statements efficiently:

```go
func BatchProcess(queries []string) ([][]models.TokenWithSpan, error) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    results := make([][]models.TokenWithSpan, len(queries))
    
    for i, query := range queries {
        // Reset tokenizer state between queries
        tkz.Reset()
        
        tokens, err := tkz.Tokenize([]byte(query))
        if err != nil {
            return nil, fmt.Errorf("query %d: %w", i, err)
        }
        
        results[i] = tokens
    }
    
    return results, nil
}
```

### Concurrent Processing

Handle multiple queries concurrently:

```go
func ConcurrentProcess(queries []string) []Result {
    results := make([]Result, len(queries))
    var wg sync.WaitGroup
    
    for i, query := range queries {
        wg.Add(1)
        go func(idx int, sql string) {
            defer wg.Done()
            
            // Each goroutine gets its own tokenizer
            tkz := tokenizer.GetTokenizer()
            defer tokenizer.PutTokenizer(tkz)
            
            tokens, err := tkz.Tokenize([]byte(sql))
            results[idx] = Result{
                Tokens: tokens,
                Error:  err,
            }
        }(i, query)
    }
    
    wg.Wait()
    return results
}
```

### Error Handling with Position Info

Get detailed error information with line and column numbers:

```go
func HandleTokenizerError(sql string) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        if tkErr, ok := err.(models.TokenizerError); ok {
            fmt.Printf("Syntax error at line %d, column %d: %s\n",
                tkErr.Location.Line,
                tkErr.Location.Column,
                tkErr.Message)

            // Show the problematic line
            lines := strings.Split(sql, "\n")
            if tkErr.Location.Line <= len(lines) {
                fmt.Printf("Line %d: %s\n",
                    tkErr.Location.Line,
                    lines[tkErr.Location.Line-1])

                // Show error position with caret
                fmt.Printf("%*s^\n",
                    tkErr.Location.Column+6, "") // +6 for "Line X: "
            }
        }
    }
}
```

## Advanced SQL Features (v1.6.0)

### GROUPING SETS, ROLLUP, CUBE (SQL-99 T431)

```go
// GROUPING SETS - explicit grouping combinations
sql := `SELECT region, product, SUM(sales)
        FROM orders
        GROUP BY GROUPING SETS ((region), (product), (region, product), ())`
ast, err := gosqlx.Parse(sql)

// ROLLUP - hierarchical subtotals
sql := `SELECT year, quarter, month, SUM(revenue)
        FROM sales
        GROUP BY ROLLUP (year, quarter, month)`
ast, err := gosqlx.Parse(sql)

// CUBE - all possible combinations
sql := `SELECT region, product, SUM(amount)
        FROM sales
        GROUP BY CUBE (region, product)`
ast, err := gosqlx.Parse(sql)
```

### MERGE Statements (SQL:2003 F312)

```go
sql := `
    MERGE INTO target_table t
    USING source_table s ON t.id = s.id
    WHEN MATCHED THEN
        UPDATE SET t.name = s.name, t.value = s.value
    WHEN NOT MATCHED THEN
        INSERT (id, name, value) VALUES (s.id, s.name, s.value)
`
ast, err := gosqlx.Parse(sql)
```

### Materialized Views

```go
// Create materialized view
sql := `CREATE MATERIALIZED VIEW sales_summary AS
        SELECT region, SUM(amount) as total
        FROM sales GROUP BY region`
ast, err := gosqlx.Parse(sql)

// Refresh materialized view
sql := `REFRESH MATERIALIZED VIEW CONCURRENTLY sales_summary`
ast, err := gosqlx.Parse(sql)

// Drop materialized view
sql := `DROP MATERIALIZED VIEW IF EXISTS sales_summary`
ast, err := gosqlx.Parse(sql)
```

### Expression Operators (BETWEEN, IN, LIKE, IS NULL)

```go
// BETWEEN with expressions
sql := `SELECT * FROM orders WHERE amount BETWEEN 100 AND 500`

// IN with subquery
sql := `SELECT * FROM users WHERE id IN (SELECT user_id FROM admins)`

// LIKE with pattern matching
sql := `SELECT * FROM products WHERE name LIKE '%widget%'`

// IS NULL / IS NOT NULL
sql := `SELECT * FROM users WHERE deleted_at IS NULL`

// NULLS FIRST/LAST ordering (SQL-99 F851)
sql := `SELECT * FROM users ORDER BY last_login DESC NULLS LAST`
```

### Subqueries

```go
// Scalar subquery
sql := `SELECT name, (SELECT MAX(salary) FROM employees) as max_sal FROM users`

// EXISTS subquery
sql := `SELECT * FROM orders o
        WHERE EXISTS (SELECT 1 FROM customers c WHERE c.id = o.customer_id)`

// Correlated subquery
sql := `SELECT * FROM employees e
        WHERE salary > (SELECT AVG(salary) FROM employees WHERE dept = e.dept)`
```

### Window Functions (SQL-99)

GoSQLX fully supports SQL-99 window functions with PARTITION BY, ORDER BY, and frame specifications:

```go
import (
    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

// Ranking functions
sql := `SELECT name, salary,
        ROW_NUMBER() OVER (ORDER BY salary DESC) as rank,
        RANK() OVER (PARTITION BY dept ORDER BY salary DESC) as dept_rank
        FROM employees`
ast, err := gosqlx.Parse(sql)

// Analytic functions with LAG/LEAD
sql := `SELECT name, salary,
        LAG(salary, 1) OVER (ORDER BY hire_date) as prev_salary,
        LEAD(salary, 2, 0) OVER (ORDER BY hire_date) as future_salary
        FROM employees`
ast, err := gosqlx.Parse(sql)

// Window frames - ROWS and RANGE
sql := `SELECT date, amount,
        SUM(amount) OVER (ORDER BY date ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) as rolling_sum,
        AVG(amount) OVER (ORDER BY date RANGE UNBOUNDED PRECEDING) as running_avg
        FROM transactions`
ast, err := gosqlx.Parse(sql)

// Complex window specifications with FIRST_VALUE/LAST_VALUE
sql := `SELECT dept, name, salary,
        FIRST_VALUE(salary) OVER (PARTITION BY dept ORDER BY salary DESC) as dept_max,
        LAST_VALUE(salary) OVER (PARTITION BY dept ORDER BY salary
            RANGE BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING) as dept_min,
        NTILE(4) OVER (ORDER BY salary) as quartile
        FROM employees`
ast, err := gosqlx.Parse(sql)
```

### CTEs and Recursive Queries (SQL-99)

Common Table Expressions including recursive CTEs:

```go
// Simple CTE
sql := `WITH active_products AS (
    SELECT product_id, product_name FROM products WHERE active = true
)
SELECT * FROM active_products`
ast, err := gosqlx.Parse(sql)

// Multiple CTEs
sql := `WITH
    active_products AS (
        SELECT product_id, product_name FROM products WHERE active = true
    ),
    recent_orders AS (
        SELECT product_id, COUNT(*) as order_count FROM orders
        WHERE order_date > '2023-01-01' GROUP BY product_id
    )
SELECT ap.product_name, ro.order_count
FROM active_products ap
LEFT JOIN recent_orders ro ON ap.product_id = ro.product_id`
ast, err := gosqlx.Parse(sql)

// Recursive CTE with proper termination
sql := `WITH RECURSIVE employee_hierarchy AS (
    SELECT id, name, manager_id, 1 as level
    FROM employees
    WHERE manager_id IS NULL
    UNION ALL
    SELECT e.id, e.name, e.manager_id, eh.level + 1
    FROM employees e
    JOIN employee_hierarchy eh ON e.manager_id = eh.id
    WHERE eh.level < 10
)
SELECT * FROM employee_hierarchy ORDER BY level, name`
ast, err := gosqlx.Parse(sql)
```

### Set Operations (SQL-99)

UNION, INTERSECT, EXCEPT with proper precedence handling:

```go
// UNION and UNION ALL
sql := `SELECT product FROM inventory
        UNION
        SELECT product FROM orders`
ast, err := gosqlx.Parse(sql)

// Complex set operations with precedence
sql := `SELECT product FROM inventory
        UNION SELECT product FROM orders
        EXCEPT SELECT product FROM discontinued
        INTERSECT SELECT product FROM active_catalog`
ast, err := gosqlx.Parse(sql)

// Set operations with CTEs
sql := `WITH active AS (
    SELECT id FROM products WHERE active = true
)
SELECT id FROM active
UNION
SELECT id FROM featured_products`
ast, err := gosqlx.Parse(sql)
```

### JOINs (All Types)

Complete JOIN support with proper left-associative parsing:

```go
// Complex multi-table JOINs
sql := `SELECT u.name, o.order_date, p.product_name, c.category_name
        FROM users u
        LEFT JOIN orders o ON u.id = o.user_id
        INNER JOIN products p ON o.product_id = p.id
        RIGHT JOIN categories c ON p.category_id = c.id
        WHERE u.active = true`
ast, err := gosqlx.Parse(sql)

// NATURAL JOIN
sql := `SELECT u.name, p.title
        FROM users u
        NATURAL JOIN posts p
        WHERE p.published = true`
ast, err := gosqlx.Parse(sql)

// JOIN with USING clause
sql := `SELECT u.name, p.title
        FROM users u
        JOIN posts p USING (user_id)
        WHERE p.published = true`
ast, err := gosqlx.Parse(sql)

// CROSS JOIN
sql := `SELECT * FROM colors CROSS JOIN sizes`
ast, err := gosqlx.Parse(sql)
```

## PostgreSQL Features (v1.6.0)

GoSQLX v1.6.0 adds comprehensive PostgreSQL-specific feature support:

### LATERAL JOIN

LATERAL allows subqueries in FROM clause to reference columns from preceding tables:

```go
import (
    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

// LATERAL with implicit syntax
sql := `SELECT u.name, r.order_date
        FROM users u,
        LATERAL (
            SELECT * FROM orders
            WHERE user_id = u.id
            ORDER BY order_date DESC
            LIMIT 3
        ) r`
ast, err := gosqlx.Parse(sql)

// LATERAL with explicit JOIN
sql := `SELECT u.name, recent.total
        FROM users u
        LEFT JOIN LATERAL (
            SELECT SUM(amount) as total
            FROM orders
            WHERE user_id = u.id
            AND order_date > CURRENT_DATE - INTERVAL '30 days'
        ) recent ON true`
ast, err := gosqlx.Parse(sql)

// Multiple LATERAL subqueries
sql := `SELECT u.name, last_order.date, avg_amount.value
        FROM users u
        LATERAL (
            SELECT order_date as date
            FROM orders
            WHERE user_id = u.id
            ORDER BY order_date DESC
            LIMIT 1
        ) last_order
        LATERAL (
            SELECT AVG(amount) as value
            FROM orders
            WHERE user_id = u.id
        ) avg_amount`
ast, err := gosqlx.Parse(sql)
```

### JSON/JSONB Operators

PostgreSQL JSON and JSONB operators for JSON document manipulation:

```go
// -> operator: Get JSON object field by key (returns JSON)
sql := `SELECT data->'name' AS name, data->'address' AS address FROM users`
ast, err := gosqlx.Parse(sql)

// ->> operator: Get JSON object field as text
sql := `SELECT data->>'name' AS name, data->'address'->>'city' AS city FROM users`
ast, err := gosqlx.Parse(sql)

// #> operator: Get JSON object at specified path (returns JSON)
sql := `SELECT data#>'{address,city}' AS city FROM users`
ast, err := gosqlx.Parse(sql)

// #>> operator: Get JSON object at specified path as text
sql := `SELECT data#>>'{address,city}' AS city FROM users`
ast, err := gosqlx.Parse(sql)

// @> operator: Does left JSON value contain right JSON value
sql := `SELECT * FROM products WHERE attributes @> '{"color": "red"}'`
ast, err := gosqlx.Parse(sql)

// <@ operator: Is left JSON value contained in right JSON value
sql := `SELECT * FROM products WHERE '{"color": "red"}' <@ attributes`
ast, err := gosqlx.Parse(sql)

// ? operator: Does JSON object contain key
sql := `SELECT * FROM users WHERE profile ? 'email'`
ast, err := gosqlx.Parse(sql)

// ?| operator: Does JSON object contain any of these keys
sql := `SELECT * FROM users WHERE profile ?| ARRAY['email', 'phone']`
ast, err := gosqlx.Parse(sql)

// ?& operator: Does JSON object contain all of these keys
sql := `SELECT * FROM users WHERE profile ?& ARRAY['email', 'phone', 'address']`
ast, err := gosqlx.Parse(sql)

// #- operator: Delete key from JSON object
sql := `SELECT data #- '{address,zipcode}' AS modified_data FROM users`
ast, err := gosqlx.Parse(sql)

// Complex JSON queries
sql := `SELECT u.id, u.data->>'name' as name,
        u.data->'preferences'->>'theme' as theme
        FROM users u
        WHERE u.data @> '{"active": true}'
        AND u.data->'profile' ? 'email'`
ast, err := gosqlx.Parse(sql)
```

### DISTINCT ON

PostgreSQL-specific row selection based on distinct values:

```go
// DISTINCT ON with single column
sql := `SELECT DISTINCT ON (dept_id) dept_id, name, salary
        FROM employees
        ORDER BY dept_id, salary DESC`
ast, err := gosqlx.Parse(sql)

// DISTINCT ON with multiple columns
sql := `SELECT DISTINCT ON (dept_id, location)
        dept_id, location, name, hire_date
        FROM employees
        ORDER BY dept_id, location, hire_date DESC`
ast, err := gosqlx.Parse(sql)

// DISTINCT ON with complex expressions
sql := `SELECT DISTINCT ON (DATE(created_at))
        DATE(created_at) as date,
        id,
        title
        FROM posts
        ORDER BY DATE(created_at), created_at DESC`
ast, err := gosqlx.Parse(sql)
```

### FILTER Clause

SQL:2003 FILTER clause for conditional aggregation:

```go
// FILTER with COUNT
sql := `SELECT
        COUNT(*) as total_count,
        COUNT(*) FILTER (WHERE status = 'active') AS active_count,
        COUNT(*) FILTER (WHERE status = 'pending') AS pending_count
        FROM transactions`
ast, err := gosqlx.Parse(sql)

// FILTER with SUM and other aggregates
sql := `SELECT
        SUM(amount) as total_amount,
        SUM(amount) FILTER (WHERE type = 'credit') AS total_credits,
        SUM(amount) FILTER (WHERE type = 'debit') AS total_debits,
        AVG(amount) FILTER (WHERE amount > 100) AS avg_large_transactions
        FROM transactions`
ast, err := gosqlx.Parse(sql)

// FILTER with GROUP BY
sql := `SELECT
        dept_id,
        COUNT(*) FILTER (WHERE salary > 50000) AS high_earners,
        AVG(salary) FILTER (WHERE employment_type = 'full_time') AS avg_ft_salary
        FROM employees
        GROUP BY dept_id`
ast, err := gosqlx.Parse(sql)
```

### Aggregate ORDER BY

ORDER BY within aggregate functions (STRING_AGG, ARRAY_AGG):

```go
// STRING_AGG with ORDER BY
sql := `SELECT dept_id,
        STRING_AGG(name, ', ' ORDER BY hire_date DESC) as recent_hires
        FROM employees
        GROUP BY dept_id`
ast, err := gosqlx.Parse(sql)

// ARRAY_AGG with ORDER BY
sql := `SELECT category,
        ARRAY_AGG(product_name ORDER BY price DESC) as products_by_price
        FROM products
        GROUP BY category`
ast, err := gosqlx.Parse(sql)

// Multiple aggregate ORDER BYs
sql := `SELECT dept_id,
        STRING_AGG(name, ', ' ORDER BY salary DESC, hire_date) as employees,
        ARRAY_AGG(DISTINCT skill ORDER BY skill) as skills
        FROM employee_skills
        GROUP BY dept_id`
ast, err := gosqlx.Parse(sql)
```

### RETURNING Clause

Return modified rows from INSERT, UPDATE, DELETE statements:

```go
// INSERT with RETURNING
sql := `INSERT INTO users (name, email)
        VALUES ('John Doe', 'john@example.com')
        RETURNING id, created_at`
ast, err := gosqlx.Parse(sql)

// UPDATE with RETURNING
sql := `UPDATE products
        SET price = price * 1.1
        WHERE category = 'Electronics'
        RETURNING id, name, price`
ast, err := gosqlx.Parse(sql)

// DELETE with RETURNING
sql := `DELETE FROM sessions
        WHERE expired_at < NOW()
        RETURNING user_id, session_id`
ast, err := gosqlx.Parse(sql)

// RETURNING with expressions
sql := `UPDATE inventory
        SET quantity = quantity - 5
        WHERE product_id = 123
        RETURNING product_id, quantity, quantity * unit_price as total_value`
ast, err := gosqlx.Parse(sql)

// INSERT with RETURNING * (all columns)
sql := `INSERT INTO audit_log (action, user_id, timestamp)
        VALUES ('login', 42, NOW())
        RETURNING *`
ast, err := gosqlx.Parse(sql)
```

## SQL Standards Compliance (v1.6.0)

### FETCH FIRST / OFFSET-FETCH

SQL:2008 standard syntax for row limiting:

```go
// FETCH FIRST without OFFSET
sql := `SELECT * FROM users ORDER BY created_at DESC FETCH FIRST 10 ROWS ONLY`
ast, err := gosqlx.Parse(sql)

// FETCH FIRST with OFFSET
sql := `SELECT * FROM products
        ORDER BY price
        OFFSET 20 ROWS
        FETCH FIRST 10 ROWS ONLY`
ast, err := gosqlx.Parse(sql)

// FETCH NEXT (synonym for FETCH FIRST)
sql := `SELECT * FROM orders
        ORDER BY order_date DESC
        FETCH NEXT 5 ROWS ONLY`
ast, err := gosqlx.Parse(sql)

// FETCH with expression
sql := `SELECT * FROM items
        ORDER BY priority
        FETCH FIRST (SELECT count_limit FROM config) ROWS ONLY`
ast, err := gosqlx.Parse(sql)

// Combined with other clauses
sql := `SELECT dept_id, AVG(salary) as avg_sal
        FROM employees
        WHERE active = true
        GROUP BY dept_id
        HAVING AVG(salary) > 50000
        ORDER BY avg_sal DESC
        OFFSET 5 ROWS
        FETCH FIRST 10 ROWS ONLY`
ast, err := gosqlx.Parse(sql)
```

### TRUNCATE TABLE

TRUNCATE statement with various options:

```go
// Simple TRUNCATE
sql := `TRUNCATE TABLE users`
ast, err := gosqlx.Parse(sql)

// TRUNCATE with CASCADE
sql := `TRUNCATE TABLE departments CASCADE`
ast, err := gosqlx.Parse(sql)

// TRUNCATE with RESTRICT
sql := `TRUNCATE TABLE temp_data RESTRICT`
ast, err := gosqlx.Parse(sql)

// TRUNCATE multiple tables
sql := `TRUNCATE TABLE logs, temp_sessions, cache_data`
ast, err := gosqlx.Parse(sql)

// TRUNCATE with RESTART IDENTITY
sql := `TRUNCATE TABLE users RESTART IDENTITY CASCADE`
ast, err := gosqlx.Parse(sql)

// TRUNCATE with CONTINUE IDENTITY
sql := `TRUNCATE TABLE orders CONTINUE IDENTITY`
ast, err := gosqlx.Parse(sql)
```

### Materialized CTEs

Control CTE materialization behavior:

```go
// Materialized CTE (force materialization)
sql := `WITH MATERIALIZED active_users AS (
    SELECT * FROM users WHERE active = true
)
SELECT * FROM active_users WHERE country = 'US'`
ast, err := gosqlx.Parse(sql)

// Not materialized CTE (inline the CTE)
sql := `WITH NOT MATERIALIZED recent_orders AS (
    SELECT * FROM orders WHERE order_date > CURRENT_DATE - 30
)
SELECT * FROM recent_orders WHERE status = 'pending'`
ast, err := gosqlx.Parse(sql)

// Multiple CTEs with different materialization
sql := `WITH
    MATERIALIZED large_dataset AS (
        SELECT * FROM historical_data WHERE year >= 2020
    ),
    NOT MATERIALIZED filtered AS (
        SELECT * FROM large_dataset WHERE region = 'APAC'
    )
SELECT COUNT(*) FROM filtered`
ast, err := gosqlx.Parse(sql)
```

## SQL Injection Detection

GoSQLX v1.6.0 includes a built-in security scanner (`pkg/sql/security`) for detecting SQL injection patterns:

```go
import (
    "fmt"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/security"
)

func CheckForInjection(sql string) {
    // Create scanner and scan SQL directly
    scanner := security.NewScanner()
    result := scanner.ScanSQL(sql)

    // Check results by severity
    if result.HasCritical() {
        fmt.Printf("CRITICAL: Found %d critical security issues!\n", result.CriticalCount)
    }
    if result.HasHighOrAbove() {
        fmt.Printf("HIGH: Found %d high-severity issues\n", result.HighCount)
    }
    if result.HasMediumOrAbove() {
        fmt.Printf("MEDIUM: Found %d medium-severity issues\n", result.MediumCount)
    }

    // Print all findings with details
    for _, finding := range result.Findings {
        fmt.Printf("[%s] %s\n", finding.Severity, finding.Pattern)
        fmt.Printf("  Description: %s\n", finding.Description)
        if finding.Location != "" {
            fmt.Printf("  Location: %s\n", finding.Location)
        }
    }
}
```

### Detected Injection Patterns

The security scanner detects multiple attack vectors with severity classification:

**CRITICAL Severity:**
- **Tautology patterns**: `1=1`, `'a'='a'`, `OR 1=1`, always-true conditions
- **Stacked queries**: Multiple statement injection (`;`)
- **Command execution**: `xp_cmdshell`, `exec xp_cmdshell`

**HIGH Severity:**
- **UNION-based injection**: Unauthorized UNION statements
- **Time-based blind injection**: `SLEEP()`, `WAITFOR DELAY`, `pg_sleep()`
- **File operations**: `LOAD_FILE()`, `INTO OUTFILE`, `INTO DUMPFILE`
- **Comment bypass**: `--`, `/**/`, `#` comment abuse

**MEDIUM Severity:**
- **Unusual operators**: Excessive OR/AND conditions
- **Hex/binary literals**: Potential obfuscation
- **System functions**: `@@version`, `version()`, `user()`

```go
// Example: Validate user input for injection
func ValidateUserQuery(userInput string) error {
    scanner := security.NewScanner()
    result := scanner.ScanSQL(userInput)

    if result.HasCritical() {
        return fmt.Errorf("CRITICAL: SQL injection detected - %d critical issues found",
            result.CriticalCount)
    }

    if result.HasHighOrAbove() {
        return fmt.Errorf("HIGH: Potential SQL injection - %d high-severity issues found",
            result.HighCount)
    }

    // Log medium-severity findings but allow
    if result.HasMediumOrAbove() {
        fmt.Printf("Warning: %d medium-severity security patterns found\n",
            result.MediumCount)
    }

    return nil
}
```

### Advanced Security Scanning

```go
import (
    "github.com/ajitpratap0/GoSQLX/pkg/sql/security"
)

func AdvancedSecurityCheck(sql string) (*security.ScanResult, error) {
    scanner := security.NewScanner()
    result := scanner.ScanSQL(sql)

    // Get detailed statistics
    fmt.Printf("Security Scan Results:\n")
    fmt.Printf("  Total Findings: %d\n", len(result.Findings))
    fmt.Printf("  Critical: %d\n", result.CriticalCount)
    fmt.Printf("  High: %d\n", result.HighCount)
    fmt.Printf("  Medium: %d\n", result.MediumCount)
    fmt.Printf("  Low: %d\n", result.LowCount)

    // Group findings by pattern
    patternMap := make(map[string][]security.Finding)
    for _, finding := range result.Findings {
        patternMap[finding.Pattern] = append(patternMap[finding.Pattern], finding)
    }

    // Print grouped findings
    for pattern, findings := range patternMap {
        fmt.Printf("\nPattern: %s (Count: %d)\n", pattern, len(findings))
        for _, f := range findings {
            fmt.Printf("  - %s [%s]\n", f.Description, f.Severity)
        }
    }

    return result, nil
}
```

## SQL Linter Usage (v1.6.0)

GoSQLX v1.6.0 includes a comprehensive SQL linter with 10 built-in rules (L001-L010):

### Basic Linting

```go
import (
    "fmt"
    "github.com/ajitpratap0/GoSQLX/pkg/linter"
)

func LintSQL(sql string) {
    // Create linter with all default rules
    l := linter.New()

    // Lint the SQL
    violations, err := l.Lint(sql)
    if err != nil {
        fmt.Printf("Linting error: %v\n", err)
        return
    }

    // Print violations
    if len(violations) == 0 {
        fmt.Println("No violations found - SQL is clean!")
        return
    }

    fmt.Printf("Found %d violation(s):\n", len(violations))
    for _, v := range violations {
        fmt.Printf("[%s] Line %d, Col %d: %s\n",
            v.Rule,
            v.Line,
            v.Column,
            v.Message)
    }
}
```

### Linter Rules (L001-L010)

The linter enforces the following rules:

**L001: Unnecessary aliases for single tables**
```go
// BAD: Alias not needed for single table
sql := `SELECT u.name FROM users u`

// GOOD: No alias for single table
sql := `SELECT name FROM users`
```

**L002: SELECT * usage**
```go
// BAD: SELECT * is ambiguous
sql := `SELECT * FROM users`

// GOOD: Explicit column list
sql := `SELECT id, name, email FROM users`
```

**L003: Missing table aliases in JOINs**
```go
// BAD: No aliases in multi-table query
sql := `SELECT name FROM users JOIN orders ON users.id = orders.user_id`

// GOOD: Clear aliases
sql := `SELECT u.name FROM users u JOIN orders o ON u.id = o.user_id`
```

**L004: Implicit column references**
```go
// BAD: Ambiguous column in JOIN
sql := `SELECT name FROM users u JOIN profiles p ON u.id = p.user_id`

// GOOD: Qualified column reference
sql := `SELECT u.name FROM users u JOIN profiles p ON u.id = p.user_id`
```

**L005-L010: Additional style and performance rules**

### Custom Linting Configuration

```go
import (
    "github.com/ajitpratap0/GoSQLX/pkg/linter"
    "github.com/ajitpratap0/GoSQLX/pkg/linter/rules"
)

func CustomLinting(sql string) {
    // Create linter with specific rules
    l := linter.New(
        rules.L001UnnecessaryAlias,
        rules.L002SelectStar,
        rules.L003MissingAlias,
    )

    violations, err := l.Lint(sql)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }

    // Process violations
    for _, v := range violations {
        fmt.Printf("%s at %d:%d - %s\n",
            v.Rule, v.Line, v.Column, v.Message)
    }
}
```

### Linting Multiple Files

```go
import (
    "io/ioutil"
    "path/filepath"
    "github.com/ajitpratap0/GoSQLX/pkg/linter"
)

func LintDirectory(dirPath string) error {
    l := linter.New()

    // Find all .sql files
    files, err := filepath.Glob(filepath.Join(dirPath, "*.sql"))
    if err != nil {
        return err
    }

    totalViolations := 0
    for _, file := range files {
        content, err := ioutil.ReadFile(file)
        if err != nil {
            fmt.Printf("Error reading %s: %v\n", file, err)
            continue
        }

        violations, err := l.Lint(string(content))
        if err != nil {
            fmt.Printf("Error linting %s: %v\n", file, err)
            continue
        }

        if len(violations) > 0 {
            fmt.Printf("\n%s: %d violation(s)\n", file, len(violations))
            for _, v := range violations {
                fmt.Printf("  [%s] Line %d: %s\n", v.Rule, v.Line, v.Message)
            }
            totalViolations += len(violations)
        }
    }

    fmt.Printf("\nTotal violations: %d across %d files\n",
        totalViolations, len(files))
    return nil
}
```

### Configuration File Support

GoSQLX supports `.gosqlx.yml` configuration files for linter customization:

```yaml
# .gosqlx.yml
linting:
  enabled: true
  rules:
    L001: true   # Unnecessary aliases
    L002: true   # SELECT * usage
    L003: true   # Missing aliases in JOINs
    L004: true   # Implicit column references
    L005: false  # Disable this rule
  severity:
    L001: warning
    L002: error
    L003: error
```

Load configuration programmatically:

```go
import (
    "github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/config"
    "github.com/ajitpratap0/GoSQLX/pkg/linter"
)

func LintWithConfig(sql string, configPath string) {
    // Load configuration
    cfg, err := config.Load(configPath)
    if err != nil {
        fmt.Printf("Config error: %v\n", err)
        return
    }

    // Create linter from config
    l := linter.NewFromConfig(cfg)

    // Lint with configured rules
    violations, err := l.Lint(sql)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }

    // Handle violations based on severity
    for _, v := range violations {
        severity := cfg.GetSeverity(v.Rule)
        fmt.Printf("[%s] %s: %s\n", severity, v.Rule, v.Message)
    }
}
```

## LSP Integration (v1.6.0)

GoSQLX v1.6.0 includes a full Language Server Protocol (LSP) server for IDE integration:

### Starting the LSP Server

```bash
# Start LSP server (stdio mode)
gosqlx lsp

# Start with debug logging
gosqlx lsp --log /tmp/gosqlx-lsp.log

# Start with verbose output
gosqlx lsp --verbose
```

### LSP Features

The LSP server provides:

1. **Diagnostics** - Real-time syntax error detection
2. **Hover** - Documentation on SQL keywords and functions
3. **Code Completion** - SQL keyword and table name suggestions
4. **Formatting** - Automatic SQL formatting
5. **Go to Definition** - Navigate to table/column definitions
6. **Signature Help** - Function parameter information

### IDE Configuration

#### Visual Studio Code

Create `.vscode/settings.json`:

```json
{
  "gosqlx.lsp.enable": true,
  "gosqlx.lsp.command": "gosqlx",
  "gosqlx.lsp.args": ["lsp"],
  "gosqlx.lsp.trace": "verbose"
}
```

Install the GoSQLX extension or configure a generic LSP client:

```json
{
  "genericLsp.languageServers": [
    {
      "languageId": "sql",
      "command": "gosqlx",
      "args": ["lsp"],
      "settings": {}
    }
  ]
}
```

#### Neovim (with nvim-lspconfig)

Add to your Neovim configuration:

```lua
local lspconfig = require('lspconfig')
local configs = require('lspconfig.configs')

-- Define GoSQLX LSP
if not configs.gosqlx then
  configs.gosqlx = {
    default_config = {
      cmd = {'gosqlx', 'lsp'},
      filetypes = {'sql'},
      root_dir = lspconfig.util.root_pattern('.gosqlx.yml', '.git'),
      settings = {},
    },
  }
end

-- Enable GoSQLX LSP
lspconfig.gosqlx.setup{}
```

#### Emacs (with lsp-mode)

Add to your Emacs configuration:

```elisp
(require 'lsp-mode)

(add-to-list 'lsp-language-id-configuration '(sql-mode . "sql"))

(lsp-register-client
 (make-lsp-client
  :new-connection (lsp-stdio-connection '("gosqlx" "lsp"))
  :major-modes '(sql-mode)
  :server-id 'gosqlx))

(add-hook 'sql-mode-hook #'lsp)
```

#### Sublime Text (with LSP package)

Add to LSP settings:

```json
{
  "clients": {
    "gosqlx": {
      "enabled": true,
      "command": ["gosqlx", "lsp"],
      "selector": "source.sql"
    }
  }
}
```

### Using LSP Programmatically

```go
import (
    "context"
    "github.com/ajitpratap0/GoSQLX/pkg/lsp"
)

func RunLSPServer() error {
    // Create LSP server
    server := lsp.NewServer()

    // Configure server
    server.SetLogFile("/tmp/gosqlx-lsp.log")
    server.SetVerbose(true)

    // Start server (stdio mode)
    ctx := context.Background()
    if err := server.Start(ctx); err != nil {
        return fmt.Errorf("LSP server failed: %w", err)
    }

    return nil
}
```

### LSP Diagnostics Example

When you type invalid SQL in your IDE:

```sql
SELECT * FROM users WHRE id = 1
                    ^^^^
-- Diagnostic: Unknown keyword 'WHRE'. Did you mean 'WHERE'?
```

The LSP server provides:
- Real-time error highlighting
- Helpful error messages
- Suggested fixes

For complete LSP documentation, see [LSP_GUIDE.md](./LSP_GUIDE.md).

## CLI Tool Usage (v1.6.0)

GoSQLX v1.6.0 includes a comprehensive CLI tool for SQL operations:

### Installation

```bash
# Install from source
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest

# Or build locally
cd cmd/gosqlx
go build -o gosqlx
```

### Validate Command

Validate SQL syntax:

```bash
# Validate SQL string
gosqlx validate "SELECT * FROM users WHERE active = true"

# Validate SQL file
gosqlx validate query.sql

# Validate with detailed output
gosqlx validate --verbose query.sql

# Validate multiple files
gosqlx validate query1.sql query2.sql query3.sql
```

### Format Command

Format SQL with intelligent indentation:

```bash
# Format and print to stdout
gosqlx format query.sql

# Format in-place (overwrite file)
gosqlx format -i query.sql
gosqlx format --in-place query.sql

# Format with custom indent
gosqlx format --indent 4 query.sql

# Format multiple files
gosqlx format -i *.sql
```

Example formatting:

```sql
# Before:
SELECT u.id,u.name,o.total FROM users u JOIN orders o ON u.id=o.user_id WHERE u.active=true

# After:
SELECT
  u.id,
  u.name,
  o.total
FROM users u
JOIN orders o ON u.id = o.user_id
WHERE u.active = true
```

### Analyze Command

Analyze SQL structure and complexity:

```bash
# Analyze SQL string
gosqlx analyze "SELECT COUNT(*) FROM orders GROUP BY status"

# Analyze SQL file
gosqlx analyze complex_query.sql

# Analyze with JSON output
gosqlx analyze --format json query.sql
```

Example output:

```
SQL Analysis Results:
  Query Type: SELECT
  Table Count: 3
  Join Count: 2
  Subquery Count: 1
  Complexity: Medium
  Estimated Execution: Fast
```

### Parse Command

Parse SQL to AST representation:

```bash
# Parse with default output
gosqlx parse query.sql

# Parse with JSON format
gosqlx parse --format json query.sql

# Parse with pretty-printed JSON
gosqlx parse -f json --pretty query.sql

# Parse and save to file
gosqlx parse -f json -o output.json query.sql
```

### Lint Command

Run SQL linter:

```bash
# Lint SQL file
gosqlx lint query.sql

# Lint with specific rules
gosqlx lint --rules L001,L002,L003 query.sql

# Lint with configuration file
gosqlx lint --config .gosqlx.yml query.sql

# Lint all SQL files in directory
gosqlx lint *.sql
```

### Security Scan Command

Scan for SQL injection patterns:

```bash
# Scan SQL file
gosqlx security scan query.sql

# Scan with severity threshold
gosqlx security scan --severity high user_input.sql

# Scan and output JSON report
gosqlx security scan --format json --output report.json query.sql
```

### LSP Command

Start LSP server (covered in LSP Integration section):

```bash
# Start LSP server
gosqlx lsp

# Start with logging
gosqlx lsp --log /tmp/lsp.log --verbose
```

### Configuration

Create `.gosqlx.yml` in your project root:

```yaml
# SQL dialect
dialect: postgresql

# Formatting options
formatting:
  indent: 2
  uppercase_keywords: true
  max_line_length: 80

# Linting configuration
linting:
  enabled: true
  rules:
    L001: true
    L002: true
    L003: true

# Security scanning
security:
  enabled: true
  severity_threshold: medium

# LSP configuration
lsp:
  diagnostics_enabled: true
  completion_enabled: true
  hover_enabled: true
```

For complete configuration documentation, see [CONFIGURATION.md](./CONFIGURATION.md).

### CLI Examples

**Validate and format a query:**

```bash
# Validate first
gosqlx validate query.sql

# If valid, format it
gosqlx format -i query.sql
```

**Complete SQL workflow:**

```bash
# 1. Format the SQL
gosqlx format -i migrations/*.sql

# 2. Lint for style issues
gosqlx lint migrations/*.sql

# 3. Security scan
gosqlx security scan migrations/*.sql

# 4. Validate syntax
gosqlx validate migrations/*.sql
```

**CI/CD Integration:**

```bash
#!/bin/bash
# SQL quality check script

echo "Validating SQL files..."
gosqlx validate sql/*.sql || exit 1

echo "Running linter..."
gosqlx lint sql/*.sql || exit 1

echo "Security scan..."
gosqlx security scan --severity high sql/*.sql || exit 1

echo "All checks passed!"
```

## Real-World Examples

### SQL Validator

Build a SQL validation service:

```go
type SQLValidator struct {
    // Configuration
    maxQueryLength int
    allowedDialects []string
}

func (v *SQLValidator) Validate(sql string) (*ValidationResult, error) {
    result := &ValidationResult{
        IsValid: true,
        Warnings: []string{},
        Errors: []string{},
    }
    
    // Check length
    if len(sql) > v.maxQueryLength {
        result.Errors = append(result.Errors, 
            fmt.Sprintf("Query exceeds maximum length of %d", 
                v.maxQueryLength))
        result.IsValid = false
        return result, nil
    }
    
    // Tokenize
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        result.Errors = append(result.Errors, err.Error())
        result.IsValid = false
        return result, nil
    }
    
    // Analyze tokens
    v.analyzeTokens(tokens, result)
    
    return result, nil
}

func (v *SQLValidator) analyzeTokens(tokens []models.TokenWithSpan, 
    result *ValidationResult) {
    
    var hasSelect, hasFrom bool
    var tableCount int
    
    for _, token := range tokens {
        switch token.Token.Type {
        case models.TokenTypeSelect:
            hasSelect = true
        case models.TokenTypeFrom:
            hasFrom = true
        case models.TokenTypeIdentifier:
            if hasFrom && !hasSelect {
                tableCount++
            }
        case models.TokenTypeSemicolon:
            result.Warnings = append(result.Warnings,
                "Query contains semicolon - ensure single statement")
        }
    }
    
    if hasSelect && !hasFrom {
        result.Warnings = append(result.Warnings,
            "SELECT without FROM clause")
    }
}
```

### Query Analyzer

Analyze query complexity and provide metrics:

```go
type QueryMetrics struct {
    TokenCount     int
    TableCount     int
    JoinCount      int
    WhereComplexity int
    HasSubquery    bool
    EstimatedCost  string
}

func AnalyzeQuery(sql string) (*QueryMetrics, error) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        return nil, err
    }
    
    metrics := &QueryMetrics{
        TokenCount: len(tokens) - 1, // Exclude EOF
    }
    
    for i, token := range tokens {
        switch token.Token.Type {
        case models.TokenTypeJoin:
            metrics.JoinCount++
        case models.TokenTypeWhere:
            metrics.WhereComplexity = 
                calculateWhereComplexity(tokens[i:])
        case models.TokenTypeLParen:
            if i > 0 && tokens[i-1].Token.Type == models.TokenTypeSelect {
                metrics.HasSubquery = true
            }
        }
    }
    
    metrics.EstimatedCost = estimateCost(metrics)
    return metrics, nil
}
```

### SQL Formatter

Format SQL for better readability:

```go
type SQLFormatter struct {
    indentSize   int
    uppercase    bool
    alignColumns bool
}

func (f *SQLFormatter) Format(sql string) (string, error) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        return "", err
    }
    
    var formatted strings.Builder
    indent := 0
    
    for i, token := range tokens {
        if token.Token.Type == models.TokenTypeEOF {
            break
        }
        
        // Handle keywords
        if isKeyword(token.Token.Type) {
            if f.uppercase {
                token.Token.Value = strings.ToUpper(token.Token.Value)
            }
            
            // Add newline before certain keywords
            if shouldNewlineBefore(token.Token.Type) {
                formatted.WriteString("\n")
                formatted.WriteString(strings.Repeat(" ", indent))
            }
        }
        
        formatted.WriteString(token.Token.Value)
        
        // Add space after token (unless it's punctuation)
        if !isPunctuation(token.Token.Type) && 
           i < len(tokens)-2 && 
           !isPunctuation(tokens[i+1].Token.Type) {
            formatted.WriteString(" ")
        }
    }
    
    return formatted.String(), nil
}
```

## SQL Dialect Support

### PostgreSQL Specific Features (v1.6.0 Enhanced)

GoSQLX v1.6.0 significantly enhances PostgreSQL support:

```go
// LATERAL JOIN - correlated subqueries in FROM clause
sql := `SELECT u.name, r.order_date
        FROM users u,
        LATERAL (SELECT * FROM orders WHERE user_id = u.id LIMIT 3) r`

// JSON/JSONB operators - comprehensive support
sql := `SELECT
        data->>'name' as name,                    -- Get field as text
        data->'address'->>'city' as city,         -- Nested access
        data @> '{"active": true}' as is_active,  -- Contains
        data ? 'email' as has_email               -- Key exists
        FROM users`

// DISTINCT ON - PostgreSQL-specific row selection
sql := `SELECT DISTINCT ON (dept_id) dept_id, name, salary
        FROM employees
        ORDER BY dept_id, salary DESC`

// FILTER clause - conditional aggregation
sql := `SELECT
        COUNT(*) FILTER (WHERE status = 'active') AS active_count,
        SUM(amount) FILTER (WHERE type = 'credit') AS credits
        FROM transactions`

// Aggregate ORDER BY - STRING_AGG, ARRAY_AGG
sql := `SELECT dept_id,
        STRING_AGG(name, ', ' ORDER BY hire_date DESC) as employees
        FROM employees GROUP BY dept_id`

// RETURNING clause - return modified rows
sql := `INSERT INTO users (name, email)
        VALUES ('John', 'john@example.com')
        RETURNING id, created_at`

// Array operators
sql := `SELECT * FROM users WHERE tags @> ARRAY['admin', 'moderator']`

// Dollar-quoted strings
sql := `CREATE FUNCTION test() RETURNS text AS $$
BEGIN
    RETURN 'Hello';
END;
$$ LANGUAGE plpgsql;`

// FETCH FIRST/OFFSET (SQL:2008 standard, PostgreSQL compatible)
sql := `SELECT * FROM users
        ORDER BY created_at DESC
        OFFSET 10 ROWS
        FETCH FIRST 20 ROWS ONLY`
```

### MySQL Specific Features

```go
// Backtick identifiers
sql := "SELECT `user_id`, `first name` FROM `users`"

// LIMIT with offset
sql := "SELECT * FROM users LIMIT 10, 20"

// Double-double quotes for escaping
sql := `SELECT * FROM users WHERE name = "John""s Pizza"`
```

### SQL Server Specific Features

```go
// Square bracket identifiers
sql := "SELECT [user_id], [first name] FROM [users]"

// TOP clause
sql := "SELECT TOP 10 * FROM users ORDER BY created_at DESC"

// WITH (NOLOCK) hint
sql := "SELECT * FROM users WITH (NOLOCK) WHERE active = 1"
```

### Oracle Specific Features

```go
// ROWNUM
sql := "SELECT * FROM users WHERE ROWNUM <= 10"

// Dual table
sql := "SELECT SYSDATE FROM dual"

// Connect by
sql := `SELECT level, employee_id 
        FROM employees 
        CONNECT BY PRIOR employee_id = manager_id`
```

## Unicode and International Support

### Multi-Language Identifiers

```go
examples := []string{
    // Japanese
    `SELECT "名前", "年齢" FROM "ユーザー" WHERE "国" = '日本'`,
    
    // Chinese
    `SELECT "姓名", "电话" FROM "客户" WHERE "城市" = '北京'`,
    
    // Russian
    `SELECT "имя", "фамилия" FROM "пользователи" WHERE "город" = 'Москва'`,
    
    // Arabic
    `SELECT "الاسم", "العمر" FROM "المستخدمون" WHERE "المدينة" = 'دبي'`,
    
    // Korean
    `SELECT "이름", "나이" FROM "사용자" WHERE "도시" = '서울'`,
    
    // Mixed languages
    `SELECT "name_英文", "名前_日本語", "имя_русский" FROM international_users`,
}

for _, sql := range examples {
    tkz := tokenizer.GetTokenizer()
    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        log.Printf("Failed to tokenize: %v", err)
    }
    tokenizer.PutTokenizer(tkz)
}
```

### Emoji Support

```go
// Emojis in string literals
sql := `INSERT INTO messages (content, reaction) VALUES ('Hello! 👋', '😊')`

// Emojis in comments
sql := `-- This query finds happy users 😊
SELECT * FROM users WHERE mood = 'happy'`
```

## Performance Optimization

### Reuse Tokenizers for Batch Operations

```go
func OptimizedBatchProcess(queries []string) error {
    // Single tokenizer for all queries
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    for _, query := range queries {
        tkz.Reset() // Reset state between queries
        
        tokens, err := tkz.Tokenize([]byte(query))
        if err != nil {
            return err
        }
        
        // Process tokens...
    }
    
    return nil
}
```

### Pre-allocate Slices

```go
func ProcessWithPreallocation(sql string) error {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        return err
    }

    // Convert tokens using the proper converter
    converter := parser.NewTokenConverter()
    result, err := converter.Convert(tokens)
    if err != nil {
        return err
    }

    // Parse with pre-converted tokens
    p := parser.NewParser()
    defer p.Release()

    _, err = p.Parse(result.Tokens)
    return err
}
```

### Avoid String Concatenation in Loops

```go
// BAD: String concatenation
func BadFormat(tokens []models.TokenWithSpan) string {
    result := ""
    for _, token := range tokens {
        result += token.Token.Value + " " // Allocates new string each time
    }
    return result
}

// GOOD: Use strings.Builder
func GoodFormat(tokens []models.TokenWithSpan) string {
    var builder strings.Builder
    builder.Grow(len(tokens) * 10) // Pre-allocate estimated size
    
    for _, token := range tokens {
        builder.WriteString(token.Token.Value)
        builder.WriteByte(' ')
    }
    return builder.String()
}
```

## Common Patterns

### Query Type Detection

```go
func DetectQueryType(sql string) (string, error) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        return "", err
    }
    
    for _, token := range tokens {
        switch token.Token.Type {
        case models.TokenTypeSelect:
            return "SELECT", nil
        case models.TokenTypeInsert:
            return "INSERT", nil
        case models.TokenTypeUpdate:
            return "UPDATE", nil
        case models.TokenTypeDelete:
            return "DELETE", nil
        case models.TokenTypeCreate:
            return "DDL", nil
        case models.TokenTypeAlter:
            return "DDL", nil
        case models.TokenTypeDrop:
            return "DDL", nil
        }
    }
    
    return "UNKNOWN", nil
}
```

### Table Extraction

```go
func ExtractTables(sql string) ([]string, error) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        return nil, err
    }
    
    tables := make([]string, 0)
    expectTable := false
    
    for _, token := range tokens {
        if token.Token.Type == models.TokenTypeFrom ||
           token.Token.Type == models.TokenTypeJoin ||
           token.Token.Type == models.TokenTypeInto {
            expectTable = true
            continue
        }
        
        if expectTable && token.Token.Type == models.TokenTypeIdentifier {
            tables = append(tables, token.Token.Value)
            expectTable = false
        }
    }
    
    return tables, nil
}
```

### Column Extraction

```go
func ExtractColumns(sql string) ([]string, error) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        return nil, err
    }
    
    columns := make([]string, 0)
    inSelect := false
    
    for i, token := range tokens {
        if token.Token.Type == models.TokenTypeSelect {
            inSelect = true
            continue
        }
        
        if token.Token.Type == models.TokenTypeFrom {
            inSelect = false
            break
        }
        
        if inSelect && token.Token.Type == models.TokenTypeIdentifier {
            // Skip if it's an alias (preceded by AS)
            if i > 0 && tokens[i-1].Token.Type != models.TokenTypeAs {
                columns = append(columns, token.Token.Value)
            }
        }
    }
    
    return columns, nil
}
```

## Testing Your Implementation

### Unit Test Example

```go
func TestTokenization(t *testing.T) {
    testCases := []struct {
        name     string
        sql      string
        expected int // expected token count
    }{
        {"Simple SELECT", "SELECT * FROM users", 5},
        {"With WHERE", "SELECT * FROM users WHERE id = 1", 9},
        {"Join query", "SELECT * FROM a JOIN b ON a.id = b.id", 13},
    }
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            tkz := tokenizer.GetTokenizer()
            defer tokenizer.PutTokenizer(tkz)
            
            tokens, err := tkz.Tokenize([]byte(tc.sql))
            if err != nil {
                t.Fatalf("Unexpected error: %v", err)
            }
            
            // -1 for EOF token
            if len(tokens)-1 != tc.expected {
                t.Errorf("Expected %d tokens, got %d",
                    tc.expected, len(tokens)-1)
            }
        })
    }
}
```

### Benchmark Example

```go
func BenchmarkTokenization(b *testing.B) {
    sql := []byte("SELECT u.id, u.name FROM users u WHERE u.active = true")
    
    b.ReportAllocs()
    b.ResetTimer()
    
    for i := 0; i < b.N; i++ {
        tkz := tokenizer.GetTokenizer()
        tokens, _ := tkz.Tokenize(sql)
        _ = tokens
        tokenizer.PutTokenizer(tkz)
    }
}
```

## Best Practices Summary (v1.6.0)

### Memory Management
1. **Always use defer** for returning objects to pools (critical for performance)
2. **Reset tokenizers** between uses in batch operations
3. **Pre-allocate slices** when size is known
4. **Use strings.Builder** for string concatenation

### Error Handling & Debugging
5. **Handle errors** with position information for better debugging
6. **Use security scanner** (`security.ScanSQL()`) on user-provided SQL
7. **Validate input** before tokenization for better error messages
8. **Enable LSP** in your IDE for real-time error detection

### Code Quality
9. **Run linter** regularly to enforce SQL style guidelines
10. **Test with Unicode** and special characters for international support
11. **Document SQL dialect** requirements in your application
12. **Use configuration files** (`.gosqlx.yml`) for consistent team settings

### Performance
13. **Benchmark critical paths** to ensure performance (target: 1M+ ops/sec)
14. **Use concurrent processing** for independent queries
15. **Monitor with metrics** package for production observability
16. **Leverage object pooling** for 60-80% memory reduction

### CI/CD Integration
17. **Validate SQL** in CI/CD pipelines with `gosqlx validate`
18. **Format SQL** consistently with `gosqlx format -i`
19. **Security scan** all SQL files with `gosqlx security scan`
20. **Lint SQL** files to catch style issues early

### PostgreSQL-Specific (v1.6.0)
21. **Use LATERAL JOIN** for correlated subqueries instead of nested SELECTs
22. **Use FILTER clause** instead of CASE expressions for conditional aggregates
23. **Use DISTINCT ON** for efficient row deduplication
24. **Use RETURNING** to reduce round-trips to database
25. **Leverage JSON operators** for efficient JSON document querying

### Development Workflow
26. **Start LSP server** (`gosqlx lsp`) for IDE integration
27. **Use CLI tools** for quick validation and formatting during development
28. **Create test files** with real-world SQL for regression testing
29. **Profile memory usage** in production with pprof integration
30. **Keep dependencies updated** for latest PostgreSQL features

Example comprehensive workflow:

```bash
# 1. Format all SQL files
gosqlx format -i sql/**/*.sql

# 2. Run linter with configuration
gosqlx lint --config .gosqlx.yml sql/**/*.sql

# 3. Security scan with high severity threshold
gosqlx security scan --severity high sql/**/*.sql

# 4. Validate all files
gosqlx validate sql/**/*.sql

# 5. Run Go tests with race detection
go test -race ./...

# 6. Benchmark performance
go test -bench=. -benchmem ./pkg/sql/parser/
```