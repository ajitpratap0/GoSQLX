# GoSQLX Usage Guide

**Version**: v1.5.1+ | **Last Updated**: November 2025

## Table of Contents
- [Getting Started](#getting-started)
- [Simple API (Recommended)](#simple-api-recommended)
- [Basic Usage](#basic-usage)
- [Advanced SQL Features (v1.4+)](#advanced-sql-features-v14)
- [SQL Injection Detection](#sql-injection-detection)
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
Go 1.24 or higher is required.

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
    "github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

func ParseSQL(sql string) error {
    // Step 1: Tokenize
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        return err
    }
    
    // Step 2: Convert to parser tokens
    parserTokens := make([]token.Token, 0, len(tokens))
    for _, tok := range tokens {
        if tok.Token.Type == models.TokenTypeEOF {
            break
        }
        parserTokens = append(parserTokens, token.Token{
            Type:    fmt.Sprintf("%d", tok.Token.Type),
            Literal: tok.Token.Value,
        })
    }
    
    // Step 3: Parse
    p := parser.NewParser()
    defer p.Release()
    
    ast, err := p.Parse(parserTokens)
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
        if tkErr, ok := err.(tokenizer.TokenizerError); ok {
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

## Advanced SQL Features (v1.4+)

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

## SQL Injection Detection

GoSQLX includes a built-in security scanner (`pkg/sql/security`) for detecting SQL injection patterns:

```go
import (
    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/security"
)

func CheckForInjection(sql string) {
    // Parse the SQL first
    ast, err := gosqlx.Parse(sql)
    if err != nil {
        fmt.Println("Parse error:", err)
        return
    }

    // Create scanner and scan for injection patterns
    scanner := security.NewScanner()
    result := scanner.Scan(ast)

    // Check results
    if result.HasCritical() {
        fmt.Printf("CRITICAL: Found %d critical security issues!\n", result.CriticalCount)
    }
    if result.HasHigh() {
        fmt.Printf("HIGH: Found %d high-severity issues\n", result.HighCount)
    }

    // Print all findings
    for _, finding := range result.Findings {
        fmt.Printf("[%s] %s: %s\n",
            finding.Severity,
            finding.Pattern,
            finding.Description)
    }
}
```

### Detected Injection Patterns

The security scanner detects:
- **Tautology patterns**: `1=1`, `'a'='a'`, always-true conditions
- **UNION-based injection**: Unauthorized UNION statements
- **Time-based blind injection**: `SLEEP()`, `WAITFOR DELAY`
- **Comment bypass**: `--`, `/**/` comment abuse
- **Stacked queries**: Multiple statement injection
- **Dangerous functions**: `xp_cmdshell`, `LOAD_FILE`, `INTO OUTFILE`

```go
// Example: Check user input for injection
func ValidateUserQuery(userInput string) error {
    ast, err := gosqlx.Parse(userInput)
    if err != nil {
        return fmt.Errorf("invalid SQL syntax: %w", err)
    }

    scanner := security.NewScanner()
    result := scanner.Scan(ast)

    if result.HasCritical() || result.HasHigh() {
        return fmt.Errorf("potential SQL injection detected: %d issues found",
            result.CriticalCount + result.HighCount)
    }

    return nil
}
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

### PostgreSQL Specific Features

```go
// Array operators
sql := `SELECT * FROM users WHERE tags @> ARRAY['admin', 'moderator']`

// JSON operators
sql := `SELECT data->>'name' FROM users WHERE data @> '{"active": true}'`

// Dollar-quoted strings
sql := `CREATE FUNCTION test() RETURNS text AS $$
BEGIN
    RETURN 'Hello';
END;
$$ LANGUAGE plpgsql;`
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
func ProcessWithPreallocation(sql string, expectedTokens int) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    tokens, _ := tkz.Tokenize([]byte(sql))
    
    // Pre-allocate with expected capacity
    parserTokens := make([]token.Token, 0, expectedTokens)
    
    for _, tok := range tokens {
        if tok.Token.Type == models.TokenTypeEOF {
            break
        }
        parserTokens = append(parserTokens, convertToken(tok))
    }
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

## Best Practices Summary

1. **Always use defer** for returning objects to pools
2. **Reset tokenizers** between uses in batch operations
3. **Pre-allocate slices** when size is known
4. **Use strings.Builder** for string concatenation
5. **Handle errors** with position information for better debugging
6. **Test with Unicode** and special characters
7. **Benchmark critical paths** to ensure performance
8. **Use concurrent processing** for independent queries
9. **Validate input** before tokenization for better error messages
10. **Document SQL dialect** requirements in your application