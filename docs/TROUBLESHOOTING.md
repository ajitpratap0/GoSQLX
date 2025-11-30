# GoSQLX Troubleshooting Guide

## Table of Contents
- [Common Issues](#common-issues)
- [Error Codes Reference](#error-codes-reference)
- [Performance Issues](#performance-issues)
- [Memory Issues](#memory-issues)
- [Debugging Techniques](#debugging-techniques)
- [FAQ](#faq)

## Common Issues

### Issue: "panic: runtime error: invalid memory address or nil pointer dereference"

**Symptom:** Application crashes when processing SQL

**Cause:** Not properly handling returned objects from pools

**Solution:**
```go
// WRONG - May cause panic
func BadExample() {
    var tkz *tokenizer.Tokenizer
    tokens, _ := tkz.Tokenize([]byte("SELECT * FROM users")) // PANIC!
}

// CORRECT - Always get from pool
func GoodExample() {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    tokens, _ := tkz.Tokenize([]byte("SELECT * FROM users"))
}
```

### Issue: "Resource leak detected"

**Symptom:** Memory usage grows over time

**Cause:** Not returning pooled objects

**Solution:**
```go
// WRONG - Leaks resources
func LeakyFunction(sql string) error {
    tkz := tokenizer.GetTokenizer()
    // Missing: defer tokenizer.PutTokenizer(tkz)
    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        return err // Tokenizer never returned!
    }
    return nil
}

// CORRECT - Always use defer
func FixedFunction(sql string) error {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    tokens, _ := tkz.Tokenize([]byte(sql))
    _ = tokens
    return nil
}
```

### Issue: "Concurrent map read and write"

**Symptom:** Race condition detected

**Cause:** Sharing tokenizer instances across goroutines

**Solution:**
```go
// WRONG - Shared tokenizer
func ConcurrentBad(queries []string) {
    tkz := tokenizer.GetTokenizer() // Shared!
    defer tokenizer.PutTokenizer(tkz)
    
    var wg sync.WaitGroup
    for _, sql := range queries {
        wg.Add(1)
        go func(q string) {
            defer wg.Done()
            tokens, _ := tkz.Tokenize([]byte(q)) // RACE!
        }(sql)
    }
    wg.Wait()
}

// CORRECT - Each goroutine gets its own
func ConcurrentGood(queries []string) {
    var wg sync.WaitGroup
    for _, sql := range queries {
        wg.Add(1)
        go func(q string) {
            defer wg.Done()
            
            tkz := tokenizer.GetTokenizer() // Own instance
            defer tokenizer.PutTokenizer(tkz)
            
            tokens, _ := tkz.Tokenize([]byte(q))
        }(sql)
    }
    wg.Wait()
}
```

## Error Codes Reference

### Tokenizer Errors (E1xxx)

**E1001 - Unexpected Character**
```
Error E1001 at line 1, column 5: unexpected character: #
```
- **Cause:** Invalid character in SQL
- **Fix:** Use standard SQL syntax, quote special characters

**E1002 - Unterminated String**
```sql
-- WRONG
SELECT * FROM users WHERE name = 'John;

-- CORRECT
SELECT * FROM users WHERE name = 'John''s Pizza';
```

**E1003 - Invalid Number**
- **Cause:** Malformed numeric literal (e.g., `1.2.3`, `1e2e3`)
- **Fix:** Use valid numeric formats

**E1004 - Invalid Operator**
- **Cause:** Invalid operator sequence
- **Fix:** Check operator syntax for your SQL dialect

**E1005 - Invalid Identifier**
- **Cause:** Malformed identifier (e.g., unclosed quotes)
- **Fix:** Ensure all quoted identifiers are properly closed

**E1006 - Input Too Large**
- **Cause:** SQL input exceeds size limits (DoS protection)
- **Fix:** Split large queries or increase limits if appropriate

**E1007 - Token Limit Reached**
- **Cause:** Too many tokens generated (DoS protection)
- **Fix:** Simplify query or increase limits

**E1008 - Tokenizer Panic**
- **Cause:** Internal tokenizer error (recovered panic)
- **Fix:** Report bug with SQL that triggers this

### Parser Errors (E2xxx)

**E2001 - Unexpected Token**
```
Error E2001 at line 1, column 15: unexpected token: LIMIT
```
- **Cause:** Token not valid in current context
- **Fix:** Check SQL syntax, verify keyword order

**E2002 - Expected Token**
```
Error E2002 at line 1, column 20: expected FROM but got WHERE
```
- **Fix:** Add missing required keyword

**E2003 - Missing Clause**
- **Cause:** Required SQL clause missing (e.g., SELECT without FROM)
- **Fix:** Add required clause

**E2004 - Invalid Syntax**
- **Cause:** General syntax error
- **Fix:** Review SQL syntax for your dialect

**E2005 - Incomplete Statement**
- **Cause:** Statement ends unexpectedly
- **Fix:** Complete the SQL statement

**E2006 - Invalid Expression**
- **Cause:** Expression syntax error
- **Fix:** Check expression syntax (operators, parentheses)

**E2007 - Recursion Depth Limit**
- **Cause:** Query too deeply nested (DoS protection)
- **Fix:** Simplify nested expressions

**E2008 - Unsupported Data Type**
- **Cause:** Data type not yet supported
- **Fix:** Use supported data type or report feature request

**E2009 - Unsupported Constraint**
- **Cause:** Constraint type not supported
- **Fix:** Use supported constraint or report feature request

**E2010 - Unsupported Join**
- **Cause:** JOIN type not supported
- **Fix:** Use supported JOIN type

**E2011 - Invalid CTE**
- **Cause:** WITH clause syntax error
- **Fix:** Check CTE syntax (column list, recursion)

**E2012 - Invalid Set Operation**
- **Cause:** UNION/EXCEPT/INTERSECT syntax error
- **Fix:** Verify set operation syntax

### Semantic Errors (E3xxx)

**E3001 - Undefined Table**
- **Cause:** Table reference not found
- **Fix:** Define table or check spelling

**E3002 - Undefined Column**
- **Cause:** Column reference not found
- **Fix:** Check column exists in table

**E3003 - Type Mismatch**
- **Cause:** Expression type incompatibility
- **Fix:** Cast or convert types appropriately

**E3004 - Ambiguous Column**
- **Cause:** Column name exists in multiple tables
- **Fix:** Use table qualifier (e.g., `users.id`)

### Feature Errors (E4xxx)

**E4001 - Unsupported Feature**
- **Cause:** Feature not yet implemented
- **Fix:** Report feature request or use alternative

**E4002 - Unsupported Dialect**
- **Cause:** SQL dialect not fully supported
- **Fix:** Use standard SQL or report dialect feature request

## Performance Issues

### Slow Parsing/Tokenization

**Common Causes:**
- Very large SQL queries (>1MB)
- Not reusing tokenizers from pool
- Processing in tight loops

**Solutions:**

```go
// 1. Reuse tokenizers for batch processing
func BatchProcess(queries []string) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    for _, sql := range queries {
        tkz.Reset()
        tokens, _ := tkz.Tokenize([]byte(sql))
        // Process...
    }
}

// 2. Parallel processing with worker pool
func ParallelProcess(queries []string) {
    numWorkers := runtime.NumCPU()
    work := make(chan string, len(queries))

    for _, sql := range queries {
        work <- sql
    }
    close(work)

    var wg sync.WaitGroup
    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            tkz := tokenizer.GetTokenizer()
            defer tokenizer.PutTokenizer(tkz)

            for sql := range work {
                tkz.Reset()
                tokens, _ := tkz.Tokenize([]byte(sql))
                // Process...
            }
        }()
    }
    wg.Wait()
}

// 3. Limit input size
const MaxQuerySize = 1_000_000 // 1MB
if len(sql) > MaxQuerySize {
    return fmt.Errorf("query too large: %d bytes", len(sql))
}
```

**Profiling:**
```bash
# CPU profiling
go test -bench=. -cpuprofile=cpu.prof
go tool pprof cpu.prof

# Memory profiling
go test -bench=. -memprofile=mem.prof
go tool pprof mem.prof

# Live profiling
import _ "net/http/pprof"
# Visit http://localhost:6060/debug/pprof/
```

## Memory Issues

### Common Leak Patterns

**1. Storing pooled objects:**
```go
// WRONG - Stores pooled object
type BadCache struct {
    tokenizer *tokenizer.Tokenizer
}

func (c *BadCache) Init() {
    c.tokenizer = tokenizer.GetTokenizer() // Never returned!
}

// CORRECT - Get when needed
type GoodCache struct{}

func (c *GoodCache) Process(sql string) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    tokens, _ := tkz.Tokenize([]byte(sql))
    _ = tokens
}
```

**2. Goroutines without defer:**
```go
// WRONG - May leak on panic
func LeakyAsync(sql string) {
    go func() {
        tkz := tokenizer.GetTokenizer()
        tokens, _ := tkz.Tokenize([]byte(sql))
        tokenizer.PutTokenizer(tkz)
    }()
}

// CORRECT - Always use defer
func SafeAsync(sql string) {
    go func() {
        tkz := tokenizer.GetTokenizer()
        defer tokenizer.PutTokenizer(tkz)
        tokens, _ := tkz.Tokenize([]byte(sql))
        _ = tokens
    }()
}
```

### Memory Monitoring

```go
func MonitorMemory() {
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    fmt.Printf("Alloc: %d MB, NumGC: %d\n", m.Alloc/1024/1024, m.NumGC)
}

func DetectLeak() {
    var m runtime.MemStats
    runtime.GC()
    runtime.ReadMemStats(&m)
    baseline := m.Alloc

    for i := 0; i < 1000; i++ {
        tkz := tokenizer.GetTokenizer()
        tkz.Tokenize([]byte("SELECT * FROM users"))
        tokenizer.PutTokenizer(tkz)
    }

    runtime.GC()
    runtime.ReadMemStats(&m)
    leaked := m.Alloc - baseline
    fmt.Printf("Potential leak: %d bytes\n", leaked)
}
```

## Debugging Techniques

### Token Stream Analysis

```go
func AnalyzeTokenStream(sql string) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }

    for i, token := range tokens {
        if token.Token.Type == models.TokenTypeEOF {
            break
        }
        fmt.Printf("%3d | Type: %3d | L%d:C%d | %q\n",
            i, token.Token.Type, token.Start.Line,
            token.Start.Column, token.Token.Value)
    }
}
```

### Parser Testing

```go
func TestParser(sql string) {
    // Tokenize
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        fmt.Printf("Tokenization error: %v\n", err)
        return
    }

    // Convert tokens
    parserTokens, err := parser.ConvertTokensForParser(tokens)
    if err != nil {
        fmt.Printf("Token conversion error: %v\n", err)
        return
    }

    // Parse
    p := parser.NewParser()
    astTree, err := p.Parse(parserTokens)
    if err != nil {
        fmt.Printf("Parse error: %v\n", err)
        return
    }
    defer ast.ReleaseAST(astTree)

    fmt.Printf("Parsed successfully: %d statements\n", len(astTree.Statements))
}
```

### Security Scanning

```go
import "github.com/ajitpratap0/GoSQLX/pkg/sql/security"

func CheckSQLSecurity(sql string) {
    scanner := security.NewScanner()
    result := scanner.Scan(sql)

    if result.HasHighOrAbove() {
        fmt.Printf("Security issues found:\n")
        for _, finding := range result.Findings {
            fmt.Printf("- [%s] %s\n", finding.Severity, finding.Description)
        }
    }
}
```

## FAQ

### Q: Why does my application panic?

**A:** Always get tokenizer from pool:
```go
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)
```

### Q: Can I modify tokens after tokenization?

**A:** Yes, tokens are copies and can be safely modified:
```go
tokens, _ := tkz.Tokenize([]byte(sql))
for i := range tokens {
    if tokens[i].Token.Type == models.TokenTypeIdentifier {
        tokens[i].Token.Value = strings.ToUpper(tokens[i].Token.Value)
    }
}
```

### Q: How do I handle large SQL files (>10MB)?

**A:** Stream and process in chunks:
```go
func ProcessLargeFile(filename string) error {
    file, _ := os.Open(filename)
    defer file.Close()

    scanner := bufio.NewScanner(file)
    scanner.Split(SplitOnSemicolon) // Custom splitter

    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    for scanner.Scan() {
        tkz.Reset()
        tokens, _ := tkz.Tokenize([]byte(scanner.Text()))
        // Process tokens...
    }
    return scanner.Err()
}
```

### Q: How do I test for race conditions?

**A:** Use Go's race detector:
```bash
go test -race ./...
go run -race main.go
```

### Q: Can I use GoSQLX with database/sql?

**A:** Yes, use it to validate queries before execution:
```go
func ValidateBeforeExecute(db *sql.DB, query string) error {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    if _, err := tkz.Tokenize([]byte(query)); err != nil {
        return fmt.Errorf("invalid SQL: %v", err)
    }

    _, err := db.Exec(query)
    return err
}
```

### Q: How do I contribute bug fixes?

**A:** Submit an issue with:
- Go version and GoSQLX version
- Minimal reproduction case with SQL
- Full error message
- Sample code

## Getting Help

1. Check test suite for usage examples
2. Review benchmarks for performance patterns
3. Enable debug logging (see Debugging section)
4. Profile your application (see Performance section)
5. Submit an issue with reproduction steps

**Remember:** Most issues stem from improper pool usage or missing `defer` statements.