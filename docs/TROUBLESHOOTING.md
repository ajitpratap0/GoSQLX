# GoSQLX Troubleshooting Guide

## Table of Contents
- [Common Issues](#common-issues)
- [Error Messages](#error-messages)
- [Performance Issues](#performance-issues)
- [Memory Issues](#memory-issues)
- [Unicode and Encoding Issues](#unicode-and-encoding-issues)
- [Dialect-Specific Issues](#dialect-specific-issues)
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

**Cause:** Not returning objects to pool

**Solution:**
```go
// WRONG - Leaks tokenizer
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
    defer tokenizer.PutTokenizer(tkz) // Always executes
    
    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        return err
    }
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

## Error Messages

### "unterminated quoted identifier"

**Example Error:**
```
unterminated quoted identifier starting at line 1, column 8
```

**Cause:** Missing closing quote for identifier

**Examples:**
```sql
-- Missing closing double quote
SELECT "user_name FROM users;

-- Missing closing backtick (MySQL)
SELECT `user_id FROM users;

-- Missing closing bracket (SQL Server)
SELECT [user_id FROM users;
```

**Solution:** Ensure all quoted identifiers have matching closing quotes

### "unterminated string literal"

**Example Error:**
```
unterminated string literal starting at line 2, column 15
```

**Cause:** Missing closing quote for string

**Examples:**
```sql
-- Missing closing single quote
SELECT * FROM users WHERE name = 'John;

-- Incorrect escaping
SELECT * FROM users WHERE name = 'John's Pizza;
```

**Solution:** 
```sql
-- Correct: Escape quotes by doubling
SELECT * FROM users WHERE name = 'John''s Pizza';

-- Or use different quote style if supported
SELECT * FROM users WHERE name = "John's Pizza";
```

### "invalid character"

**Example Error:**
```
invalid character: #
```

**Cause:** Unsupported character in SQL

**Common Causes:**
1. Comments using unsupported syntax
2. Special characters not properly quoted
3. Encoding issues

**Solution:**
```sql
-- Use standard SQL comments
-- This is a comment (standard)
/* This is also a comment */

-- Avoid # style comments (MySQL specific)
# This might not work

-- Quote special characters in identifiers
SELECT "column#1" FROM users;  -- Quoted
```

### "unexpected token"

**Example Error:**
```
unexpected token: LIMIT at position 45
```

**Cause:** Token not expected in current context

**Debugging Steps:**
1. Check SQL syntax for your specific dialect
2. Verify token order
3. Look for missing keywords

```go
func DebugUnexpectedToken(sql string) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        fmt.Printf("Tokenization failed: %v\n", err)
        return
    }
    
    // Print all tokens for debugging
    for i, token := range tokens {
        fmt.Printf("%d: %s (type: %d)\n", 
            i, token.Token.Value, token.Token.Type)
    }
}
```

## Performance Issues

### Slow Tokenization

**Symptom:** Tokenization takes longer than expected

**Common Causes:**
1. Very large SQL queries
2. Complex Unicode processing
3. Not reusing tokenizers

**Diagnosis:**
```go
func MeasurePerformance(sql string) {
    start := time.Now()
    
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    tokens, err := tkz.Tokenize([]byte(sql))
    
    elapsed := time.Since(start)
    fmt.Printf("Tokenization took: %v\n", elapsed)
    fmt.Printf("Tokens generated: %d\n", len(tokens))
    fmt.Printf("Bytes per second: %.2f\n", 
        float64(len(sql))/elapsed.Seconds())
}
```

**Solutions:**

1. **Reuse tokenizers:**
```go
// Process multiple queries with one tokenizer
func BatchProcess(queries []string) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    for _, sql := range queries {
        tkz.Reset()
        tokens, _ := tkz.Tokenize([]byte(sql))
        // Process...
    }
}
```

2. **Limit query size:**
```go
const MaxQuerySize = 1_000_000 // 1MB

func ProcessWithLimit(sql string) error {
    if len(sql) > MaxQuerySize {
        return fmt.Errorf("query too large: %d bytes", len(sql))
    }

    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    _, err := tkz.Tokenize([]byte(sql))
    return err
}
```

3. **Use concurrent processing:**
```go
func ParallelProcess(queries []string) {
    numWorkers := runtime.NumCPU()
    work := make(chan string, len(queries))
    
    // Queue work
    for _, sql := range queries {
        work <- sql
    }
    close(work)
    
    // Process in parallel
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
```

### High CPU Usage

**Symptom:** CPU usage spikes during tokenization

**Profiling:**
```go
import _ "net/http/pprof"

func init() {
    go func() {
        log.Println(http.ListenAndServe("localhost:6060", nil))
    }()
}

// Profile with: go tool pprof http://localhost:6060/debug/pprof/profile
```

**Common Causes:**
1. Tokenizing in tight loops
2. Not using pools effectively
3. Excessive string operations

## Memory Issues

### Memory Leaks

**Detection:**
```go
func DetectLeak() {
    var m runtime.MemStats
    
    // Baseline
    runtime.GC()
    runtime.ReadMemStats(&m)
    baseline := m.Alloc
    
    // Run operations
    for i := 0; i < 1000; i++ {
        tkz := tokenizer.GetTokenizer()
        tokens, _ := tkz.Tokenize([]byte("SELECT * FROM users"))
        tokenizer.PutTokenizer(tkz)
    }
    
    // Check memory
    runtime.GC()
    runtime.ReadMemStats(&m)
    leaked := m.Alloc - baseline
    
    fmt.Printf("Potential leak: %d bytes\n", leaked)
}
```

**Common Leak Patterns:**

1. **Storing pooled objects:**
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
    // Use and return
}
```

2. **Goroutine leaks:**
```go
// WRONG - Goroutine may leak
func LeakyAsync(sql string) {
    go func() {
        tkz := tokenizer.GetTokenizer()
        // If this panics, tokenizer is never returned
        tokens, _ := tkz.Tokenize([]byte(sql))
        tokenizer.PutTokenizer(tkz)
    }()
}

// CORRECT - Always use defer
func SafeAsync(sql string) {
    go func() {
        tkz := tokenizer.GetTokenizer()
        defer tokenizer.PutTokenizer(tkz) // Always returns
        tokens, _ := tkz.Tokenize([]byte(sql))
    }()
}
```

### High Memory Usage

**Monitoring:**
```go
func MonitorMemory() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        var m runtime.MemStats
        runtime.ReadMemStats(&m)
        
        fmt.Printf("Alloc: %d MB\n", m.Alloc/1024/1024)
        fmt.Printf("Total: %d MB\n", m.TotalAlloc/1024/1024)
        fmt.Printf("Sys: %d MB\n", m.Sys/1024/1024)
        fmt.Printf("NumGC: %d\n", m.NumGC)
    }
}
```

**Optimization:**
```go
// Pre-allocate for known sizes
func OptimizedTokenization(sql string) {
    estimatedTokens := len(sql) / 5 // Rough estimate
    
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    tokens, _ := tkz.Tokenize([]byte(sql))
    
    // Pre-allocate result slice
    result := make([]string, 0, estimatedTokens)
    for _, token := range tokens {
        result = append(result, token.Token.Value)
    }
}
```

## Unicode and Encoding Issues

### Invalid UTF-8 Sequences

**Problem:** Tokenizer fails with encoding errors

**Detection:**
```go
func ValidateUTF8(sql string) error {
    if !utf8.ValidString(sql) {
        return fmt.Errorf("invalid UTF-8 encoding")
    }
    
    // Find invalid sequences
    for i, r := range sql {
        if r == utf8.RuneError {
            return fmt.Errorf("invalid UTF-8 at position %d", i)
        }
    }
    
    return nil
}
```

**Fix Encoding:**
```go
func FixEncoding(input []byte) []byte {
    // Remove invalid UTF-8 sequences
    return bytes.ToValidUTF8(input, []byte("?"))
}
```

### Mixed Character Sets

**Problem:** Mixing incompatible character sets

**Solution:**
```go
func NormalizeCharsets(sql string) string {
    // Normalize Unicode
    return norm.NFC.String(sql)
}
```

## Dialect-Specific Issues

### PostgreSQL

**Issue:** Array operators not recognized

```go
// Ensure PostgreSQL operators are handled
sql := `SELECT * FROM users WHERE tags @> ARRAY['admin']`

tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)

tokens, err := tkz.Tokenize([]byte(sql))
if err != nil {
    // Check if it's the @> operator causing issues
    if strings.Contains(err.Error(), "@>") {
        fmt.Println("PostgreSQL array operator issue")
    }
}
```

### MySQL

**Issue:** Backtick identifiers not working

```go
// Test MySQL backtick support
func TestMySQLBackticks() error {
    sql := "SELECT `user_id` FROM `users`"
    
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        return fmt.Errorf("MySQL backtick not supported: %v", err)
    }
    
    // Verify backticks were tokenized correctly
    for _, token := range tokens {
        if token.Token.Type == models.TokenTypeIdentifier {
            fmt.Printf("Identifier: %s\n", token.Token.Value)
        }
    }
    
    return nil
}
```

### SQL Server

**Issue:** Square brackets not recognized

```go
// Handle SQL Server brackets
sql := "SELECT [user id] FROM [user table]"

// Pre-process if needed
processed := strings.ReplaceAll(sql, "[", `"`)
processed = strings.ReplaceAll(processed, "]", `"`)
```

## Debugging Techniques

### Enable Debug Logging

```go
type DebugTokenizer struct {
    *tokenizer.Tokenizer
    debug bool
}

func (d *DebugTokenizer) Tokenize(input []byte) ([]models.TokenWithSpan, error) {
    if d.debug {
        fmt.Printf("Input: %s\n", string(input))
        fmt.Printf("Length: %d bytes\n", len(input))
    }
    
    start := time.Now()
    tokens, err := d.Tokenizer.Tokenize(input)
    
    if d.debug {
        fmt.Printf("Duration: %v\n", time.Since(start))
        fmt.Printf("Tokens: %d\n", len(tokens))
        
        if err != nil {
            fmt.Printf("Error: %v\n", err)
        }
    }
    
    return tokens, err
}
```

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
    
    fmt.Println("Token Stream Analysis:")
    fmt.Println("==================================================")
    
    for i, token := range tokens {
        if token.Token.Type == models.TokenTypeEOF {
            fmt.Println("EOF reached")
            break
        }
        
        fmt.Printf("%3d | Type: %3d | Pos: L%d:C%d | Value: %q\n",
            i,
            token.Token.Type,
            token.Start.Line,
            token.Start.Column,
            token.Token.Value)
    }
    
    // Statistics
    fmt.Printf("\nTotal tokens: %d\n", len(tokens))
    fmt.Printf("Input size: %d bytes\n", len(sql))
    fmt.Printf("Tokens per byte: %.2f\n", 
        float64(len(tokens))/float64(len(sql)))
}
```

### Memory Profiling

```go
func ProfileMemory(sql string, iterations int) {
    var m runtime.MemStats
    
    // Before
    runtime.GC()
    runtime.ReadMemStats(&m)
    allocBefore := m.Alloc
    
    // Run tokenization
    for i := 0; i < iterations; i++ {
        tkz := tokenizer.GetTokenizer()
        tokens, _ := tkz.Tokenize([]byte(sql))
        _ = tokens
        tokenizer.PutTokenizer(tkz)
    }
    
    // After
    runtime.GC()
    runtime.ReadMemStats(&m)
    allocAfter := m.Alloc
    
    fmt.Printf("Memory used: %d bytes\n", allocAfter-allocBefore)
    fmt.Printf("Per iteration: %d bytes\n", 
        (allocAfter-allocBefore)/int64(iterations))
}
```

## FAQ

### Q: Why does my application panic when using tokenizers?

**A:** Most likely you're not getting the tokenizer from the pool:
```go
// Always use:
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)
```

### Q: How many tokenizers can I get from the pool simultaneously?

**A:** The pool has no hard limit. It creates new instances as needed and reuses returned ones. For best performance, return tokenizers as soon as possible.

### Q: Can I modify token values after tokenization?

**A:** Yes, tokens are copies and can be safely modified:
```go
tokens, _ := tkz.Tokenize([]byte(sql))
for i := range tokens {
    if tokens[i].Token.Type == models.TokenTypeIdentifier {
        tokens[i].Token.Value = strings.ToUpper(tokens[i].Token.Value)
    }
}
```

### Q: How do I handle very large SQL files?

**A:** For files > 10MB, consider streaming or chunking:
```go
func ProcessLargeFile(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    scanner := bufio.NewScanner(file)
    scanner.Split(SplitOnSemicolon) // Custom splitter
    
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    for scanner.Scan() {
        sql := scanner.Text()
        tkz.Reset()
        tokens, err := tkz.Tokenize([]byte(sql))
        if err != nil {
            return err
        }
        // Process tokens...
    }
    
    return scanner.Err()
}
```

### Q: Why is Unicode text tokenizing slowly?

**A:** Complex Unicode requires more processing. Optimize by:
1. Normalizing text before tokenization
2. Using byte operations where possible
3. Caching tokenization results for repeated queries

### Q: How do I test for race conditions?

**A:** Use Go's race detector:
```bash
go test -race ./...
go run -race main.go
```

### Q: Can I use GoSQLX with database/sql?

**A:** GoSQLX is a parser/tokenizer, not a driver. Use it to analyze queries before sending to database/sql:
```go
func ValidateBeforeExecute(db *sql.DB, query string) error {
    // Validate with GoSQLX
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    _, err := tkz.Tokenize([]byte(query))
    if err != nil {
        return fmt.Errorf("invalid SQL: %v", err)
    }
    
    // Execute with database/sql
    _, err = db.Exec(query)
    return err
}
```

### Q: How do I contribute bug fixes?

**A:** 
1. Create a minimal reproduction case
2. Include the SQL that causes the issue
3. Submit an issue with:
   - Go version
   - GoSQLX version
   - Full error message
   - Sample code

## Getting Help

If you're still experiencing issues:

1. **Check the test suite** - Examples of correct usage
2. **Review benchmarks** - Performance patterns
3. **Enable debug logging** - Understand what's happening
4. **Profile your application** - Identify bottlenecks
5. **Submit an issue** - With reproduction steps

Remember: Most issues are related to improper pool usage or not using defer for cleanup.