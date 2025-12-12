# GoSQLX Troubleshooting Guide

**Version:** v1.6.0
**Last Updated:** 2025-12-12

## Table of Contents
- [Common Issues](#common-issues)
- [v1.6.0 Feature Issues](#v160-feature-issues)
  - [LSP Server Issues](#lsp-server-issues)
  - [Linter Issues](#linter-issues)
  - [Security Scanner Issues](#security-scanner-issues)
  - [Parser Issues (v1.6.0)](#parser-issues-v160)
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

## v1.6.0 Feature Issues

### LSP Server Issues

#### Issue: LSP Server Not Starting

**Symptom:** `gosqlx lsp` command exits immediately or hangs

**Common Causes:**
1. Port already in use
2. Invalid configuration
3. Permission issues with log file

**Diagnosis:**
```bash
# Check if port is in use
lsof -i :9999  # Default LSP port

# Start with debug logging
gosqlx lsp --log /tmp/gosqlx-lsp.log

# Check log file for errors
tail -f /tmp/gosqlx-lsp.log
```

**Solutions:**
```bash
# Solution 1: Use different port (if implementing custom transport)
# For stdio (default), no port conflict possible

# Solution 2: Check configuration file
cat .gosqlx.yml
# Ensure valid YAML syntax

# Solution 3: Test with minimal config
rm .gosqlx.yml
gosqlx lsp  # Uses defaults
```

**Code Example - Programmatic LSP Server:**
```go
import (
    "context"
    "github.com/ajitpratap0/GoSQLX/pkg/lsp"
    "log"
)

func StartLSPServer() {
    server := lsp.NewServer()

    // Set up error handler
    server.OnError(func(err error) {
        log.Printf("LSP error: %v", err)
    })

    // Start server
    if err := server.Start(context.Background()); err != nil {
        log.Fatalf("Failed to start LSP: %v", err)
    }
}
```

#### Issue: IDE Not Connecting to LSP Server

**Symptom:** No diagnostics, hover, or completion in IDE

**Common Causes:**
1. LSP client not configured correctly
2. Server not in PATH
3. Wrong command or arguments

**Solutions:**

**VS Code Configuration (.vscode/settings.json):**
```json
{
  "gosqlx.lsp.enabled": true,
  "gosqlx.lsp.command": "gosqlx",
  "gosqlx.lsp.args": ["lsp"],
  "gosqlx.lsp.trace.server": "verbose"
}
```

**Neovim Configuration (init.lua):**
```lua
local lspconfig = require('lspconfig')
local configs = require('lspconfig.configs')

-- Define gosqlx LSP
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

-- Setup gosqlx LSP
lspconfig.gosqlx.setup{}
```

**Troubleshooting Steps:**
```bash
# 1. Verify gosqlx is in PATH
which gosqlx
gosqlx --version

# 2. Test LSP manually
gosqlx lsp --log /tmp/lsp-debug.log

# 3. Check IDE LSP client logs
# VS Code: Output > Language Server Protocol
# Neovim: :LspLog

# 4. Enable verbose logging
export GOSQLX_LSP_VERBOSE=1
gosqlx lsp
```

#### Issue: Diagnostics Not Appearing

**Symptom:** Errors in SQL but no diagnostics shown in IDE

**Common Causes:**
1. File not saved
2. Diagnostics disabled in config
3. Severity threshold too high
4. File type not recognized as SQL

**Solutions:**
```yaml
# .gosqlx.yml - Enable all diagnostics
lsp:
  diagnostics:
    enabled: true
    severity_threshold: "hint"  # Show all levels
    debounce_ms: 300
    max_diagnostics: 100

linter:
  enabled: true
  rules:
    - L001  # Ensure key rules enabled
    - L002
    - L003
```

**Verify Diagnostics Programmatically:**
```go
import (
    "github.com/ajitpratap0/GoSQLX/pkg/lsp"
    "github.com/ajitpratap0/GoSQLX/pkg/linter"
)

func TestDiagnostics(sqlContent string) {
    // Create linter
    l := linter.NewLinter()

    // Run lint
    violations := l.Lint(sqlContent)

    for _, v := range violations {
        log.Printf("Line %d: [%s] %s",
            v.Location.Line, v.Rule, v.Message)
    }
}
```

#### Issue: High Memory Usage with Large Files

**Symptom:** LSP server consumes excessive memory with large SQL files

**Common Causes:**
1. Full file re-parsing on every change
2. AST cache growing unbounded
3. Too many diagnostics stored

**Solutions:**
```yaml
# .gosqlx.yml - Optimize for large files
lsp:
  max_file_size: 1048576  # 1MB limit
  diagnostics:
    max_diagnostics: 50  # Limit diagnostic count
    debounce_ms: 1000    # Reduce parsing frequency

parser:
  max_recursion_depth: 100
  max_tokens: 50000
```

**Monitor Memory Usage:**
```go
import (
    "runtime"
    "time"
)

func MonitorLSPMemory() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        var m runtime.MemStats
        runtime.ReadMemStats(&m)
        log.Printf("LSP Memory: Alloc=%dMB HeapInuse=%dMB",
            m.Alloc/1024/1024, m.HeapInuse/1024/1024)

        // Force GC if memory high
        if m.Alloc > 500*1024*1024 { // 500MB
            runtime.GC()
        }
    }
}
```

#### Issue: Hover Information Not Displaying

**Symptom:** No information shown when hovering over SQL keywords or identifiers

**Common Cause:** Hover provider not fully implemented or position calculation incorrect

**Workaround:**
```yaml
# .gosqlx.yml - Enable hover with fallback
lsp:
  hover:
    enabled: true
    show_documentation: true
    show_examples: true
```

**Test Hover Programmatically:**
```go
func TestHover(content string, line, char int) {
    server := lsp.NewServer()

    // Simulate hover request
    params := lsp.HoverParams{
        TextDocument: lsp.TextDocumentIdentifier{URI: "file:///test.sql"},
        Position:     lsp.Position{Line: line, Character: char},
    }

    hover, err := server.Hover(params)
    if err != nil {
        log.Printf("Hover failed: %v", err)
        return
    }

    log.Printf("Hover content: %s", hover.Contents)
}
```

### Linter Issues

#### Issue: Auto-Fix Not Working

**Symptom:** Running `gosqlx lint --fix` doesn't modify files

**Common Causes:**
1. Rule doesn't support auto-fix
2. File permissions prevent writing
3. Syntax errors prevent parsing

**Diagnosis:**
```bash
# Check which rules support auto-fix
gosqlx lint --list-rules

# Output shows:
# L001: keyword-capitalization (auto-fixable)
# L002: indentation (auto-fixable)
# L003: trailing-whitespace (auto-fixable)
# L004: semicolon-required (auto-fixable)
# L005: line-length (not auto-fixable)
# ...
```

**Solutions:**
```bash
# Solution 1: Verify file permissions
ls -l query.sql
chmod 644 query.sql  # Ensure writable

# Solution 2: Check for syntax errors first
gosqlx validate query.sql
# Fix syntax errors before linting

# Solution 3: Enable verbose mode
gosqlx lint --fix --verbose query.sql

# Solution 4: Use specific rules
gosqlx lint --fix --rules L001,L002,L003 query.sql
```

**Programmatic Auto-Fix:**
```go
import (
    "github.com/ajitpratap0/GoSQLX/pkg/linter"
    "os"
)

func AutoFixFile(filename string) error {
    content, err := os.ReadFile(filename)
    if err != nil {
        return err
    }

    l := linter.NewLinter()
    l.EnableAutoFix(true)
    l.EnableRules([]string{"L001", "L002", "L003", "L004"})

    fixed, err := l.Fix(string(content))
    if err != nil {
        return err
    }

    return os.WriteFile(filename, []byte(fixed), 0644)
}
```

#### Issue: Rules Not Detecting Violations

**Symptom:** Expected violations not reported by linter

**Common Causes:**
1. Rule disabled in configuration
2. Severity threshold filters out violations
3. Rule pattern doesn't match SQL dialect

**Diagnosis:**
```bash
# Check active configuration
gosqlx lint --show-config

# Test specific rule
gosqlx lint --rules L001 query.sql

# Show all violations regardless of severity
gosqlx lint --severity hint query.sql
```

**Solutions:**
```yaml
# .gosqlx.yml - Enable all rules with detailed config
linter:
  enabled: true
  auto_fix: false
  severity_threshold: "hint"

  rules:
    L001:  # Keyword capitalization
      enabled: true
      severity: "warning"
      style: "upper"  # or "lower"

    L002:  # Indentation
      enabled: true
      severity: "warning"
      indent_size: 4
      indent_type: "space"  # or "tab"

    L003:  # Trailing whitespace
      enabled: true
      severity: "info"

    L004:  # Semicolon required
      enabled: true
      severity: "warning"

    L005:  # Line length
      enabled: true
      severity: "info"
      max_length: 120

    L006:  # Table alias required
      enabled: true
      severity: "warning"

    L007:  # No SELECT *
      enabled: true
      severity: "info"

    L008:  # Column naming convention
      enabled: true
      severity: "info"
      pattern: "^[a-z_][a-z0-9_]*$"

    L009:  # No implicit JOIN
      enabled: true
      severity: "warning"

    L010:  # Consistent quoting
      enabled: true
      severity: "info"
      quote_style: "double"  # or "single", "backtick"
```

**Test Rule Detection:**
```go
func TestRuleDetection(sql string, ruleID string) {
    l := linter.NewLinter()
    l.EnableRules([]string{ruleID})

    violations := l.Lint(sql)

    if len(violations) == 0 {
        log.Printf("Rule %s: No violations detected", ruleID)
    } else {
        for _, v := range violations {
            log.Printf("Rule %s: Line %d - %s",
                ruleID, v.Location.Line, v.Message)
        }
    }
}
```

#### Issue: Configuration Not Loading

**Symptom:** Custom linter config ignored, defaults used instead

**Common Causes:**
1. Config file in wrong location
2. Invalid YAML syntax
3. Wrong config file name
4. Config file not in project root

**Diagnosis:**
```bash
# Check config file search path
gosqlx lint --show-config-path

# Validate YAML syntax
yamllint .gosqlx.yml

# Show effective configuration
gosqlx lint --show-config query.sql
```

**Solutions:**
```bash
# Solution 1: Place config in correct location
# Priority order:
# 1. .gosqlx.yml in current directory
# 2. .gosqlx.yml in parent directories (up to git root)
# 3. ~/.gosqlx.yml (user home)

# Solution 2: Specify config explicitly
gosqlx lint --config ./custom-config.yml query.sql

# Solution 3: Validate config structure
cat > .gosqlx.yml <<EOF
linter:
  enabled: true
  rules:
    - L001
    - L002
EOF

# Solution 4: Use default config template
gosqlx lint --init-config
```

#### Issue: Performance Degradation with Many Rules

**Symptom:** Linting very slow with all 10 rules enabled

**Solutions:**
```yaml
# .gosqlx.yml - Optimize linter performance
linter:
  enabled: true
  parallel: true  # Enable parallel rule execution
  max_workers: 4  # Limit concurrent workers

  # Enable only essential rules for fast feedback
  rules:
    - L001  # Keywords
    - L003  # Whitespace
    - L004  # Semicolon
```

**Benchmark Linter:**
```go
import "testing"

func BenchmarkLinter(b *testing.B) {
    sql := `SELECT * FROM users WHERE id = 1`
    l := linter.NewLinter()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _ = l.Lint(sql)
    }
}

// Run: go test -bench=BenchmarkLinter -benchmem
```

### Security Scanner Issues

#### Issue: False Positives on UNION Queries

**Symptom:** Legitimate UNION queries flagged as SQL injection risks

**Common Cause:** Security scanner detects UNION keyword without context

**Solutions:**
```go
import "github.com/ajitpratap0/GoSQLX/pkg/sql/security"

// Solution 1: Use parameterized queries (recommended)
func SafeUnionQuery(userID int) string {
    return fmt.Sprintf(`
        SELECT name, email FROM users WHERE id = %d
        UNION
        SELECT name, email FROM archived_users WHERE id = %d
    `, userID, userID)
}

// Solution 2: Suppress false positives
func ScanWithContext(sql string) {
    scanner := security.NewScanner()
    result := scanner.Scan(sql)

    // Filter findings by context
    realThreats := []security.Finding{}
    for _, finding := range result.Findings {
        if !isFalsePositive(finding, sql) {
            realThreats = append(realThreats, finding)
        }
    }
}

func isFalsePositive(finding security.Finding, sql string) bool {
    // Check if UNION is part of legitimate query structure
    if finding.Pattern == "UNION" {
        // Verify UNION has proper SELECT statements
        if strings.Contains(sql, "SELECT") &&
           strings.Count(sql, "SELECT") >= 2 {
            return true
        }
    }
    return false
}
```

**Configuration:**
```yaml
# .gosqlx.yml - Tune security scanner
security:
  enabled: true
  severity_threshold: "medium"  # Ignore low-severity findings

  # Disable specific patterns if false positives
  ignore_patterns:
    - "UNION in subquery"

  # Enable allowlist for known-safe patterns
  allowlist:
    - "SELECT .* UNION SELECT .* FROM"
```

#### Issue: Pattern Detection Missing Obfuscated Injections

**Symptom:** Security scanner doesn't detect sophisticated injection attempts

**Common Cause:** Scanner uses simple pattern matching, not semantic analysis

**Solutions:**
```go
// Enhanced security checking
func EnhancedSecurityScan(sql string) error {
    // Step 1: Basic pattern scanning
    scanner := security.NewScanner()
    result := scanner.Scan(sql)

    if result.HasHighOrAbove() {
        return fmt.Errorf("high-risk SQL detected")
    }

    // Step 2: Parse and validate structure
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        return fmt.Errorf("failed to tokenize: %v", err)
    }

    // Step 3: Check for suspicious patterns
    if hasSuspiciousComments(tokens) {
        return fmt.Errorf("suspicious comment detected")
    }

    if hasNestedQuotes(tokens) {
        return fmt.Errorf("nested quotes detected")
    }

    return nil
}

func hasSuspiciousComments(tokens []models.TokenWithSpan) bool {
    for _, t := range tokens {
        if t.Token.Type == models.TokenTypeComment {
            // Check for comment injection patterns
            if strings.Contains(t.Token.Value, "';") ||
               strings.Contains(t.Token.Value, "';--") {
                return true
            }
        }
    }
    return false
}
```

#### Issue: Performance Impact on Large Codebases

**Symptom:** Security scanning slows down CI/CD pipeline

**Solutions:**
```yaml
# .gosqlx.yml - Optimize security scanning
security:
  enabled: true
  max_file_size: 524288  # 512KB limit
  timeout_ms: 5000       # 5 second timeout per file
  parallel: true         # Scan files in parallel
  cache_results: true    # Cache scan results
```

**Selective Scanning:**
```go
func SelectiveScan(files []string) error {
    scanner := security.NewScanner()

    // Scan only user-input handling files
    for _, file := range files {
        if !strings.Contains(file, "_handler") &&
           !strings.Contains(file, "_controller") {
            continue  // Skip non-critical files
        }

        content, _ := os.ReadFile(file)
        result := scanner.Scan(string(content))

        if result.HasHighOrAbove() {
            return fmt.Errorf("security issue in %s", file)
        }
    }
    return nil
}
```

### Parser Issues (v1.6.0)

#### Issue: LATERAL JOIN Parsing Problems

**Symptom:** LATERAL JOIN queries fail to parse or produce incorrect AST

**Common Causes:**
1. LATERAL keyword not recognized in JOIN context
2. Subquery after LATERAL not properly parsed
3. Correlated references not validated

**Diagnosis:**
```bash
# Test LATERAL JOIN parsing
echo "SELECT u.name, r.order_date FROM users u,
LATERAL (SELECT * FROM orders WHERE user_id = u.id LIMIT 3) r" | \
gosqlx parse --format json
```

**Working Examples:**
```sql
-- Simple LATERAL JOIN
SELECT u.name, r.order_date
FROM users u,
LATERAL (SELECT * FROM orders WHERE user_id = u.id ORDER BY order_date DESC LIMIT 3) r;

-- LATERAL with explicit JOIN syntax
SELECT u.name, r.total
FROM users u
CROSS JOIN LATERAL (
    SELECT SUM(amount) as total
    FROM orders
    WHERE user_id = u.id
) r;

-- Multiple LATERAL joins
SELECT u.name, o.order_count, p.product_count
FROM users u
LEFT JOIN LATERAL (
    SELECT COUNT(*) as order_count FROM orders WHERE user_id = u.id
) o ON true
LEFT JOIN LATERAL (
    SELECT COUNT(*) as product_count FROM products WHERE seller_id = u.id
) p ON true;
```

**Troubleshooting:**
```go
func TestLateralJoinParsing(sql string) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        log.Printf("Tokenization failed: %v", err)
        return
    }

    // Check for LATERAL token
    hasLateral := false
    for _, t := range tokens {
        if strings.ToUpper(t.Token.Value) == "LATERAL" {
            hasLateral = true
            log.Printf("Found LATERAL at line %d, col %d",
                t.Start.Line, t.Start.Column)
        }
    }

    if !hasLateral {
        log.Println("LATERAL keyword not found - may not be tokenized correctly")
    }

    // Parse
    parserTokens, _ := parser.ConvertTokensForParser(tokens)
    p := parser.NewParser()
    astTree, err := p.Parse(parserTokens)
    if err != nil {
        log.Printf("Parse failed: %v", err)
        return
    }
    defer ast.ReleaseAST(astTree)

    log.Printf("Successfully parsed LATERAL JOIN with %d statements",
        len(astTree.Statements))
}
```

#### Issue: JSON Operator Parsing

**Symptom:** PostgreSQL JSON operators (`->`, `->>`, `#>`, `@>`, etc.) not parsed correctly

**Common Causes:**
1. Operator tokenized as separate tokens
2. Operator precedence incorrect
3. Expression tree structure invalid

**Working Examples:**
```sql
-- JSON extraction operators
SELECT data->>'name' AS name FROM users;
SELECT data->'address'->>'city' AS city FROM users;

-- JSON path operators
SELECT data#>'{address,city}' AS city FROM users;
SELECT data#>>'{contact,email}' AS email FROM users;

-- JSON containment operators
SELECT * FROM products WHERE attributes @> '{"color": "red"}';
SELECT * FROM users WHERE profile <@ '{"verified": true}';

-- JSON existence operators
SELECT * FROM users WHERE profile ? 'email';
SELECT * FROM users WHERE tags ?| array['admin', 'moderator'];
SELECT * FROM users WHERE permissions ?& array['read', 'write'];

-- JSON deletion operator
SELECT data - 'password' FROM users;
SELECT data #- '{address,street}' FROM users;
```

**Diagnosis:**
```go
func TestJSONOperatorParsing(sql string) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        log.Printf("Tokenization failed: %v", err)
        return
    }

    // Check JSON operators
    jsonOps := []string{"->", "->>", "#>", "#>>", "@>", "<@", "?", "?|", "?&", "#-"}
    for _, t := range tokens {
        for _, op := range jsonOps {
            if t.Token.Value == op {
                log.Printf("Found JSON operator %s at line %d, col %d",
                    op, t.Start.Line, t.Start.Column)
            }
        }
    }
}
```

#### Issue: Complex Nested Query Parsing

**Symptom:** Deeply nested queries fail with "recursion depth limit" error

**Common Cause:** Parser hits max recursion depth (default 200)

**Solutions:**
```yaml
# .gosqlx.yml - Increase recursion limit
parser:
  max_recursion_depth: 500  # Increase for complex queries
  max_tokens: 100000        # Increase token limit if needed
```

**Code Solution:**
```go
import "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"

func ParseComplexQuery(sql string) error {
    p := parser.NewParser()

    // Increase limits for complex queries
    p.SetMaxRecursionDepth(500)
    p.SetMaxTokens(100000)

    tokens, _ := /* tokenize */
    astTree, err := p.Parse(tokens)
    if err != nil {
        return err
    }
    defer ast.ReleaseAST(astTree)

    return nil
}
```

**Refactor Complex Query:**
```sql
-- Instead of deep nesting:
SELECT * FROM (
    SELECT * FROM (
        SELECT * FROM (
            SELECT * FROM users WHERE active = true
        ) a WHERE created_at > '2024-01-01'
    ) b WHERE email LIKE '%@example.com'
) c WHERE id > 100;

-- Use CTEs for better readability and parsing:
WITH active_users AS (
    SELECT * FROM users WHERE active = true
),
recent_users AS (
    SELECT * FROM active_users WHERE created_at > '2024-01-01'
),
example_users AS (
    SELECT * FROM recent_users WHERE email LIKE '%@example.com'
)
SELECT * FROM example_users WHERE id > 100;
```

#### Issue: DISTINCT ON Parsing

**Symptom:** PostgreSQL DISTINCT ON clause not recognized

**Working Example:**
```sql
-- DISTINCT ON with proper syntax
SELECT DISTINCT ON (dept_id) dept_id, name, salary
FROM employees
ORDER BY dept_id, salary DESC;

-- Multiple columns in DISTINCT ON
SELECT DISTINCT ON (region, product_id) region, product_id, sale_date, amount
FROM sales
ORDER BY region, product_id, sale_date DESC;
```

#### Issue: FILTER Clause Parsing

**Symptom:** Aggregate FILTER clause not parsed correctly

**Working Examples:**
```sql
-- FILTER with COUNT
SELECT COUNT(*) FILTER (WHERE status = 'active') AS active_count
FROM users;

-- FILTER with multiple aggregates
SELECT
    COUNT(*) FILTER (WHERE status = 'active') AS active,
    COUNT(*) FILTER (WHERE status = 'inactive') AS inactive,
    SUM(amount) FILTER (WHERE type = 'credit') AS total_credits
FROM transactions;

-- FILTER in window functions
SELECT
    name,
    COUNT(*) FILTER (WHERE status = 'completed')
        OVER (PARTITION BY dept_id) AS dept_completed
FROM tasks;
```

#### Issue: RETURNING Clause Parsing

**Symptom:** RETURNING clause in INSERT/UPDATE/DELETE not recognized

**Working Examples:**
```sql
-- RETURNING with INSERT
INSERT INTO users (name, email)
VALUES ('John Doe', 'john@example.com')
RETURNING id, created_at;

-- RETURNING with UPDATE
UPDATE products
SET price = price * 1.1
WHERE category = 'Electronics'
RETURNING id, name, price;

-- RETURNING with DELETE
DELETE FROM sessions
WHERE expired_at < NOW()
RETURNING user_id, session_id;

-- RETURNING with multiple columns and expressions
INSERT INTO orders (user_id, amount)
VALUES (123, 99.99)
RETURNING id, amount * 1.1 AS amount_with_tax, NOW() AS created_at;
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
- LSP server re-parsing entire files on every keystroke

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

### LSP Performance Optimization

**Issue:** LSP server slow with large files or frequent edits

**Solutions:**
```yaml
# .gosqlx.yml - Performance tuning
lsp:
  # Debounce diagnostics to reduce parsing frequency
  diagnostics:
    debounce_ms: 500  # Wait 500ms after last edit before re-parsing
    max_diagnostics: 50

  # Limit file size
  max_file_size: 1048576  # 1MB limit

  # Enable incremental parsing (if supported)
  incremental_sync: true

parser:
  # Reduce recursion depth for faster parsing
  max_recursion_depth: 200
  max_tokens: 50000

  # Enable parser caching
  cache_enabled: true
  cache_ttl_seconds: 300  # 5 minutes
```

**Code-Level Optimization:**
```go
import (
    "sync"
    "time"
)

// Debouncer prevents excessive re-parsing
type Debouncer struct {
    mu    sync.Mutex
    timer *time.Timer
    delay time.Duration
}

func NewDebouncer(delay time.Duration) *Debouncer {
    return &Debouncer{delay: delay}
}

func (d *Debouncer) Debounce(fn func()) {
    d.mu.Lock()
    defer d.mu.Unlock()

    if d.timer != nil {
        d.timer.Stop()
    }

    d.timer = time.AfterFunc(d.delay, fn)
}

// Usage in LSP server
type LSPServer struct {
    debouncer *Debouncer
}

func (s *LSPServer) OnDocumentChange(content string) {
    // Debounce diagnostics
    s.debouncer.Debounce(func() {
        s.runDiagnostics(content)
    })
}
```

### Linter Performance Issues

**Issue:** Linting large files or codebases is slow

**Solutions:**
```yaml
# .gosqlx.yml - Linter optimization
linter:
  enabled: true
  parallel: true  # Run rules in parallel
  max_workers: 8  # Use 8 workers for parallel execution

  # Cache results
  cache_enabled: true
  cache_dir: ".gosqlx-cache"

  # Limit processing
  max_file_size: 524288  # 512KB
  timeout_seconds: 10

  # Enable only fast rules
  rules:
    - L001  # Keyword case (fast)
    - L003  # Trailing whitespace (fast)
    - L004  # Semicolon (fast)
```

**Benchmark and Optimize:**
```go
func BenchmarkLinterRules(b *testing.B) {
    testSQL := `
        SELECT u.id, u.name, o.total
        FROM users u
        JOIN orders o ON u.id = o.user_id
        WHERE u.active = true
    `

    l := linter.NewLinter()

    // Benchmark individual rules
    rules := []string{"L001", "L002", "L003", "L004", "L005"}
    for _, rule := range rules {
        b.Run(rule, func(b *testing.B) {
            l.EnableRules([]string{rule})
            b.ResetTimer()
            for i := 0; i < b.N; i++ {
                _ = l.Lint(testSQL)
            }
        })
    }
}

// Run: go test -bench=BenchmarkLinterRules -benchmem
```

### Memory Optimization

**Issue:** High memory usage in production

**Diagnosis:**
```go
import (
    "runtime"
    "runtime/debug"
    "time"
)

func MonitorMemoryUsage() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        var m runtime.MemStats
        runtime.ReadMemStats(&m)

        log.Printf("Memory Stats:")
        log.Printf("  Alloc: %d MB", m.Alloc/1024/1024)
        log.Printf("  TotalAlloc: %d MB", m.TotalAlloc/1024/1024)
        log.Printf("  Sys: %d MB", m.Sys/1024/1024)
        log.Printf("  NumGC: %d", m.NumGC)
        log.Printf("  HeapObjects: %d", m.HeapObjects)

        // Alert if memory high
        if m.Alloc > 500*1024*1024 { // 500MB
            log.Println("WARNING: High memory usage detected")
            debug.FreeOSMemory()
        }
    }
}
```

**Solutions:**
```yaml
# .gosqlx.yml - Memory optimization
parser:
  pool_size: 100  # Limit pool size
  max_ast_cache: 50  # Limit AST cache

lsp:
  max_documents: 100  # Limit open documents
  gc_interval_seconds: 300  # Run GC every 5 minutes

linter:
  max_workers: 4  # Limit parallel workers
```

**Code-Level Optimization:**
```go
// Proper resource cleanup
func ProcessManyQueries(queries []string) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    p := parser.NewParser()

    for i, sql := range queries {
        // Reset tokenizer between uses
        tkz.Reset()

        tokens, err := tkz.Tokenize([]byte(sql))
        if err != nil {
            continue
        }

        parserTokens, _ := parser.ConvertTokensForParser(tokens)
        astTree, err := p.Parse(parserTokens)
        if err != nil {
            continue
        }

        // CRITICAL: Always release AST
        ast.ReleaseAST(astTree)

        // Periodic GC for long-running processes
        if i%1000 == 0 {
            runtime.GC()
        }
    }
}
```

### Pool Configuration

**Issue:** Pool not providing expected performance benefits

**Diagnosis:**
```go
import "github.com/ajitpratap0/GoSQLX/pkg/metrics"

func DiagnosePoolPerformance() {
    snapshot := metrics.GetSnapshot()

    log.Printf("Pool Statistics:")
    log.Printf("  Tokenizer Gets: %d", snapshot.TokenizerGets)
    log.Printf("  Tokenizer Puts: %d", snapshot.TokenizerPuts)
    log.Printf("  AST Gets: %d", snapshot.ASTGets)
    log.Printf("  AST Puts: %d", snapshot.ASTPuts)

    // Calculate hit rates
    getTotal := snapshot.TokenizerGets
    putTotal := snapshot.TokenizerPuts
    hitRate := float64(putTotal) / float64(getTotal) * 100

    log.Printf("  Pool Hit Rate: %.2f%%", hitRate)

    // Should be >95% in production
    if hitRate < 95.0 {
        log.Println("WARNING: Low pool hit rate - check for resource leaks")
    }
}
```

**Solutions:**
```go
// Ensure proper pool usage pattern
func CorrectPoolUsage() {
    // ALWAYS use defer immediately after Get
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)  // MANDATORY

    // Use the object
    tokens, _ := tkz.Tokenize([]byte("SELECT * FROM users"))

    // AST pool usage
    astObj := ast.NewAST()
    defer ast.ReleaseAST(astObj)  // MANDATORY

    // Object automatically returned to pool on function exit
}

// Common mistake - conditional return
func IncorrectPoolUsage(sql string) error {
    tkz := tokenizer.GetTokenizer()

    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        return err  // LEAK! Tokenizer never returned
    }

    tokenizer.PutTokenizer(tkz)
    return nil
}
```

### Large File Handling

**Issue:** Processing large SQL files (>10MB) causes timeouts or memory issues

**Solutions:**
```go
import (
    "bufio"
    "io"
    "os"
)

// Stream large files instead of loading into memory
func ProcessLargeFile(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    reader := bufio.NewReader(file)
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    var buffer []byte
    delimiter := []byte(";")

    for {
        line, err := reader.ReadBytes('\n')
        if err != nil && err != io.EOF {
            return err
        }

        buffer = append(buffer, line...)

        // Process when we hit a delimiter
        if bytes.Contains(buffer, delimiter) {
            statements := bytes.Split(buffer, delimiter)

            for i := 0; i < len(statements)-1; i++ {
                stmt := statements[i]
                if len(bytes.TrimSpace(stmt)) == 0 {
                    continue
                }

                tkz.Reset()
                tokens, _ := tkz.Tokenize(stmt)
                // Process tokens...
            }

            // Keep incomplete statement in buffer
            buffer = statements[len(statements)-1]
        }

        if err == io.EOF {
            break
        }
    }

    return nil
}

// Alternative: Memory-mapped files for very large files
func ProcessMemoryMappedFile(filename string) error {
    // Use mmap for efficient large file access
    // Implementation depends on platform
    return nil
}
```

**Configuration:**
```yaml
# .gosqlx.yml - Large file handling
parser:
  streaming_mode: true
  chunk_size: 65536  # 64KB chunks

lsp:
  max_file_size: 10485760  # 10MB limit
  stream_large_files: true

linter:
  max_file_size: 5242880  # 5MB limit
  skip_large_files: true  # Skip instead of error
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

### General Questions

#### Q: Why does my application panic?

**A:** Always get tokenizer from pool:
```go
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)
```

#### Q: Can I modify tokens after tokenization?

**A:** Yes, tokens are copies and can be safely modified:
```go
tokens, _ := tkz.Tokenize([]byte(sql))
for i := range tokens {
    if tokens[i].Token.Type == models.TokenTypeIdentifier {
        tokens[i].Token.Value = strings.ToUpper(tokens[i].Token.Value)
    }
}
```

#### Q: How do I handle large SQL files (>10MB)?

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

#### Q: How do I test for race conditions?

**A:** Use Go's race detector:
```bash
go test -race ./...
go run -race main.go
```

#### Q: Can I use GoSQLX with database/sql?

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

### v1.6.0 LSP Questions

#### Q: How do I configure my IDE to use the GoSQLX LSP server?

**A:** Add to your IDE configuration:

**VS Code** - Create `.vscode/settings.json`:
```json
{
  "gosqlx.lsp.enabled": true,
  "gosqlx.lsp.command": "gosqlx",
  "gosqlx.lsp.args": ["lsp"]
}
```

**Neovim** - Add to `init.lua`:
```lua
require('lspconfig').gosqlx.setup{
  cmd = {'gosqlx', 'lsp'},
  filetypes = {'sql'},
}
```

#### Q: Why aren't diagnostics showing in my IDE?

**A:** Check these common issues:
1. Ensure file is saved
2. Check `.gosqlx.yml` has linter enabled
3. Verify `gosqlx` is in PATH: `which gosqlx`
4. Check LSP server logs: `gosqlx lsp --log /tmp/lsp.log`

#### Q: Can I disable specific linter rules in the LSP?

**A:** Yes, configure in `.gosqlx.yml`:
```yaml
linter:
  enabled: true
  rules:
    L001:
      enabled: false  # Disable keyword capitalization
    L002:
      enabled: true   # Keep indentation
```

#### Q: How do I get hover documentation to work?

**A:** Hover support is IDE-dependent. Ensure:
1. LSP server is running: `ps aux | grep gosqlx`
2. Hover is enabled in `.gosqlx.yml`:
```yaml
lsp:
  hover:
    enabled: true
    show_documentation: true
```

### v1.6.0 Linter Questions

#### Q: Which linter rules support auto-fix?

**A:** Auto-fixable rules:
- **L001**: Keyword capitalization
- **L002**: Indentation
- **L003**: Trailing whitespace
- **L004**: Semicolon required

Not auto-fixable:
- **L005**: Line length
- **L006**: Table alias required
- **L007**: No SELECT *
- **L008**: Column naming convention
- **L009**: No implicit JOIN
- **L010**: Consistent quoting

#### Q: How do I run only specific linter rules?

**A:** Use the `--rules` flag:
```bash
gosqlx lint --rules L001,L002,L003 query.sql
```

Or configure in `.gosqlx.yml`:
```yaml
linter:
  enabled: true
  rules:
    - L001
    - L002
    - L003
```

#### Q: Can I customize linter rule severity?

**A:** Yes, in `.gosqlx.yml`:
```yaml
linter:
  rules:
    L001:
      severity: "error"    # error, warning, info, hint
    L002:
      severity: "warning"
```

#### Q: How do I ignore linter warnings for specific queries?

**A:** Use inline comments (feature planned):
```sql
-- gosqlx-disable-next-line L007
SELECT * FROM users;

-- gosqlx-disable L001
select * from orders;
-- gosqlx-enable L001
```

### v1.6.0 Parser Questions

#### Q: Does GoSQLX support PostgreSQL JSON operators?

**A:** Yes, all PostgreSQL JSON operators are supported:
```sql
-- Extraction: ->, ->>
SELECT data->>'name' FROM users;

-- Path: #>, #>>
SELECT data#>'{address,city}' FROM users;

-- Containment: @>, <@
SELECT * FROM products WHERE attrs @> '{"color":"red"}';

-- Existence: ?, ?|, ?&
SELECT * FROM users WHERE profile ? 'email';
```

#### Q: Can I parse LATERAL JOINs?

**A:** Yes, LATERAL JOIN support added in v1.6.0:
```sql
SELECT u.name, r.order_date
FROM users u,
LATERAL (SELECT * FROM orders WHERE user_id = u.id LIMIT 3) r;
```

#### Q: Are DISTINCT ON queries supported?

**A:** Yes, PostgreSQL DISTINCT ON is fully supported:
```sql
SELECT DISTINCT ON (dept_id) dept_id, name, salary
FROM employees
ORDER BY dept_id, salary DESC;
```

#### Q: Can I use FILTER clauses in aggregates?

**A:** Yes, FILTER clauses are supported:
```sql
SELECT
  COUNT(*) FILTER (WHERE status = 'active') AS active,
  SUM(amount) FILTER (WHERE type = 'credit') AS credits
FROM transactions;
```

#### Q: Does the parser support RETURNING clauses?

**A:** Yes, RETURNING works with INSERT/UPDATE/DELETE:
```sql
INSERT INTO users (name, email)
VALUES ('John', 'john@example.com')
RETURNING id, created_at;
```

### v1.6.0 Security Questions

#### Q: How do I scan SQL for injection vulnerabilities?

**A:** Use the security scanner:
```bash
gosqlx security scan query.sql
```

Or programmatically:
```go
import "github.com/ajitpratap0/GoSQLX/pkg/sql/security"

scanner := security.NewScanner()
result := scanner.Scan(sqlQuery)

if result.HasHighOrAbove() {
    // Handle security issues
}
```

#### Q: Why is my UNION query flagged as SQL injection?

**A:** Security scanner may flag UNION queries. Verify:
1. Query is properly parameterized
2. UNION is structurally valid
3. Consider whitelisting in `.gosqlx.yml`:
```yaml
security:
  allowlist:
    - "SELECT .* UNION SELECT .* FROM"
```

#### Q: Can I customize security scan severity levels?

**A:** Yes, configure thresholds:
```yaml
security:
  enabled: true
  severity_threshold: "medium"  # Only report medium+ findings
```

### Configuration Questions

#### Q: Where should I place the `.gosqlx.yml` file?

**A:** Configuration file search order:
1. `.gosqlx.yml` in current directory
2. `.gosqlx.yml` in parent directories (up to git root)
3. `~/.gosqlx.yml` (user home directory)

#### Q: How do I generate a default configuration file?

**A:** Use the init command:
```bash
gosqlx config init
# Creates .gosqlx.yml with default settings
```

#### Q: Can I use different configs for different environments?

**A:** Yes, specify config file explicitly:
```bash
gosqlx lint --config .gosqlx.production.yml query.sql
```

### Performance Questions

#### Q: Why is the LSP server slow with large files?

**A:** Optimize configuration:
```yaml
lsp:
  max_file_size: 1048576  # 1MB limit
  diagnostics:
    debounce_ms: 500      # Reduce parsing frequency
    max_diagnostics: 50
```

#### Q: How can I improve linter performance?

**A:** Enable parallel processing:
```yaml
linter:
  parallel: true
  max_workers: 8
  cache_enabled: true
```

#### Q: What's the expected performance for parsing?

**A:** v1.6.0 performance benchmarks:
- **Throughput**: 1.38M+ ops/sec sustained, 1.5M peak
- **Tokenization**: 8M+ tokens/sec
- **Latency**: <1μs for complex queries
- **Memory**: 60-80% reduction with object pooling

### Contributing

#### Q: How do I contribute bug fixes?

**A:** Submit an issue with:
- Go version and GoSQLX version (`gosqlx --version`)
- Minimal reproduction case with SQL
- Full error message
- Sample code

#### Q: How do I request a new feature?

**A:** Create a GitHub issue with:
- Feature description
- Use case and motivation
- Example SQL queries
- Expected behavior

#### Q: Can I contribute new linter rules?

**A:** Yes! Follow these steps:
1. Review `docs/LINTING_RULES.md` for rule structure
2. Implement rule in `pkg/linter/rules/`
3. Add tests in `pkg/linter/rules/*_test.go`
4. Update documentation
5. Submit pull request

## Getting Help

### Documentation Resources

1. **Quick Start**: `docs/GETTING_STARTED.md` - Basic usage and setup
2. **Comprehensive Guide**: `docs/USAGE_GUIDE.md` - Detailed SDK documentation
3. **LSP Guide**: `docs/LSP_GUIDE.md` - LSP server setup and IDE integration
4. **Linting Rules**: `docs/LINTING_RULES.md` - All 10 linter rules reference
5. **Configuration**: `docs/CONFIGURATION.md` - .gosqlx.yml file structure
6. **SQL Compatibility**: `docs/SQL_COMPATIBILITY.md` - Dialect support matrix

### Code Examples

1. **Test Suite**: Check `*_test.go` files for usage examples
2. **Benchmarks**: Review `*_bench_test.go` for performance patterns
3. **Examples**: See `examples/` directory for real-world usage
4. **Tutorials**: See `examples/tutorials/` for step-by-step guides

### Debugging Tools

```bash
# Enable verbose logging
export GOSQLX_DEBUG=1
gosqlx parse query.sql

# LSP debug logging
gosqlx lsp --log /tmp/gosqlx-lsp.log

# View tokenization
gosqlx parse --tokens query.sql

# Check AST structure
gosqlx parse --format json query.sql | jq .

# Profile performance
go test -bench=. -cpuprofile=cpu.prof
go tool pprof cpu.prof
```

### Common Issue Checklist

Before submitting an issue, verify:

- [ ] Using latest version: `gosqlx --version`
- [ ] Configuration valid: `gosqlx config validate`
- [ ] Pool usage correct: Always use `defer` with `PutTokenizer()` and `ReleaseAST()`
- [ ] Race detector clean: `go test -race ./...`
- [ ] Minimal reproduction case prepared
- [ ] Error messages captured completely
- [ ] Environment details documented (OS, Go version)

### v1.6.0 Specific Troubleshooting

**LSP Issues:**
1. Check server is running: `ps aux | grep gosqlx`
2. Verify PATH: `which gosqlx`
3. Test manually: `echo "SELECT * FROM users" | gosqlx validate`
4. Check logs: `tail -f /tmp/gosqlx-lsp.log`

**Linter Issues:**
1. List available rules: `gosqlx lint --list-rules`
2. Show config: `gosqlx lint --show-config`
3. Test specific rule: `gosqlx lint --rules L001 query.sql`

**Parser Issues:**
1. Test tokenization: `gosqlx parse --tokens query.sql`
2. Check AST: `gosqlx parse --format json query.sql`
3. Validate syntax: `gosqlx validate query.sql`

### Submitting Issues

When submitting bug reports, include:

```markdown
### Environment
- GoSQLX version: `gosqlx --version`
- Go version: `go version`
- OS: `uname -a`

### Issue Description
[Clear description of the problem]

### Reproduction
```sql
-- Minimal SQL that reproduces the issue
SELECT * FROM users WHERE id = 1;
```

### Expected Behavior
[What you expected to happen]

### Actual Behavior
[What actually happened, with full error messages]

### Additional Context
- Configuration file (if relevant)
- IDE/editor being used (for LSP issues)
- Relevant code snippets
```

### Performance Issues

If experiencing performance problems:

1. **Collect Metrics:**
```go
import "github.com/ajitpratap0/GoSQLX/pkg/metrics"

snapshot := metrics.GetSnapshot()
log.Printf("Pool hit rate: %.2f%%",
    float64(snapshot.TokenizerPuts)/float64(snapshot.TokenizerGets)*100)
```

2. **Profile Application:**
```bash
go test -bench=. -cpuprofile=cpu.prof -memprofile=mem.prof
go tool pprof -http=:8080 cpu.prof
```

3. **Check Pool Usage:**
```bash
# Look for missing defer statements
grep -n "GetTokenizer()" *.go | grep -v "defer"
```

### Community Support

- **GitHub Issues**: https://github.com/ajitpratap0/GoSQLX/issues
- **Discussions**: Use GitHub Discussions for questions
- **Examples**: Check closed issues for similar problems
- **Contributing**: See CONTRIBUTING.md for guidelines

### Quick Reference

**Most Common Issues:**
1. Missing `defer` with pool operations (95% of panics)
2. LSP not in PATH (most IDE integration issues)
3. Configuration file syntax errors (YAML validation)
4. Race conditions from shared tokenizer instances
5. Memory leaks from unreleased AST objects

**Quick Fixes:**
```go
// ALWAYS do this:
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)  // MANDATORY

astObj := ast.NewAST()
defer ast.ReleaseAST(astObj)  // MANDATORY

// NEVER share across goroutines:
// Each goroutine needs its own tokenizer instance
```

**Remember:**
- Most issues stem from improper pool usage or missing `defer` statements
- LSP issues are usually PATH or configuration problems
- Parser issues often need SQL dialect clarification
- Performance issues typically relate to pool usage or file size

---

**Still Stuck?** Check existing issues or create a new one with full details.