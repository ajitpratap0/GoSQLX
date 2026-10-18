# security package

SQL injection pattern detection with severity classification.

Import path: `github.com/ajitpratap0/GoSQLX/pkg/sql/security` ([pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/sql/security))

Part of the [GoSQLX API reference](../API_REFERENCE.md).

The security package provides SQL injection pattern detection and security scanning.

## Types

### `Scanner`
```go
type Scanner struct {
    MinSeverity Severity // Filter findings by minimum severity
}
```

### `Severity`
```go
type Severity string

const (
    SeverityLow      Severity = "LOW"
    SeverityMedium   Severity = "MEDIUM"
    SeverityHigh     Severity = "HIGH"
    SeverityCritical Severity = "CRITICAL"
)
```

### `PatternType`
```go
type PatternType string

const (
    PatternTautology     PatternType = "TAUTOLOGY"
    PatternComment       PatternType = "COMMENT_BYPASS"
    PatternStackedQuery  PatternType = "STACKED_QUERY"
    PatternUnionBased    PatternType = "UNION_BASED"
    PatternTimeBased     PatternType = "TIME_BASED"
    PatternBooleanBased  PatternType = "BOOLEAN_BASED"
    PatternOutOfBand     PatternType = "OUT_OF_BAND"
    PatternDangerousFunc PatternType = "DANGEROUS_FUNCTION"
)
```

### `Finding`
```go
type Finding struct {
    Severity    Severity    // Severity level
    Pattern     PatternType // Pattern type detected
    Description string      // Description of the finding
    Risk        string      // Risk explanation
    Line        int         // Line number (if available)
    Column      int         // Column number (if available)
    SQL         string      // SQL snippet (if available)
    Suggestion  string      // Fix suggestion
}
```

### `ScanResult`
```go
type ScanResult struct {
    Findings      []Finding // All findings
    TotalCount    int       // Total findings
    CriticalCount int       // Critical findings
    HighCount     int       // High severity findings
    MediumCount   int       // Medium severity findings
    LowCount      int       // Low severity findings
}
```

## Functions

### `NewScanner() *Scanner`
Create security scanner with default settings (minimum severity: LOW).

```go
scanner := security.NewScanner()
```

### `NewScannerWithSeverity(minSeverity Severity) (*Scanner, error)`
Create scanner with custom minimum severity filter.

```go
scanner, err := security.NewScannerWithSeverity(security.SeverityHigh)
// Only returns HIGH and CRITICAL findings
```

### `(s *Scanner) Scan(ast *ast.AST) *ScanResult`
Scan parsed AST for security issues.

```go
scanner := security.NewScanner()
ast, _ := gosqlx.Parse(sql)
result := scanner.Scan(ast)

for _, finding := range result.Findings {
    fmt.Printf("[%s] %s: %s\n", finding.Severity, finding.Pattern, finding.Description)
}
```

### `(s *Scanner) ScanSQL(sql string) *ScanResult`
Scan raw SQL string for injection patterns (useful for patterns not in AST).

```go
scanner := security.NewScanner()
result := scanner.ScanSQL("SELECT * FROM users WHERE id = '" + userInput + "'")
```

### `(r *ScanResult) HasCritical() bool`
Returns true if any critical findings exist.

### `(r *ScanResult) HasHighOrAbove() bool`
Returns true if any high or critical findings exist.

### `(r *ScanResult) IsClean() bool`
Returns true if no findings exist.

## Detection Patterns

The scanner detects 8 pattern types:

1. **Tautologies** - Always-true conditions (e.g., `1=1`, `'a'='a'`)
2. **Comment Bypasses** - SQL comment-based injection (`--`, `/**/`, `#`)
3. **UNION-Based Injection** - Data extraction via UNION SELECT
4. **Stacked Queries** - Destructive statements after semicolon (`;DROP`, `;DELETE`)
5. **Time-Based Blind** - Time delay functions (SLEEP, WAITFOR DELAY, pg_sleep, BENCHMARK)
6. **Out-of-Band** - Data exfiltration (xp_cmdshell, LOAD_FILE, UTL_HTTP)
7. **Dangerous Functions** - Dynamic SQL execution (EXEC, sp_executesql, PREPARE FROM)
8. **Boolean-Based** - Conditional logic exploitation

**Example:**
```go
scanner := security.NewScanner()

// Detect tautology
sql := "SELECT * FROM users WHERE username = 'admin' OR 1=1 --"
result := scanner.ScanSQL(sql)
// Finding: TAUTOLOGY, Severity: CRITICAL

// Detect UNION injection
sql := "SELECT * FROM products WHERE id = 1 UNION SELECT NULL, username, password FROM users"
result = scanner.ScanSQL(sql)
// Finding: UNION_BASED, Severity: CRITICAL

// Detect time-based injection
sql := "SELECT * FROM orders WHERE id = 1; SELECT SLEEP(5)"
result = scanner.ScanSQL(sql)
// Finding: TIME_BASED, Severity: HIGH

// Clean SQL
sql := "SELECT * FROM users WHERE id = $1"
result = scanner.ScanSQL(sql)
// result.IsClean() == true
```

**v1.6.0 Performance:**
- Pre-compiled regex patterns for performance
- Thread-safe pattern compilation (sync.Once)
- Precise system table matching (avoids false positives)
- 100% detection rate on common injection patterns
