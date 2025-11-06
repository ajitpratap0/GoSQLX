# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Currently supported versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of GoSQLX seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Please do NOT:
- Open a public GitHub issue
- Post about it publicly on social media
- Exploit the vulnerability in production systems

### Please DO:
- Open a security advisory: https://github.com/ajitpratap0/GoSQLX/security/advisories/new
- Or create a private issue with "SECURITY:" prefix
- Provide detailed steps to reproduce the issue
- Allow us reasonable time to fix the issue before public disclosure

## What to Include

When reporting a vulnerability, please include:

1. **Description**: Clear description of the vulnerability
2. **Impact**: Potential impact and attack scenarios
3. **Steps to Reproduce**: Detailed steps to reproduce the issue
4. **Affected Versions**: Which versions are affected
5. **Suggested Fix**: If you have ideas on how to fix it

## Response Timeline

- **Initial Response**: Best effort
- **Confirmation**: Best effort
- **Fix Development**: Based on severity and available resources
- **Security Advisory**: After fix is released

## Security Best Practices

When using GoSQLX in your applications:

### 1. Input Validation
Always validate and sanitize SQL input before parsing:
```go
// Good practice
if err := validateInput(userSQL); err != nil {
    return fmt.Errorf("invalid input: %w", err)
}
tokens, err := tokenizer.Tokenize([]byte(userSQL))
```

### 2. Resource Limits
GoSQLX includes built-in DoS protection with the following limits:
- **Maximum Input Size**: 10MB (10 * 1024 * 1024 bytes)
- **Maximum Token Count**: 1,000,000 tokens per query

These limits are enforced automatically by the tokenizer:
```go
// Built-in protection - no additional code needed
tokens, err := tokenizer.Tokenize([]byte(sql))
if err != nil {
    // Will return error if input exceeds 10MB or would generate >1M tokens
    return fmt.Errorf("tokenization failed: %w", err)
}
```

For additional application-specific limits:
```go
const maxSQLLength = 1_000_000 // 1MB max (custom limit)
if len(sql) > maxSQLLength {
    return errors.New("SQL query too large")
}
```

### 3. Timeout Controls
Use timeouts for parsing operations:
```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
// Parse with timeout context
```

### 4. Pool Management
Always return objects to pools to prevent resource exhaustion:
```go
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz) // Always defer return

astObj := ast.NewAST()
defer ast.ReleaseAST(astObj) // Always defer return
```

## Known Security Considerations

### Memory Management
- GoSQLX uses object pooling which could potentially leak data between requests
- Always clear sensitive data after use
- Use dedicated pools for security-sensitive contexts

### Denial of Service
GoSQLX includes built-in DoS protection:
- **Input Size Limit**: Maximum 10MB per query (automatically enforced)
- **Token Count Limit**: Maximum 1,000,000 tokens per query (automatically enforced)
- **Recursion Depth Limit**: Maximum 100 levels of nesting (automatically enforced)
- Queries exceeding these limits will fail fast with descriptive errors

Additional recommendations:
- Implement rate limiting at the application level
- Set timeout contexts for parsing operations
- Monitor resource usage in production
- Consider additional custom limits based on your use case

### Stack Overflow Protection (QW-005)
GoSQLX implements recursion depth limits to prevent stack overflow attacks from deeply nested SQL expressions:

**Protection Features**:
- **Maximum Recursion Depth**: 100 levels (configurable via `MaxRecursionDepth` constant in `parser.go`)
- **Protected Operations**: Expression parsing, CTEs, nested function calls, window functions
- **Performance Impact**: <1% overhead (verified via benchmarks)
- **Error Handling**: Returns structured error with clear message when depth exceeded

**Example of Protected Attack**:
```go
// This malicious query with 1000+ nested functions is safely rejected:
// SELECT f(f(f(...f(x)...))) FROM t  -- 1000 levels deep
// Error: "maximum recursion depth exceeded (100) - expression too deeply nested"

// The parser safely rejects this without stack overflow
tokens, _ := tokenizer.Tokenize([]byte(maliciousSQL))
_, err := parser.Parse(tokens)
// err != nil: "maximum recursion depth exceeded"
```

**Implementation Details**:
- Depth counter incremented on entry to recursive methods (`parseExpression`, `parseCommonTableExpr`)
- Automatic decrement on exit via `defer` ensures proper cleanup
- Depth reset between independent parse operations
- Thread-safe depth tracking per parser instance
- No performance degradation for normal queries (tested up to 50 levels of realistic nesting)

### SQL Injection
- GoSQLX is a parser, not a query executor
- It does NOT protect against SQL injection
- Always use parameterized queries when executing SQL

## Security Updates

Security updates will be released as:
- Patch versions for non-breaking fixes (1.0.x)
- Minor versions if breaking changes are required (1.x.0)

Subscribe to security advisories:
- Watch the repository for releases
- Follow @gosqlx on Twitter
- Join our security mailing list

## Acknowledgments

We appreciate responsible disclosure of security vulnerabilities. Security researchers who report valid issues will be acknowledged in our Hall of Fame (unless they prefer to remain anonymous).

### Hall of Fame
- (Your name could be here!)

## Contact

- Security Advisory Page: https://github.com/ajitpratap0/GoSQLX/security/advisories
- GitHub Issues (private): Use "SECURITY:" prefix in title