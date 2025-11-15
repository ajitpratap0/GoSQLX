# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Currently supported versions:

| Version | Supported          | Security Updates |
| ------- | ------------------ | ---------------- |
| 1.5.x   | :white_check_mark: | Active           |
| 1.4.x   | :white_check_mark: | Active           |
| 1.0-1.3 | :x:                | Upgrade Required |
| < 1.0   | :x:                | Not Supported    |

**Upgrade Policy**: We recommend always using the latest version for optimal security and performance.

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

## Automated Security Scanning

GoSQLX implements comprehensive automated security scanning:

### Continuous Monitoring
- **GoSec**: Static security analyzer for Go code (runs on every push/PR)
- **Trivy**: Comprehensive vulnerability scanner for dependencies and configurations
- **GovulnCheck**: Official Go vulnerability database checker
- **Dependabot**: Automated dependency updates with security patch monitoring
- **Weekly Scans**: Full security audit every Sunday at midnight UTC

### Security Thresholds
- **Build Failure**: High or critical vulnerabilities block merges
- **Medium Severity**: Reviewed but may not block deployment
- **Low Severity**: Tracked and addressed in maintenance releases

### Viewing Security Reports
- Navigate to repository **Security** tab
- Review **Code Scanning Alerts** for detailed findings
- Check **Dependabot Alerts** for dependency vulnerabilities
- View workflow runs in **Actions** tab for scan details

## Security Updates

Security updates will be released as:
- **Patch versions** (1.x.Y) for non-breaking security fixes
- **Minor versions** (1.X.0) if breaking changes are required for security
- **Emergency releases** within 24-48 hours for critical vulnerabilities

### Update Notifications
Subscribe to security advisories:
- **GitHub Security Advisories**: Watch the repository for security alerts
- **GitHub Releases**: Enable notifications for new releases
- **Dependabot**: Automatic PR creation for vulnerable dependencies
- **Security Tab**: Review active security alerts

## Acknowledgments

We appreciate responsible disclosure of security vulnerabilities. Security researchers who report valid issues will be acknowledged in our Hall of Fame (unless they prefer to remain anonymous).

### Hall of Fame
- (Your name could be here!)

## Contact

- **Security Advisory Page**: https://github.com/ajitpratap0/GoSQLX/security/advisories
- **GitHub Issues (private)**: Use "SECURITY:" prefix in title
- **Email**: For urgent security matters, contact the maintainers directly through GitHub
- **Response Time**: Initial acknowledgment within 48 hours for critical issues

## Security Compliance

GoSQLX follows industry best practices:
- **OWASP Guidelines**: Aligned with OWASP secure coding practices
- **CWE Mitigation**: Addresses common weakness enumeration patterns
- **CVE Tracking**: All dependencies monitored for known CVE entries
- **SBOM**: Software Bill of Materials available on request