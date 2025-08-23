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
Set appropriate limits for SQL parsing:
```go
const maxSQLLength = 1_000_000 // 1MB max
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
```

## Known Security Considerations

### Memory Management
- GoSQLX uses object pooling which could potentially leak data between requests
- Always clear sensitive data after use
- Use dedicated pools for security-sensitive contexts

### Denial of Service
- Large or complex SQL queries could cause high CPU/memory usage
- Implement rate limiting and resource quotas
- Monitor resource usage in production

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