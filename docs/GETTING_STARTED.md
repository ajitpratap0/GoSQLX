# Getting Started with GoSQLX in 5 Minutes

Welcome! This guide will get you parsing SQL in under 5 minutes. No prior experience with GoSQLX required.

---

## Step 1: Install GoSQLX (30 seconds)

### Option A: Using Go Get (Recommended)
```bash
go get github.com/ajitpratap0/GoSQLX
```

### Option B: Install CLI Tool
```bash
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
```

**Requirements**: Go 1.19 or higher

---

## Step 2: Verify Installation (30 seconds)

Let's make sure everything works:

### If you installed the CLI:
```bash
gosqlx validate "SELECT 1"
```

**Expected output:**
```
✓ Valid SQL
```

### If you installed the library:
```bash
go version
# Should show Go 1.19+
```

---

## Step 3: Parse Your First Query with CLI (1 minute)

The fastest way to get started is with the CLI:

### Validate SQL syntax:
```bash
gosqlx validate "SELECT * FROM users WHERE active = true"
```

### Format SQL:
```bash
gosqlx format "select * from users where age>18"
```

**Output:**
```sql
SELECT *
FROM users
WHERE age > 18
```

### Analyze SQL structure:
```bash
gosqlx analyze "SELECT COUNT(*) FROM orders GROUP BY status"
```

**That's it!** You're validating and formatting SQL. ✨

---

## Step 4: Parse Your First Query with Go (2 minutes)

Now let's use GoSQLX in your Go application.

### Create a file `main.go`:

```go
package main

import (
    "fmt"
    "log"

    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func main() {
    sql := "SELECT * FROM users"

    // Parse SQL in one line!
    ast, err := gosqlx.Parse(sql)
    if err != nil {
        log.Fatalf("Parsing failed: %v", err)
    }

    // Success!
    fmt.Printf("✓ Successfully parsed SQL!\n")
    fmt.Printf("  Type: %T\n", ast)
    fmt.Printf("  Statements: %d\n", len(ast.Statements))
}
```

**That's it!** Just 3 lines of actual code. 🎉

### Need to validate without parsing?

```go
if err := gosqlx.Validate("SELECT * FROM users"); err != nil {
    fmt.Println("Invalid SQL:", err)
} else {
    fmt.Println("Valid SQL!")
}
```

### Run it:
```bash
go run main.go
```

**Expected output:**
```
✓ Successfully parsed SQL!
  Type: *ast.AST
  Statements: 1
```

**Congratulations!** You've parsed your first SQL query with GoSQLX! 🎉

---

## Step 5: What's Next? (1 minute)

### Learn More:
- **[Usage Guide](USAGE_GUIDE.md)** - Comprehensive patterns and examples
- **[CLI Guide](CLI_GUIDE.md)** - Full CLI documentation
- **[API Reference](API_REFERENCE.md)** - Complete API documentation
- **[Examples](../examples/)** - Real-world code examples

### Common Tasks:

#### Validate SQL in Your Application:
```go
func ValidateSQL(sql string) error {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    _, err := tkz.Tokenize([]byte(sql))
    return err
}
```

#### Process Multiple Queries:
```go
func ProcessBatch(queries []string) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    for _, query := range queries {
        tokens, err := tkz.Tokenize([]byte(query))
        if err != nil {
            fmt.Printf("✗ Invalid: %s\n", query)
            continue
        }
        fmt.Printf("✓ Valid: %d tokens\n", len(tokens))
    }
}
```

#### Use in CI/CD:
```bash
# In your .github/workflows/test.yml
- name: Validate SQL
  run: |
    gosqlx validate migrations/*.sql
    gosqlx format --check queries/*.sql
```

---

## Common Pitfalls ⚠️

### 1. Forgetting to Return to Pool
**❌ Wrong:**
```go
tkz := tokenizer.GetTokenizer()
tokens, _ := tkz.Tokenize([]byte(sql))
// Missing: defer tokenizer.PutTokenizer(tkz)
```

**✅ Correct:**
```go
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)  // Always use defer!
tokens, _ := tkz.Tokenize([]byte(sql))
```

### 2. Reusing Tokenizer Without Reset
**❌ Wrong:**
```go
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)

tokens1, _ := tkz.Tokenize([]byte(sql1))
tokens2, _ := tkz.Tokenize([]byte(sql2))  // State from sql1 still there!
```

**✅ Correct:**
```go
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)

tokens1, _ := tkz.Tokenize([]byte(sql1))

// Reset state before reusing
tkz.Reset()
tokens2, _ := tkz.Tokenize([]byte(sql2))
```

### 3. Not Checking for EOF
**❌ Wrong:**
```go
for _, tok := range tokens {
    fmt.Println(tok.Token.Value)  // Will print empty EOF token
}
```

**✅ Correct:**
```go
for _, tok := range tokens {
    if tok.Token.Type == models.TokenTypeEOF {
        break
    }
    fmt.Println(tok.Token.Value)
}
```

---

## Quick Reference

### Key Imports:
```go
import (
    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
    "github.com/ajitpratap0/GoSQLX/pkg/models"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)
```

### Essential Pattern:
```go
// 1. Get from pool
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)

// 2. Tokenize
tokens, err := tkz.Tokenize([]byte(sql))

// 3. Check for errors
if err != nil {
    // Handle error
}

// 4. Process tokens
for _, tok := range tokens {
    if tok.Token.Type == models.TokenTypeEOF {
        break
    }
    // Use tok
}
```

### CLI Commands:
```bash
gosqlx validate <query or file>   # Validate SQL syntax
gosqlx format <query or file>     # Format SQL with style
gosqlx analyze <query or file>    # Analyze SQL structure
gosqlx parse <query or file>      # Parse to AST
```

---

## Troubleshooting

### "command not found: gosqlx"
**Solution:** Make sure `$GOPATH/bin` is in your `PATH`:
```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

### "cannot find package"
**Solution:** Run `go mod tidy` to download dependencies:
```bash
go mod init myproject
go get github.com/ajitpratap0/GoSQLX
go mod tidy
```

### "tokenization failed: unexpected character"
**Solution:** Check for invalid SQL syntax. Use CLI to debug:
```bash
gosqlx validate "your SQL here"
```

### Need Help?
- **[Troubleshooting Guide](TROUBLESHOOTING.md)** - Common issues and solutions
- **[GitHub Issues](https://github.com/ajitpratap0/GoSQLX/issues)** - Report bugs or ask questions
- **[Discussions](https://github.com/ajitpratap0/GoSQLX/discussions)** - Community Q&A

---

## Performance Tips 💡

GoSQLX is designed for high performance. Here are quick tips:

1. **Always use object pools** (via `defer`)
2. **Reuse tokenizer for multiple queries** (with `Reset()`)
3. **Avoid string conversions** when possible
4. **Use batch processing** for multiple queries
5. **Profile with benchmarks** for critical paths

See [Performance Optimization](USAGE_GUIDE.md#performance-optimization) for details.

---

## What You've Learned ✅

- ✓ Installing GoSQLX (library and CLI)
- ✓ Validating SQL with CLI
- ✓ Parsing SQL in Go applications
- ✓ Using object pools correctly
- ✓ Common pitfalls to avoid
- ✓ Where to find more help

---

## Next Steps 🚀

**For CLI Users:**
- Explore all CLI commands: [CLI Guide](CLI_GUIDE.md)
- Integrate into CI/CD pipelines
- Batch process SQL files

**For Library Users:**
- Learn advanced patterns: [Usage Guide](USAGE_GUIDE.md)
- Build custom SQL analysis tools
- Optimize for your use case

**For Everyone:**
- Check out [real-world examples](../examples/)
- Read the [architecture documentation](ARCHITECTURE.md)
- Contribute to [the project](../CONTRIBUTING.md)

---

**Time to first success:** < 5 minutes ✓

**Questions?** Open an issue or start a discussion on GitHub!

---

*Built with ❤️ by the GoSQLX community*
