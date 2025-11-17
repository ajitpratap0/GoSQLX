# Tutorial 1: Building a SQL Validator for CI/CD

## What You'll Build

In this tutorial, you'll create a SQL validation tool that scans directories for SQL files and validates their syntax. This is perfect for:

- Catching SQL syntax errors in CI/CD pipelines before deployment
- Validating migration files before they run
- Enforcing SQL quality standards across your team
- Pre-commit hooks to prevent broken SQL from being committed

**Time to Complete**: ~25 minutes

## What You'll Learn

- How to use GoSQLX tokenizer and parser
- Processing multiple files and directories
- Proper error reporting and exit codes
- Integration with GitHub Actions, GitLab CI, and git hooks

## Prerequisites

- Go 1.21 or higher installed
- Basic understanding of SQL
- Familiarity with command-line tools
- GoSQLX installed: `go get github.com/ajitpratap0/GoSQLX`

## Step 1: Project Setup

Create a new directory for your validator:

```bash
mkdir sql-validator
cd sql-validator
go mod init sql-validator
go get github.com/ajitpratap0/GoSQLX
```

## Step 2: Understanding the Core Validation Logic

GoSQLX provides a simple API for validating SQL:

```go
// 1. Get a tokenizer from the pool
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)

// 2. Tokenize the SQL
tokens, err := tkz.Tokenize([]byte(sqlContent))
if err != nil {
    // Syntax error found
}

// 3. Parse the tokens into an AST
astObj := ast.NewAST()
defer ast.ReleaseAST(astObj)

result, err := parser.Parse(tokens)
if err != nil {
    // Parse error found
}
```

## Step 3: Create the Validator Core

Create `validator.go`:

```go
package main

import (
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// ValidationResult holds the result of validating a single SQL file
type ValidationResult struct {
    FilePath string
    Valid    bool
    Error    error
}

// ValidateFile validates a single SQL file
func ValidateFile(filePath string) ValidationResult {
    // Read the file
    content, err := os.ReadFile(filePath)
    if err != nil {
        return ValidationResult{
            FilePath: filePath,
            Valid:    false,
            Error:    fmt.Errorf("failed to read file: %w", err),
        }
    }

    // Get tokenizer from pool
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    // Tokenize the SQL
    tokens, err := tkz.Tokenize(content)
    if err != nil {
        return ValidationResult{
            FilePath: filePath,
            Valid:    false,
            Error:    fmt.Errorf("tokenization error: %w", err),
        }
    }

    // Get AST from pool
    astObj := ast.NewAST()
    defer ast.ReleaseAST(astObj)

    // Parse the tokens
    _, err = parser.Parse(tokens)
    if err != nil {
        return ValidationResult{
            FilePath: filePath,
            Valid:    false,
            Error:    fmt.Errorf("parse error: %w", err),
        }
    }

    return ValidationResult{
        FilePath: filePath,
        Valid:    true,
        Error:    nil,
    }
}

// ValidateDirectory recursively validates all .sql files in a directory
func ValidateDirectory(dirPath string) ([]ValidationResult, error) {
    var results []ValidationResult

    err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }

        // Skip directories
        if info.IsDir() {
            return nil
        }

        // Only process .sql files
        if !strings.HasSuffix(strings.ToLower(path), ".sql") {
            return nil
        }

        // Validate the file
        result := ValidateFile(path)
        results = append(results, result)

        return nil
    })

    if err != nil {
        return nil, fmt.Errorf("failed to walk directory: %w", err)
    }

    return results, nil
}

// PrintResults prints validation results in a user-friendly format
func PrintResults(results []ValidationResult) {
    validCount := 0
    invalidCount := 0

    fmt.Println("\n=== SQL Validation Results ===\n")

    for _, result := range results {
        if result.Valid {
            fmt.Printf("✓ %s\n", result.FilePath)
            validCount++
        } else {
            fmt.Printf("✗ %s\n", result.FilePath)
            fmt.Printf("  Error: %v\n\n", result.Error)
            invalidCount++
        }
    }

    fmt.Printf("\n=== Summary ===\n")
    fmt.Printf("Total files: %d\n", len(results))
    fmt.Printf("Valid: %d\n", validCount)
    fmt.Printf("Invalid: %d\n", invalidCount)
}
```

## Step 4: Create the CLI Interface

Create `main.go`:

```go
package main

import (
    "fmt"
    "os"
)

func main() {
    if len(os.Args) < 2 {
        fmt.Println("Usage: sql-validator <file-or-directory>")
        fmt.Println("\nExamples:")
        fmt.Println("  sql-validator query.sql")
        fmt.Println("  sql-validator ./migrations")
        fmt.Println("  sql-validator .")
        os.Exit(1)
    }

    target := os.Args[1]

    // Check if target exists
    info, err := os.Stat(target)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }

    var results []ValidationResult

    // Process file or directory
    if info.IsDir() {
        fmt.Printf("Scanning directory: %s\n", target)
        results, err = ValidateDirectory(target)
        if err != nil {
            fmt.Printf("Error scanning directory: %v\n", err)
            os.Exit(1)
        }
    } else {
        fmt.Printf("Validating file: %s\n", target)
        result := ValidateFile(target)
        results = []ValidationResult{result}
    }

    // Print results
    PrintResults(results)

    // Exit with error code if any files are invalid
    for _, result := range results {
        if !result.Valid {
            os.Exit(1)
        }
    }

    fmt.Println("\nAll SQL files are valid!")
    os.Exit(0)
}
```

## Step 5: Build and Test

Build your validator:

```bash
go build -o sql-validator
```

Create test SQL files to validate:

**valid.sql**:
```sql
SELECT id, name, email
FROM users
WHERE active = true
ORDER BY created_at DESC;
```

**invalid.sql**:
```sql
SELECT id, name, email
FROM users
WHERE active = true
ORDER BY created_at DESC
INVALID SYNTAX HERE;
```

Test the validator:

```bash
# Validate a single file
./sql-validator valid.sql

# Expected output:
# Validating file: valid.sql
#
# === SQL Validation Results ===
#
# ✓ valid.sql
#
# === Summary ===
# Total files: 1
# Valid: 1
# Invalid: 0
#
# All SQL files are valid!

# Test with invalid file
./sql-validator invalid.sql

# Expected output:
# Validating file: invalid.sql
#
# === SQL Validation Results ===
#
# ✗ invalid.sql
#   Error: parse error: ...
#
# === Summary ===
# Total files: 1
# Valid: 0
# Invalid: 1
```

## Step 6: GitHub Actions Integration

Create `.github/workflows/validate-sql.yml`:

```yaml
name: Validate SQL Files

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  validate:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.21'

    - name: Install SQL Validator
      run: |
        git clone https://github.com/ajitpratap0/GoSQLX.git
        cd GoSQLX/examples/tutorials/01-sql-validator
        go build -o sql-validator
        sudo mv sql-validator /usr/local/bin/

    - name: Validate SQL Files
      run: |
        sql-validator ./sql
```

## Step 7: GitLab CI Integration

Create `.gitlab-ci.yml`:

```yaml
stages:
  - validate

validate-sql:
  stage: validate
  image: golang:1.21
  script:
    - git clone https://github.com/ajitpratap0/GoSQLX.git
    - cd GoSQLX/examples/tutorials/01-sql-validator
    - go build -o sql-validator
    - ./sql-validator ../../sql
  only:
    - merge_requests
    - main
```

## Step 8: Pre-commit Hook Integration

Create `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: validate-sql
        name: Validate SQL Files
        entry: sql-validator
        language: system
        files: \.sql$
        pass_filenames: true
```

Install the hook:

```bash
pip install pre-commit
pre-commit install
```

Alternatively, create a simple git hook at `.git/hooks/pre-commit`:

```bash
#!/bin/bash

# Find all staged .sql files
SQL_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.sql$')

if [ -n "$SQL_FILES" ]; then
    echo "Validating SQL files..."

    for file in $SQL_FILES; do
        sql-validator "$file"
        if [ $? -ne 0 ]; then
            echo "SQL validation failed for $file"
            exit 1
        fi
    done

    echo "All SQL files validated successfully!"
fi

exit 0
```

Make it executable:

```bash
chmod +x .git/hooks/pre-commit
```

## Advanced Features

### Add Verbose Output

Enhance `main.go` to support verbose mode:

```go
func main() {
    verbose := false
    target := ""

    // Parse arguments
    for i := 1; i < len(os.Args); i++ {
        arg := os.Args[i]
        if arg == "-v" || arg == "--verbose" {
            verbose = true
        } else {
            target = arg
        }
    }

    if target == "" {
        fmt.Println("Usage: sql-validator [-v] <file-or-directory>")
        os.Exit(1)
    }

    // ... rest of validation logic

    if verbose {
        // Print detailed token/AST information
        fmt.Printf("Tokens: %d\n", len(tokens))
    }
}
```

### Add JSON Output

For easier CI integration:

```go
func PrintResultsJSON(results []ValidationResult) {
    output := struct {
        TotalFiles int                  `json:"total_files"`
        Valid      int                  `json:"valid"`
        Invalid    int                  `json:"invalid"`
        Results    []ValidationResult   `json:"results"`
    }{
        TotalFiles: len(results),
        Results:    results,
    }

    for _, r := range results {
        if r.Valid {
            output.Valid++
        } else {
            output.Invalid++
        }
    }

    json.NewEncoder(os.Stdout).Encode(output)
}
```

## Troubleshooting

### Issue: "Failed to read file"
**Solution**: Check file permissions and ensure the path is correct.

### Issue: "Tokenization error"
**Solution**: This means the SQL has invalid characters or syntax. Check for:
- Unterminated strings
- Invalid operators
- Unsupported characters

### Issue: "Parse error"
**Solution**: The SQL has structural issues. Common causes:
- Missing semicolons
- Unmatched parentheses
- Invalid SQL keywords
- Incorrect JOIN syntax

### Issue: Validator too slow on large directories
**Solution**: Add concurrent processing:

```go
func ValidateDirectoryConcurrent(dirPath string, workers int) ([]ValidationResult, error) {
    // Collect all SQL files first
    var files []string
    filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
        if !info.IsDir() && strings.HasSuffix(strings.ToLower(path), ".sql") {
            files = append(files, path)
        }
        return nil
    })

    // Process concurrently
    resultsChan := make(chan ValidationResult, len(files))
    semaphore := make(chan struct{}, workers)

    for _, file := range files {
        go func(f string) {
            semaphore <- struct{}{}
            resultsChan <- ValidateFile(f)
            <-semaphore
        }(file)
    }

    // Collect results
    var results []ValidationResult
    for i := 0; i < len(files); i++ {
        results = append(results, <-resultsChan)
    }

    return results, nil
}
```

## Next Steps

Now that you've built a SQL validator, you can:

1. **Add more validation rules**: Check for specific patterns, naming conventions, or anti-patterns
2. **Create a custom reporter**: Generate HTML or markdown reports
3. **Add performance metrics**: Track validation time and SQL complexity
4. **Move to Tutorial 2**: Build a custom SQL formatter with team-specific rules

## Full Example

The complete, working code for this tutorial is available at:
`examples/tutorials/01-sql-validator/`

To run it:

```bash
cd examples/tutorials/01-sql-validator
go build
./sql-validator testdata/
```

## Summary

You've learned how to:
- Use GoSQLX tokenizer and parser for SQL validation
- Build a CLI tool with proper error handling and exit codes
- Integrate SQL validation into CI/CD pipelines
- Set up pre-commit hooks for development workflow
- Handle both single files and directories recursively

This validator is production-ready and can be customized for your team's needs!
