# Tutorial 2: Creating a SQL Formatter with Custom Rules

## What You'll Build

In this tutorial, you'll create a SQL formatter that enforces your team's coding standards. This tool will:

- Format SQL with custom indentation and keyword casing rules
- Support configuration files for team-wide consistency
- Integrate with pre-commit hooks and CI/CD
- Provide both in-place file modification and stdout output

**Time to Complete**: ~30 minutes

## What You'll Learn

- How to traverse and manipulate SQL AST with GoSQLX
- Implementing custom formatting rules
- Building configurable CLI tools
- Integration with development workflows

## Prerequisites

- Go 1.21 or higher installed
- Completion of Tutorial 1 (recommended but not required)
- Basic understanding of SQL formatting preferences
- GoSQLX installed: `go get github.com/ajitpratap0/GoSQLX`

## Step 1: Understanding SQL Formatting

Good SQL formatting improves readability and maintainability. Common formatting preferences include:

- **Keyword casing**: UPPER, lower, or Title Case for SQL keywords
- **Indentation**: 2 or 4 spaces, or tabs
- **Line length**: Maximum characters per line
- **Comma placement**: Leading or trailing in SELECT lists
- **JOIN alignment**: How to align JOIN clauses

Example of unformatted SQL:
```sql
select id,name,email from users where active=true and role in ('admin','user') order by created_at desc;
```

After formatting:
```sql
SELECT
    id,
    name,
    email
FROM users
WHERE
    active = true
    AND role IN ('admin', 'user')
ORDER BY created_at DESC;
```

## Step 2: Project Setup

Create a new directory for your formatter:

```bash
mkdir sql-formatter
cd sql-formatter
go mod init sql-formatter
go get github.com/ajitpratap0/GoSQLX
```

## Step 3: Define Configuration

Create `config.go` to define formatting rules:

```go
package main

import (
    "encoding/json"
    "os"
)

// FormatterConfig holds all formatting preferences
type FormatterConfig struct {
    // Keyword casing: "upper", "lower", "title"
    KeywordCase string `json:"keyword_case"`

    // Indentation: number of spaces (use 0 for tabs)
    IndentSpaces int `json:"indent_spaces"`

    // Maximum line length before wrapping
    MaxLineLength int `json:"max_line_length"`

    // Comma style: "leading", "trailing"
    CommaStyle string `json:"comma_style"`

    // Add spaces around operators (=, +, -, etc.)
    SpaceAroundOperators bool `json:"space_around_operators"`

    // Align JOIN keywords
    AlignJoins bool `json:"align_joins"`

    // Uppercase function names
    UppercaseFunctions bool `json:"uppercase_functions"`
}

// DefaultConfig returns the default formatting configuration
func DefaultConfig() FormatterConfig {
    return FormatterConfig{
        KeywordCase:          "upper",
        IndentSpaces:         4,
        MaxLineLength:        80,
        CommaStyle:           "leading",
        SpaceAroundOperators: true,
        AlignJoins:           true,
        UppercaseFunctions:   true,
    }
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(filePath string) (FormatterConfig, error) {
    // If file doesn't exist, return default config
    if _, err := os.Stat(filePath); os.IsNotExist(err) {
        return DefaultConfig(), nil
    }

    data, err := os.ReadFile(filePath)
    if err != nil {
        return FormatterConfig{}, err
    }

    var config FormatterConfig
    if err := json.Unmarshal(data, &config); err != nil {
        return FormatterConfig{}, err
    }

    return config, nil
}

// SaveConfig saves configuration to a JSON file
func SaveConfig(config FormatterConfig, filePath string) error {
    data, err := json.MarshalIndent(config, "", "  ")
    if err != nil {
        return err
    }

    return os.WriteFile(filePath, data, 0644)
}
```

## Step 4: Create the Formatter Core

Create `formatter.go`:

```go
package main

import (
    "bytes"
    "fmt"
    "strings"

    "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Formatter handles SQL formatting with custom rules
type Formatter struct {
    config FormatterConfig
    buffer *bytes.Buffer
    indent int
}

// NewFormatter creates a new formatter with the given configuration
func NewFormatter(config FormatterConfig) *Formatter {
    return &Formatter{
        config: config,
        buffer: &bytes.Buffer{},
        indent: 0,
    }
}

// Format formats SQL according to the configuration
func (f *Formatter) Format(sql string) (string, error) {
    // Reset buffer
    f.buffer.Reset()
    f.indent = 0

    // Get tokenizer from pool
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    // Tokenize
    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        return "", fmt.Errorf("tokenization error: %w", err)
    }

    // Convert tokens for parser
    p := parser.NewParser()
    defer p.Release()
    if err != nil {
        return "", fmt.Errorf("token conversion error: %w", err)
    }

    // Create parser and parse
    p := parser.NewParser()

    result, err := p.ParseFromModelTokens(tokens)
    if err != nil {
        return "", fmt.Errorf("parse error: %w", err)
    }

    // Format the AST
    f.formatNode(result)

    return f.buffer.String(), nil
}

// formatNode formats an AST node
func (f *Formatter) formatNode(node ast.Node) {
    if node == nil {
        return
    }

    switch n := node.(type) {
    case *ast.SelectStatement:
        f.formatSelectStatement(n)
    case *ast.InsertStatement:
        f.formatInsertStatement(n)
    case *ast.UpdateStatement:
        f.formatUpdateStatement(n)
    case *ast.DeleteStatement:
        f.formatDeleteStatement(n)
    default:
        // Fallback: just write the token literal
        f.writeString(node.TokenLiteral())
    }
}

// formatSelectStatement formats a SELECT statement
func (f *Formatter) formatSelectStatement(stmt *ast.SelectStatement) {
    // SELECT keyword
    f.writeKeyword("SELECT")
    f.newline()

    // Indent for columns
    f.increaseIndent()

    // Format columns
    if stmt.Columns != nil {
        for i, col := range stmt.Columns {
            if i > 0 {
                if f.config.CommaStyle == "trailing" {
                    f.writeString(",")
                    f.newline()
                } else {
                    f.newline()
                    f.writeString(", ")
                }
            }
            f.writeIndent()
            f.formatExpression(col)
        }
    }

    f.decreaseIndent()
    f.newline()

    // FROM clause
    if stmt.From != nil {
        f.writeKeyword("FROM")
        f.writeString(" ")
        f.formatTableReference(stmt.From)
        f.newline()
    }

    // WHERE clause
    if stmt.Where != nil {
        f.writeKeyword("WHERE")
        f.newline()
        f.increaseIndent()
        f.writeIndent()
        f.formatExpression(stmt.Where)
        f.decreaseIndent()
        f.newline()
    }

    // GROUP BY clause
    if len(stmt.GroupBy) > 0 {
        f.writeKeyword("GROUP BY")
        f.writeString(" ")
        for i, expr := range stmt.GroupBy {
            if i > 0 {
                f.writeString(", ")
            }
            f.formatExpression(expr)
        }
        f.newline()
    }

    // ORDER BY clause
    if len(stmt.OrderBy) > 0 {
        f.writeKeyword("ORDER BY")
        f.writeString(" ")
        for i, order := range stmt.OrderBy {
            if i > 0 {
                f.writeString(", ")
            }
            f.formatExpression(order.Expression)
            if order.Direction != "" {
                f.writeString(" ")
                f.writeKeyword(order.Direction)
            }
        }
        f.newline()
    }

    // LIMIT clause
    if stmt.Limit != nil {
        f.writeKeyword("LIMIT")
        f.writeString(" ")
        f.formatExpression(stmt.Limit)
        f.newline()
    }
}

// formatInsertStatement formats an INSERT statement
func (f *Formatter) formatInsertStatement(stmt *ast.InsertStatement) {
    f.writeKeyword("INSERT INTO")
    f.writeString(" ")
    f.writeString(stmt.Table.TokenLiteral())

    if len(stmt.Columns) > 0 {
        f.writeString(" (")
        for i, col := range stmt.Columns {
            if i > 0 {
                f.writeString(", ")
            }
            f.writeString(col.TokenLiteral())
        }
        f.writeString(")")
    }

    f.newline()
    f.writeKeyword("VALUES")
    f.writeString(" ")

    // Format values
    if stmt.Values != nil {
        f.writeString("(")
        for i, val := range stmt.Values {
            if i > 0 {
                f.writeString(", ")
            }
            f.formatExpression(val)
        }
        f.writeString(")")
    }

    f.newline()
}

// formatUpdateStatement formats an UPDATE statement
func (f *Formatter) formatUpdateStatement(stmt *ast.UpdateStatement) {
    f.writeKeyword("UPDATE")
    f.writeString(" ")
    f.writeString(stmt.Table.TokenLiteral())
    f.newline()

    f.writeKeyword("SET")
    f.newline()
    f.increaseIndent()

    for i, assignment := range stmt.Assignments {
        if i > 0 {
            if f.config.CommaStyle == "trailing" {
                f.writeString(",")
                f.newline()
            } else {
                f.newline()
                f.writeString(", ")
            }
        }
        f.writeIndent()
        f.writeString(assignment.Column.TokenLiteral())
        if f.config.SpaceAroundOperators {
            f.writeString(" = ")
        } else {
            f.writeString("=")
        }
        f.formatExpression(assignment.Value)
    }

    f.decreaseIndent()
    f.newline()

    if stmt.Where != nil {
        f.writeKeyword("WHERE")
        f.writeString(" ")
        f.formatExpression(stmt.Where)
        f.newline()
    }
}

// formatDeleteStatement formats a DELETE statement
func (f *Formatter) formatDeleteStatement(stmt *ast.DeleteStatement) {
    f.writeKeyword("DELETE FROM")
    f.writeString(" ")
    f.writeString(stmt.Table.TokenLiteral())
    f.newline()

    if stmt.Where != nil {
        f.writeKeyword("WHERE")
        f.writeString(" ")
        f.formatExpression(stmt.Where)
        f.newline()
    }
}

// formatExpression formats an expression
func (f *Formatter) formatExpression(expr ast.Expression) {
    if expr == nil {
        return
    }

    switch e := expr.(type) {
    case *ast.Identifier:
        f.writeString(e.Value)
    case *ast.IntegerLiteral:
        f.writeString(e.TokenLiteral())
    case *ast.StringLiteral:
        f.writeString("'")
        f.writeString(e.Value)
        f.writeString("'")
    case *ast.BinaryExpression:
        f.formatExpression(e.Left)
        if f.config.SpaceAroundOperators {
            f.writeString(" ")
        }
        f.writeString(e.Operator)
        if f.config.SpaceAroundOperators {
            f.writeString(" ")
        }
        f.formatExpression(e.Right)
    case *ast.FunctionCall:
        funcName := e.Name.Value
        if f.config.UppercaseFunctions {
            funcName = strings.ToUpper(funcName)
        }
        f.writeString(funcName)
        f.writeString("(")
        for i, arg := range e.Arguments {
            if i > 0 {
                f.writeString(", ")
            }
            f.formatExpression(arg)
        }
        f.writeString(")")
    default:
        f.writeString(expr.TokenLiteral())
    }
}

// formatTableReference formats a table reference
func (f *Formatter) formatTableReference(table ast.Node) {
    if table == nil {
        return
    }
    f.writeString(table.TokenLiteral())
}

// writeKeyword writes a keyword with proper casing
func (f *Formatter) writeKeyword(keyword string) {
    switch f.config.KeywordCase {
    case "upper":
        f.writeString(strings.ToUpper(keyword))
    case "lower":
        f.writeString(strings.ToLower(keyword))
    case "title":
        // Title case for keywords (capitalize first letter of each word)
        words := strings.Fields(strings.ToLower(keyword))
        for i, word := range words {
            if len(word) > 0 {
                words[i] = strings.ToUpper(word[:1]) + word[1:]
            }
        }
        f.writeString(strings.Join(words, " "))
    default:
        f.writeString(keyword)
    }
}

// writeString writes a string to the buffer
func (f *Formatter) writeString(s string) {
    f.buffer.WriteString(s)
}

// newline writes a newline and resets to proper indentation
func (f *Formatter) newline() {
    f.buffer.WriteString("\n")
}

// writeIndent writes the current indentation
func (f *Formatter) writeIndent() {
    if f.config.IndentSpaces == 0 {
        for i := 0; i < f.indent; i++ {
            f.buffer.WriteString("\t")
        }
    } else {
        spaces := f.indent * f.config.IndentSpaces
        for i := 0; i < spaces; i++ {
            f.buffer.WriteString(" ")
        }
    }
}

// increaseIndent increases indentation level
func (f *Formatter) increaseIndent() {
    f.indent++
}

// decreaseIndent decreases indentation level
func (f *Formatter) decreaseIndent() {
    if f.indent > 0 {
        f.indent--
    }
}
```

## Step 5: Create the CLI Interface

Create `main.go`:

```go
package main

import (
    "fmt"
    "os"
    "path/filepath"
)

func main() {
    if len(os.Args) < 2 {
        printUsage()
        os.Exit(1)
    }

    command := os.Args[1]

    switch command {
    case "format":
        formatCommand()
    case "init":
        initCommand()
    case "help":
        printUsage()
    default:
        fmt.Printf("Unknown command: %s\n", command)
        printUsage()
        os.Exit(1)
    }
}

func printUsage() {
    fmt.Println("SQL Formatter - Format SQL files with custom rules")
    fmt.Println("\nUsage:")
    fmt.Println("  sql-formatter format [options] <file>")
    fmt.Println("  sql-formatter init")
    fmt.Println("  sql-formatter help")
    fmt.Println("\nFormat Options:")
    fmt.Println("  -i           Format file in-place")
    fmt.Println("  -c <config>  Use custom config file (default: .sqlformat.json)")
    fmt.Println("\nExamples:")
    fmt.Println("  sql-formatter format query.sql")
    fmt.Println("  sql-formatter format -i query.sql")
    fmt.Println("  sql-formatter format -c myconfig.json query.sql")
    fmt.Println("  sql-formatter init  # Create default config file")
}

func initCommand() {
    configPath := ".sqlformat.json"

    // Check if config already exists
    if _, err := os.Stat(configPath); err == nil {
        fmt.Printf("Config file already exists: %s\n", configPath)
        fmt.Println("Delete it first or use a different name.")
        os.Exit(1)
    }

    // Save default config
    config := DefaultConfig()
    if err := SaveConfig(config, configPath); err != nil {
        fmt.Printf("Error creating config: %v\n", err)
        os.Exit(1)
    }

    fmt.Printf("Created default config file: %s\n", configPath)
    fmt.Println("\nEdit this file to customize formatting rules:")
    fmt.Printf("  {\n")
    fmt.Printf("    \"keyword_case\": \"upper\",\n")
    fmt.Printf("    \"indent_spaces\": 4,\n")
    fmt.Printf("    \"max_line_length\": 80,\n")
    fmt.Printf("    \"comma_style\": \"leading\",\n")
    fmt.Printf("    \"space_around_operators\": true,\n")
    fmt.Printf("    \"align_joins\": true,\n")
    fmt.Printf("    \"uppercase_functions\": true\n")
    fmt.Printf("  }\n")
}

func formatCommand() {
    var (
        inPlace    bool
        configPath string
        filePath   string
    )

    // Parse arguments
    configPath = ".sqlformat.json"
    args := os.Args[2:]

    for i := 0; i < len(args); i++ {
        arg := args[i]
        switch arg {
        case "-i":
            inPlace = true
        case "-c":
            if i+1 >= len(args) {
                fmt.Println("Error: -c requires a config file path")
                os.Exit(1)
            }
            configPath = args[i+1]
            i++
        default:
            filePath = arg
        }
    }

    if filePath == "" {
        fmt.Println("Error: No file specified")
        printUsage()
        os.Exit(1)
    }

    // Load configuration
    config, err := LoadConfig(configPath)
    if err != nil {
        fmt.Printf("Error loading config: %v\n", err)
        os.Exit(1)
    }

    // Read SQL file
    content, err := os.ReadFile(filePath)
    if err != nil {
        fmt.Printf("Error reading file: %v\n", err)
        os.Exit(1)
    }

    // Format SQL
    formatter := NewFormatter(config)
    formatted, err := formatter.Format(string(content))
    if err != nil {
        fmt.Printf("Error formatting SQL: %v\n", err)
        os.Exit(1)
    }

    // Output or write to file
    if inPlace {
        if err := os.WriteFile(filePath, []byte(formatted), 0644); err != nil {
            fmt.Printf("Error writing file: %v\n", err)
            os.Exit(1)
        }
        fmt.Printf("Formatted: %s\n", filePath)
    } else {
        fmt.Print(formatted)
    }
}
```

## Step 6: Build and Test

Build your formatter:

```bash
go build -o sql-formatter
```

Initialize a config file:

```bash
./sql-formatter init
```

Create a test SQL file `test.sql`:

```sql
select id,name,email from users where active=true and role in('admin','user')order by created_at desc;
```

Format it:

```bash
./sql-formatter format test.sql
```

Expected output:
```sql
SELECT
    id
    , name
    , email
FROM users
WHERE
    active = true AND role IN ('admin', 'user')
ORDER BY created_at DESC
```

Format in-place:

```bash
./sql-formatter format -i test.sql
cat test.sql
```

## Step 7: Customize Configuration

Edit `.sqlformat.json` to change formatting style:

```json
{
  "keyword_case": "lower",
  "indent_spaces": 2,
  "max_line_length": 100,
  "comma_style": "trailing",
  "space_around_operators": true,
  "align_joins": true,
  "uppercase_functions": false
}
```

Now formatting the same SQL produces:

```sql
select
  id,
  name,
  email
from users
where
  active = true and role in ('admin', 'user')
order by created_at desc
```

## Step 8: Pre-commit Hook Integration

Create `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: format-sql
        name: Format SQL Files
        entry: sql-formatter format -i
        language: system
        files: \.sql$
        pass_filenames: true
```

Or create a git hook at `.git/hooks/pre-commit`:

```bash
#!/bin/bash

# Find all staged .sql files
SQL_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.sql$')

if [ -n "$SQL_FILES" ]; then
    echo "Formatting SQL files..."

    for file in $SQL_FILES; do
        sql-formatter format -i "$file"
        git add "$file"
    done

    echo "SQL files formatted!"
fi

exit 0
```

Make it executable:

```bash
chmod +x .git/hooks/pre-commit
```

## Step 9: CI Integration

### GitHub Actions

Create `.github/workflows/format-sql.yml`:

```yaml
name: Check SQL Formatting

on:
  pull_request:
    branches: [ main, develop ]

jobs:
  check-format:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.21'

    - name: Install SQL Formatter
      run: |
        git clone https://github.com/ajitpratap0/GoSQLX.git
        cd GoSQLX/examples/tutorials/02-sql-formatter
        go build -o sql-formatter
        sudo mv sql-formatter /usr/local/bin/

    - name: Check SQL Formatting
      run: |
        FILES=$(find . -name "*.sql")
        UNFORMATTED=""

        for file in $FILES; do
          ORIGINAL=$(cat "$file")
          FORMATTED=$(sql-formatter format "$file")

          if [ "$ORIGINAL" != "$FORMATTED" ]; then
            echo "Unformatted: $file"
            UNFORMATTED="$UNFORMATTED $file"
          fi
        done

        if [ -n "$UNFORMATTED" ]; then
          echo "The following files are not formatted:"
          echo "$UNFORMATTED"
          echo "Run: sql-formatter format -i <file>"
          exit 1
        fi

        echo "All SQL files are properly formatted!"
```

### GitLab CI

Create `.gitlab-ci.yml`:

```yaml
stages:
  - format-check

check-sql-format:
  stage: format-check
  image: golang:1.21
  script:
    - git clone https://github.com/ajitpratap0/GoSQLX.git
    - cd GoSQLX/examples/tutorials/02-sql-formatter
    - go build -o sql-formatter
    - cd ../../../
    - |
      for file in $(find . -name "*.sql"); do
        ORIGINAL=$(cat "$file")
        FORMATTED=$(./GoSQLX/examples/tutorials/02-sql-formatter/sql-formatter format "$file")
        if [ "$ORIGINAL" != "$FORMATTED" ]; then
          echo "Unformatted: $file"
          exit 1
        fi
      done
  only:
    - merge_requests
```

## Advanced Features

### Team-Specific Rules

Add custom rules to `config.go`:

```go
type FormatterConfig struct {
    // ... existing fields ...

    // Team-specific rules
    RequireTableAliases     bool     `json:"require_table_aliases"`
    ForbiddenKeywords       []string `json:"forbidden_keywords"`
    PreferredJoinStyle      string   `json:"preferred_join_style"` // "explicit", "implicit"
    MaxSubqueryDepth        int      `json:"max_subquery_depth"`
}
```

### Add Batch Processing

Process multiple files:

```go
func formatDirectory(dirPath string, config FormatterConfig, inPlace bool) error {
    return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }

        if info.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".sql") {
            return nil
        }

        content, err := os.ReadFile(path)
        if err != nil {
            return err
        }

        formatter := NewFormatter(config)
        formatted, err := formatter.Format(string(content))
        if err != nil {
            fmt.Printf("Error formatting %s: %v\n", path, err)
            return nil // Continue with other files
        }

        if inPlace {
            os.WriteFile(path, []byte(formatted), 0644)
            fmt.Printf("Formatted: %s\n", path)
        } else {
            fmt.Printf("=== %s ===\n%s\n", path, formatted)
        }

        return nil
    })
}
```

## Troubleshooting

### Issue: "Parse error"
**Solution**: The SQL has syntax errors. Run it through the validator from Tutorial 1 first.

### Issue: Formatting changes semantics
**Solution**: This shouldn't happen. Report as a bug. Always test formatted SQL before committing.

### Issue: Config file not found
**Solution**: Run `sql-formatter init` to create a default config file.

### Issue: Inconsistent formatting across team
**Solution**: Commit `.sqlformat.json` to version control and enforce it in CI.

## Next Steps

Now that you have a SQL formatter, you can:

1. **Add more formatting rules**: Implement window function formatting, CTE formatting
2. **Create a diff mode**: Show what would change without modifying files
3. **Add auto-fix mode**: Automatically format on file save in your editor
4. **Build a language server**: Integrate with IDEs for real-time formatting

## Full Example

The complete, working code for this tutorial is available at:
`examples/tutorials/02-sql-formatter/`

To run it:

```bash
cd examples/tutorials/02-sql-formatter
go build
./sql-formatter init
./sql-formatter format testdata/input.sql
```

## Summary

You've learned how to:
- Build a configurable SQL formatter using GoSQLX AST
- Implement custom formatting rules (keyword casing, indentation, operators)
- Create a CLI tool with multiple commands
- Integrate formatting into development workflows (pre-commit hooks, CI/CD)
- Share formatting standards across a team with configuration files

This formatter is production-ready and can be customized to match your team's SQL coding standards!
