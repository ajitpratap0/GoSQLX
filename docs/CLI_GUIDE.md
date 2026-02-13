# GoSQLX CLI Guide

**Version**: v1.6.0
**Last Updated**: December 2025

The GoSQLX Command Line Interface (CLI) provides high-performance SQL parsing, validation, formatting, and analysis capabilities directly from your terminal.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands Reference](#commands-reference)
  - [validate](#gosqlx-validate---ultra-fast-sql-validation)
  - [format](#gosqlx-format---high-performance-sql-formatting)
  - [parse](#gosqlx-parse---ast-structure-inspection)
  - [analyze](#gosqlx-analyze---sql-analysis)
  - [lint](#gosqlx-lint---style-and-quality-checking)
  - [lsp](#gosqlx-lsp---language-server-protocol)
  - [config](#gosqlx-config---configuration-management)
  - [completion](#gosqlx-completion---shell-autocompletion)
- [Global Flags](#global-flags)
- [Configuration](#configuration)
- [Input Methods](#input-methods)
- [Output Formats](#output-formats)
- [Security & Validation](#security--validation)
- [CI/CD Integration](#cicd-integration)
- [Performance](#performance)
- [Examples & Use Cases](#examples--use-cases)
- [Troubleshooting](#troubleshooting)

---

## Installation

### Build from Source

```bash
git clone https://github.com/ajitpratap0/GoSQLX.git
cd GoSQLX
task build:cli  # or: go build -o gosqlx ./cmd/gosqlx
```

### Install via Go

```bash
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
```

### Install Globally (from project)

```bash
task install
```

### Verify Installation

```bash
gosqlx --version
gosqlx --help
```

---

## Quick Start

```bash
# Validate a SQL query
gosqlx validate "SELECT * FROM users WHERE active = true"

# Format a SQL file
gosqlx format query.sql

# Analyze SQL structure and security
gosqlx analyze "SELECT COUNT(*) FROM orders GROUP BY status"

# Lint SQL files for style issues
gosqlx lint query.sql

# Start LSP server for IDE integration
gosqlx lsp

# Generate configuration file
gosqlx config init
```

---

## Commands Reference

### `gosqlx validate` - Ultra-Fast SQL Validation

Validate SQL syntax with <10ms typical latency and 100+ files/second throughput.

#### Syntax

```bash
gosqlx validate [file...] [flags]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--dialect` | string | postgresql | SQL dialect (postgresql, mysql, sqlserver, oracle, sqlite) |
| `-r, --recursive` | bool | false | Recursively process directories |
| `-p, --pattern` | string | `*.sql` | File pattern for recursive processing |
| `-q, --quiet` | bool | false | Quiet mode (exit code only) |
| `-s, --stats` | bool | false | Show performance statistics |
| `--strict` | bool | false | Enable strict validation mode |
| `--output-format` | string | text | Output format (text, json, sarif) |
| `--output-file` | string | stdout | Output file path |

#### Examples

```bash
# Validate single file
gosqlx validate query.sql

# Validate direct SQL string
gosqlx validate "SELECT * FROM users WHERE id = 1"

# Validate multiple files
gosqlx validate query1.sql query2.sql query3.sql

# Validate with glob pattern (must quote)
gosqlx validate "*.sql"
gosqlx validate "queries/**/*.sql"

# Recursively validate directory
gosqlx validate -r ./queries/

# Validate with custom dialect
gosqlx validate --dialect mysql query.sql

# Quiet mode (exit code only - useful for scripts)
gosqlx validate --quiet query.sql
if [ $? -eq 0 ]; then echo "Valid!"; fi

# Show performance statistics
gosqlx validate --stats ./queries/

# Strict validation mode
gosqlx validate --strict query.sql

# SARIF output for GitHub Code Scanning
gosqlx validate --output-format sarif --output-file results.sarif queries/

# JSON output for programmatic consumption
gosqlx validate --output-format json query.sql > results.json
```

#### Pipeline/Stdin Examples

```bash
# Validate from stdin (auto-detect)
echo "SELECT * FROM users" | gosqlx validate

# Pipe file contents
cat query.sql | gosqlx validate

# Explicit stdin marker
gosqlx validate -

# Input redirection
gosqlx validate < query.sql

# Chain with other tools
cat query.sql | gosqlx validate && echo "Valid SQL"
```

#### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Valid SQL - no syntax errors |
| 1 | Invalid SQL - syntax errors detected |

#### Performance Target

- **Latency**: <10ms for typical queries (50-500 characters)
- **Throughput**: 100+ files/second in batch mode

---

### `gosqlx format` - High-Performance SQL Formatting

Format SQL queries with intelligent indentation and style - 100x faster than SQLFluff.

#### Syntax

```bash
gosqlx format [file...] [flags]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-i, --in-place` | bool | false | Edit files in place (not supported with stdin) |
| `--indent` | int | 2 | Indentation size in spaces (0-8) |
| `--uppercase` | bool | true | Uppercase SQL keywords |
| `--no-uppercase` | bool | false | Keep original keyword case |
| `--compact` | bool | false | Compact format (minimal whitespace) |
| `--check` | bool | false | Check if formatting is needed (CI mode) |
| `--max-line` | int | 80 | Maximum line length (0-500) |

#### Examples

```bash
# Format to stdout
gosqlx format query.sql

# Format in-place (overwrites file)
gosqlx format -i query.sql

# Format multiple files in-place
gosqlx format -i query1.sql query2.sql

# Custom indentation (4 spaces)
gosqlx format --indent 4 query.sql

# Keep original keyword case
gosqlx format --no-uppercase query.sql

# Compact format (minimal whitespace)
gosqlx format --compact query.sql

# Check if formatting is needed (CI mode)
gosqlx format --check query.sql
# Exit code 0: already formatted
# Exit code 1: needs formatting

# Format all SQL files with glob
gosqlx format "*.sql"
gosqlx format "queries/**/*.sql"

# Save to specific file
gosqlx format -o formatted.sql query.sql

# Format with custom line length
gosqlx format --max-line 120 query.sql

# Format with lowercase keywords
gosqlx format --no-uppercase query.sql
```

#### Pipeline/Stdin Examples

```bash
# Format from stdin (auto-detect)
echo "SELECT * FROM users" | gosqlx format

# Pipe file contents
cat query.sql | gosqlx format

# Explicit stdin marker
gosqlx format -

# Input redirection
gosqlx format < query.sql

# Full pipeline with output redirection
cat query.sql | gosqlx format > formatted.sql

# Chain multiple commands
cat query.sql | gosqlx format | gosqlx validate
```

#### Exit Codes (--check mode)

| Code | Meaning |
|------|---------|
| 0 | File is already formatted correctly |
| 1 | File needs formatting |

#### Performance

- **100x faster** than SQLFluff for equivalent operations
- Handles complex queries with CTEs, window functions, JOINs

---

### `gosqlx parse` - AST Structure Inspection

Parse SQL into Abstract Syntax Tree (AST) representation for analysis.

#### Syntax

```bash
gosqlx parse [file|query] [flags]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--ast` | bool | false | Show detailed AST structure |
| `--tokens` | bool | false | Show tokenization output |
| `--tree` | bool | false | Show tree visualization |

#### Examples

```bash
# Parse file and display AST
gosqlx parse query.sql

# Parse direct SQL string
gosqlx parse "SELECT * FROM users WHERE age > 18"

# Show detailed AST structure
gosqlx parse --ast query.sql

# Show tokenization output
gosqlx parse --tokens query.sql

# Show tree visualization
gosqlx parse --tree query.sql

# Parse to JSON format
gosqlx parse -f json query.sql > ast.json

# Parse to YAML format
gosqlx parse -f yaml query.sql

# Parse to table format
gosqlx parse -f table query.sql

# Combine with other tools
gosqlx parse -f json query.sql | jq '.Statements[0]'
```

#### Pipeline/Stdin Examples

```bash
# Parse from stdin
echo "SELECT * FROM users" | gosqlx parse

# Pipe file contents
cat query.sql | gosqlx parse

# Explicit stdin marker
gosqlx parse -

# Input redirection
gosqlx parse < query.sql
```

#### Output Formats

- **json**: JSON output for programmatic consumption
- **yaml**: YAML output for human-readable structure
- **table**: Table format for quick inspection
- **tree**: Tree visualization for visual AST inspection

---

### `gosqlx analyze` - SQL Analysis

Analyze SQL queries for security vulnerabilities, performance issues, and complexity metrics.

#### Syntax

```bash
gosqlx analyze [file|query] [flags]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--security` | bool | false | Focus on security vulnerability analysis |
| `--performance` | bool | false | Focus on performance optimization analysis |
| `--complexity` | bool | false | Focus on complexity metrics |
| `--all` | bool | false | Comprehensive analysis (all features) |

#### Examples

```bash
# Basic analysis
gosqlx analyze query.sql

# Analyze direct SQL string
gosqlx analyze "SELECT u.name, COUNT(o.id) FROM users u JOIN orders o ON u.id = o.user_id GROUP BY u.name"

# Security vulnerability scan
gosqlx analyze --security query.sql

# Performance optimization hints
gosqlx analyze --performance query.sql

# Complexity scoring
gosqlx analyze --complexity query.sql

# Comprehensive analysis (all features)
gosqlx analyze --all query.sql

# Analyze with JSON output
gosqlx analyze -f json query.sql > analysis.json

# Analyze multiple files
gosqlx analyze --all query1.sql query2.sql
```

#### Pipeline/Stdin Examples

```bash
# Analyze from stdin
echo "SELECT * FROM users" | gosqlx analyze

# Pipe file contents
cat query.sql | gosqlx analyze

# Explicit stdin marker
gosqlx analyze -

# Input redirection
gosqlx analyze < query.sql
```

#### Analysis Capabilities

- **SQL Injection Detection**: Pattern scanning for common injection techniques
  - Tautology patterns (`'1'='1'`, `OR 1=1`)
  - UNION-based injection
  - Time-based blind injection (SLEEP, WAITFOR DELAY)
  - Comment bypass (`--`, `/**/`)
  - Stacked queries
  - Dangerous functions (xp_cmdshell, LOAD_FILE)

- **Performance Optimization**: Suggestions for query improvements
  - Missing indexes detection
  - Full table scan warnings
  - JOIN optimization opportunities
  - SELECT * recommendations

- **Complexity Metrics**: Query complexity scoring
  - Statement count
  - JOIN depth
  - Subquery nesting
  - Expression complexity

- **Best Practices**: Validation against SQL best practices
  - Multi-dialect compatibility checks
  - Code style recommendations

---

### `gosqlx lint` - Style and Quality Checking

Check SQL files for style issues and best practices with 10 built-in rules (L001-L010).

#### Syntax

```bash
gosqlx lint [file...] [flags]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-r, --recursive` | bool | false | Recursively process directories |
| `-p, --pattern` | string | `*.sql` | File pattern for recursive processing |
| `--auto-fix` | bool | false | Automatically fix violations where possible |
| `--max-length` | int | 100 | Maximum line length for L005 rule |
| `--fail-on-warn` | bool | false | Exit with error code on warnings |

#### Available Lint Rules

| Rule | Name | Auto-Fix | Description |
|------|------|----------|-------------|
| L001 | Trailing Whitespace | Yes | Detects trailing whitespace at end of lines |
| L002 | Mixed Indentation | Yes | Detects mixed tabs and spaces |
| L003 | Consecutive Blank Lines | Yes | Detects multiple blank lines |
| L004 | Indentation Depth | No | Warns on excessive nesting (>4 levels) |
| L005 | Line Length | No | Warns on long lines |
| L006 | Column Alignment | No | Checks SELECT column alignment |
| L007 | Keyword Case | Yes | Enforces uppercase/lowercase keywords |
| L008 | Comma Placement | No | Trailing vs leading comma style |
| L009 | Aliasing Consistency | No | Detects mixed table aliasing |
| L010 | Redundant Whitespace | Yes | Finds multiple consecutive spaces |

See [LINTING_RULES.md](LINTING_RULES.md) for complete rule documentation.

#### Examples

```bash
# Lint single file
gosqlx lint query.sql

# Lint multiple files
gosqlx lint query1.sql query2.sql

# Lint with glob pattern
gosqlx lint "*.sql"

# Lint directory recursively
gosqlx lint -r ./queries/

# Auto-fix violations where possible
gosqlx lint --auto-fix query.sql

# Auto-fix directory
gosqlx lint --auto-fix -r ./queries/

# Set maximum line length (L005 rule)
gosqlx lint --max-length 120 query.sql

# Fail on warnings (useful for CI)
gosqlx lint --fail-on-warn query.sql

# Lint with custom pattern
gosqlx lint -r --pattern "**/*.sql" ./src/
```

#### Pipeline/Stdin Examples

```bash
# Lint from stdin
echo "SELECT * FROM users" | gosqlx lint

# Pipe file contents
cat query.sql | gosqlx lint

# Explicit stdin marker
gosqlx lint -
```

#### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No violations found (or info only) |
| 1 | Errors or warnings found (warnings only if --fail-on-warn is set) |

---

### `gosqlx lsp` - Language Server Protocol

Start the LSP server for IDE integration with real-time diagnostics, formatting, and autocomplete.

#### Syntax

```bash
gosqlx lsp [flags]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--log` | string | - | Log file path (optional, for debugging) |

#### Features

- **Real-time Diagnostics**: Syntax error detection as you type
- **Formatting**: SQL code formatting with customizable options
- **Hover Documentation**: Keyword and function documentation (60+ keywords)
- **Code Completion**: SQL autocomplete (100+ keywords, 22 snippets)
- **Document Symbols**: SQL statement outline navigation
- **Signature Help**: Function signatures (20+ SQL functions)
- **Code Actions**: Quick fixes (add semicolon, uppercase keywords)

#### Examples

```bash
# Start LSP server on stdio
gosqlx lsp

# Start with logging enabled (for debugging)
gosqlx lsp --log /tmp/gosqlx-lsp.log

# Start with verbose logging
gosqlx lsp --log /var/log/gosqlx-lsp.log -v
```

#### IDE Integration

##### VSCode

Install the official GoSQLX VSCode extension or configure manually:

```json
// settings.json
{
  "gosqlx.enable": true,
  "gosqlx.executablePath": "gosqlx",
  "gosqlx.format.indentSize": 2,
  "gosqlx.format.uppercaseKeywords": true,
  "gosqlx.dialect": "postgresql"
}
```

##### Neovim (nvim-lspconfig)

```lua
require('lspconfig.configs').gosqlx = {
  default_config = {
    cmd = { 'gosqlx', 'lsp' },
    filetypes = { 'sql' },
    root_dir = function() return vim.fn.getcwd() end,
  },
}
require('lspconfig').gosqlx.setup{}
```

##### Emacs (lsp-mode)

```elisp
(lsp-register-client
  (make-lsp-client
    :new-connection (lsp-stdio-connection '("gosqlx" "lsp"))
    :major-modes '(sql-mode)
    :server-id 'gosqlx))
```

See [LSP_GUIDE.md](LSP_GUIDE.md) for complete LSP documentation.

---

### `gosqlx config` - Configuration Management

Manage GoSQLX configuration files for persistent settings.

#### Syntax

```bash
gosqlx config [command] [flags]
```

#### Subcommands

| Command | Description |
|---------|-------------|
| `init` | Create a default configuration file |
| `validate` | Validate configuration file |
| `show` | Show current configuration |

#### Configuration File Locations

Configuration files are searched in this order (highest priority first):

1. **Current directory**: `.gosqlx.yml`
2. **Home directory**: `~/.gosqlx.yml`
3. **System-wide**: `/etc/gosqlx.yml`

CLI flags always override configuration file settings.

#### Examples

```bash
# Create .gosqlx.yml in current directory
gosqlx config init

# Create in specific location
gosqlx config init --path ~/.gosqlx.yml

# Validate configuration file
gosqlx config validate

# Validate specific file
gosqlx config validate --file /path/to/config.yml

# Show current configuration (YAML)
gosqlx config show

# Show as JSON
gosqlx config show --format json
```

#### Configuration Schema

```yaml
# Format settings - controls SQL formatting behavior
format:
  indent: 2                    # Indentation size (0-8 spaces)
  uppercase_keywords: true     # Convert keywords to uppercase
  max_line_length: 80          # Maximum line length (0-500, 0=unlimited)
  compact: false               # Minimal whitespace format

# Validation settings - controls SQL validation behavior
validate:
  dialect: postgresql          # SQL dialect (postgresql, mysql, sqlserver, oracle, sqlite, generic)
  strict_mode: false           # Enable strict validation
  recursive: false             # Recursively process directories
  pattern: "*.sql"             # File pattern for recursive processing

# Output settings - controls result display
output:
  format: auto                 # Output format (json, yaml, table, tree, auto)
  verbose: false               # Enable verbose output

# Analyze settings - controls analysis features
analyze:
  security: true               # Enable security analysis
  performance: true            # Enable performance analysis
  complexity: true             # Enable complexity analysis
  all: false                   # Enable all analysis features

# Linter settings - controls linting behavior
linter:
  rules:
    L001: enabled              # Trailing whitespace
    L002: enabled              # Mixed indentation
    L003: enabled              # Consecutive blank lines
    L004: enabled              # Indentation depth
    L005: enabled              # Line length
    L006: enabled              # Column alignment
    L007: enabled              # Keyword case
    L008: enabled              # Comma placement
    L009: enabled              # Aliasing consistency
    L010: enabled              # Redundant whitespace
```

See [CONFIGURATION.md](CONFIGURATION.md) for complete configuration guide.

---

### `gosqlx completion` - Shell Autocompletion

Generate autocompletion script for your shell.

#### Syntax

```bash
gosqlx completion [shell] [flags]
```

#### Supported Shells

- bash
- zsh
- fish
- powershell

#### Examples

```bash
# Bash
gosqlx completion bash > /etc/bash_completion.d/gosqlx

# Zsh
gosqlx completion zsh > "${fpath[1]}/_gosqlx"

# Fish
gosqlx completion fish > ~/.config/fish/completions/gosqlx.fish

# PowerShell
gosqlx completion powershell > gosqlx.ps1
```

---

## Global Flags

Available for all commands:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-v, --verbose` | bool | false | Enable verbose output |
| `-o, --output FILE` | string | stdout | Output to file instead of stdout |
| `-f, --format FORMAT` | string | auto | Output format (auto, json, yaml, table, tree) |
| `-h, --help` | bool | false | Help for any command |
| `--version` | bool | false | Show version information |

---

## Configuration

### Configuration File Locations

GoSQLX searches for configuration files in this order:

1. CLI flags (highest priority)
2. Current directory: `.gosqlx.yml`
3. Home directory: `~/.gosqlx.yml`
4. System-wide: `/etc/gosqlx.yml`
5. Built-in defaults (lowest priority)

### Configuration Precedence

Settings are merged in priority order:
1. CLI flags
2. Current directory `.gosqlx.yml`
3. Home directory `~/.gosqlx.yml`
4. System-wide `/etc/gosqlx.yml`
5. Built-in defaults

### Example Configuration

**Team configuration** (`.gosqlx.yml`):

```yaml
format:
  indent: 2
  uppercase_keywords: true
  max_line_length: 100

validate:
  dialect: postgresql
  strict_mode: true

analyze:
  security: true
  performance: true

linter:
  rules:
    L001: enabled
    L002: enabled
    L005: enabled
    L007: enabled
```

---

## Input Methods

GoSQLX supports multiple input methods for all commands.

### File Input

```bash
# Single file
gosqlx validate query.sql

# Multiple files
gosqlx validate query1.sql query2.sql query3.sql

# Glob patterns (must quote)
gosqlx validate "*.sql"
gosqlx validate "queries/**/*.sql"

# Directory (with -r flag)
gosqlx validate -r ./queries/
```

### Direct SQL String

```bash
# Auto-detected as SQL string (not file path)
gosqlx validate "SELECT * FROM users"
gosqlx format "SELECT * FROM users WHERE id = 1"
gosqlx analyze "SELECT COUNT(*) FROM orders"
```

### Stdin/Pipeline

```bash
# Pipe from echo
echo "SELECT * FROM users" | gosqlx validate

# Pipe from cat
cat query.sql | gosqlx format

# Explicit stdin marker
gosqlx validate -

# Input redirection
gosqlx validate < query.sql

# Output redirection
cat query.sql | gosqlx format > formatted.sql

# Chained commands
cat query.sql | gosqlx format | gosqlx validate
```

### Supported File Extensions

- `.sql` - SQL files (primary)
- `.txt` - Text files containing SQL
- Files without extension (also supported)

---

## Output Formats

### Text (Default)

Human-readable output with colors and formatting.

```bash
gosqlx validate query.sql
# ✓ query.sql is valid
```

### JSON

Structured JSON for programmatic consumption.

```bash
gosqlx validate -f json query.sql
# {"file": "query.sql", "valid": true, "errors": []}

gosqlx analyze -f json query.sql > analysis.json
```

### YAML

Human-readable structured output.

```bash
gosqlx parse -f yaml query.sql
# Statements:
#   - Type: SELECT
#     Columns: [...]
```

### Table

Tabular output for quick inspection.

```bash
gosqlx parse -f table query.sql
# +------+----------+--------+
# | Type | Line     | Column |
# +------+----------+--------+
# | ...  | ...      | ...    |
# +------+----------+--------+
```

### Tree

Tree visualization for AST structure.

```bash
gosqlx parse -f tree query.sql
# SELECT
#   ├── Columns
#   │   └── *
#   └── FROM
#       └── users
```

### SARIF

SARIF 2.1.0 format for GitHub Code Scanning integration.

```bash
gosqlx validate --output-format sarif --output-file results.sarif queries/
```

---

## Security & Validation

GoSQLX CLI implements comprehensive security validation to protect against malicious input.

### File Size Limits

- **Maximum file size**: 10MB (10,485,760 bytes)
- **Maximum direct SQL query length**: 10MB
- Prevents DoS attacks via oversized files

```bash
# Rejected - file too large
$ gosqlx validate huge.sql
Error: file too large: 11534336 bytes (max 10485760 bytes)
```

### Path Traversal Protection

Blocks attempts to access files outside intended directories.

```bash
# Rejected - path traversal detected
$ gosqlx validate "../../etc/passwd"
Error: security validation failed: path traversal detected
```

### Symlink Protection

Symlinks are blocked by default for security.

```bash
# Rejected - symlink detected
$ gosqlx validate symlink.sql
Error: symlink detected (symlinks are blocked for security)
```

### File Type Restrictions

**Allowed**: `.sql`, `.txt`, files without extension
**Blocked**: `.exe`, `.bat`, `.sh`, `.py`, `.js`, `.dll`, `.so`, `.jar`, and all other executable/binary formats

```bash
# Rejected - executable file
$ gosqlx validate malware.exe
Error: unsupported file extension: .exe (allowed: [.sql .txt ])
```

### Special File Protection

- Blocks device files (`/dev/null`, `/dev/random`, etc.)
- Rejects directories, pipes, and sockets
- Only regular files are accepted

```bash
# Rejected - device file
$ gosqlx validate /dev/null
Error: not a regular file: /dev/null
```

For more details, see the [Security Validation Package](../cmd/gosqlx/internal/validate/README.md).

---

## CI/CD Integration

GoSQLX is designed for seamless CI/CD integration with proper exit codes and output formats.

### GitHub Actions

```yaml
name: SQL Validation
on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.24'
      - name: Install GoSQLX
        run: go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
      - name: Validate SQL
        run: gosqlx validate -r --strict queries/
      - name: Lint SQL
        run: gosqlx lint --fail-on-warn -r queries/
      - name: Format check
        run: gosqlx format --check -r queries/
```

### GitHub Code Scanning

```yaml
- name: SQL Security Scan
  run: gosqlx validate --output-format sarif --output-file results.sarif queries/
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### GitLab CI

```yaml
sql-validation:
  stage: test
  script:
    - go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
    - gosqlx validate -r --strict queries/
    - gosqlx lint --fail-on-warn -r queries/
    - gosqlx format --check -r queries/
```

### Pre-commit Hook

```bash
#!/usr/bin/env bash
# .git/hooks/pre-commit

# Format check
gosqlx format --check *.sql
if [ $? -ne 0 ]; then
    echo "SQL files need formatting. Run: gosqlx format -i *.sql"
    exit 1
fi

# Lint check
gosqlx lint --fail-on-warn *.sql
if [ $? -ne 0 ]; then
    echo "SQL linting failed. Fix violations and try again."
    exit 1
fi

# Validation
gosqlx validate *.sql
if [ $? -ne 0 ]; then
    echo "SQL validation failed."
    exit 1
fi
```

### Task/Makefile Integration

**Taskfile.yml** (using [go-task](https://taskfile.dev)):

```yaml
version: '3'

tasks:
  sql:validate:
    desc: Validate SQL files
    cmds:
      - gosqlx validate -r queries/

  sql:format:
    desc: Format SQL files in place
    cmds:
      - gosqlx format -i -r queries/

  sql:format:check:
    desc: Check SQL formatting
    cmds:
      - gosqlx format --check -r queries/

  sql:lint:
    desc: Lint SQL files
    cmds:
      - gosqlx lint -r queries/

  sql:analyze:
    desc: Analyze SQL security
    cmds:
      - gosqlx analyze --all -r queries/

  sql:check:
    desc: Full SQL check suite
    cmds:
      - task: sql:format:check
      - task: sql:lint
      - task: sql:validate
```

Run with: `task sql:validate`, `task sql:format`, or `task sql:check`

---

## Performance

GoSQLX CLI delivers exceptional performance for all operations.

### Benchmark Results

| Operation | Throughput | Latency | Performance vs Competitors |
|-----------|------------|---------|----------------------------|
| **Validation** | 100+ files/sec | <10ms per query | 100-1000x faster |
| **Formatting** | - | <5ms per file | 100x faster than SQLFluff |
| **Analysis** | 1.38M+ ops/sec | <1μs per query | Production-ready |
| **Parsing** | 1.5M+ ops/sec | <1μs per query | Direct AST inspection |
| **Linting** | 50+ files/sec | <20ms per file | High-performance |

### Core Library Performance

- **1.38M+ operations/second** sustained throughput
- **1.5M peak** with memory-efficient object pooling
- **60-80% memory reduction** through object pooling
- **Zero-copy tokenization** for maximum efficiency
- **Concurrent processing** support with linear scaling
- **Race-free implementation** validated through comprehensive testing

### Performance Tips

1. **Use batch processing** for multiple files with glob patterns
2. **Enable verbose output only when needed** (`-v` adds overhead)
3. **Use JSON format for scripts** (faster than table/tree formats)
4. **Leverage SARIF format** for GitHub Code Scanning integration
5. **Use --quiet mode** for scripts (minimal output overhead)

---

## Examples & Use Cases

### Validate and Format Workflow

```bash
# Validate all SQL files
gosqlx validate -r queries/

# Format with consistent style
gosqlx format -i --indent 2 --uppercase -r queries/

# CI format check
gosqlx format --check -r queries/ || exit 1
```

### Security Analysis

```bash
# Scan for SQL injection vulnerabilities
gosqlx analyze --security query.sql

# Comprehensive analysis
gosqlx analyze --all query.sql

# Batch security scan with JSON output
gosqlx analyze --security -f json -r queries/ > security-report.json
```

### Linting for Code Quality

```bash
# Lint with strict rules
gosqlx lint --fail-on-warn -r queries/

# Auto-fix where possible
gosqlx lint --auto-fix -r queries/

# Custom line length
gosqlx lint --max-length 120 -r queries/
```

### AST Inspection

```bash
# Parse to JSON for analysis
gosqlx parse -f json complex_query.sql > ast.json

# Visualize tree structure
gosqlx parse -f tree complex_query.sql

# Extract tokens
gosqlx parse --tokens query.sql
```

### Multi-Dialect Support

```bash
# PostgreSQL validation
gosqlx validate --dialect postgresql pg_query.sql

# MySQL validation
gosqlx validate --dialect mysql mysql_query.sql

# SQL Server validation
gosqlx validate --dialect sqlserver tsql_query.sql
```

### Pipeline Processing

```bash
# Format then validate
cat query.sql | gosqlx format | gosqlx validate

# Validate multiple files via pipeline
find queries/ -name "*.sql" | xargs gosqlx validate

# Format and save
for file in queries/*.sql; do
  gosqlx format "$file" > "formatted/$file"
done
```

---

## Troubleshooting

### Common Issues

#### File not found

```bash
$ gosqlx validate missing.sql
Error: cannot access file missing.sql: no such file or directory
```

**Solution**: Verify file path is correct and file exists.

#### Invalid SQL

```bash
$ gosqlx validate "SELECT * WHERE"
Error at line 1, column 11: expected FROM clause
  SELECT * WHERE
           ^^^^^
```

**Solution**: Fix SQL syntax based on error message.

#### Large file rejected

```bash
$ gosqlx validate huge.sql
Error: file too large: 15728640 bytes (max 10485760 bytes)
```

**Solution**: File exceeds 10MB limit. Consider splitting or increasing limit (not recommended).

#### Format check failed in CI

```bash
$ gosqlx format --check query.sql
File needs formatting: query.sql
```

**Solution**: Run `gosqlx format -i query.sql` to fix formatting.

#### Glob pattern not working

```bash
$ gosqlx validate *.sql
Error: no such file or directory: *.sql
```

**Solution**: Quote glob patterns: `gosqlx validate "*.sql"`

#### Configuration not loading

```bash
# Show which config is being used
gosqlx config show

# Validate config file
gosqlx config validate --file .gosqlx.yml
```

**Solution**: Ensure `.gosqlx.yml` is in current directory, home directory, or `/etc/`.

### Error Handling

GoSQLX provides detailed error messages with context:

```bash
$ gosqlx validate "SELECT * FORM users"
Error at line 1, column 10: expected FROM, got IDENT 'FORM'
  SELECT * FORM users
           ^^^^
Hint: Did you mean 'FROM'?
```

### Debug Mode

Enable verbose output for detailed information:

```bash
gosqlx -v validate query.sql
gosqlx --verbose format query.sql
gosqlx lsp --log /tmp/lsp.log  # LSP debug logging
```

### Getting Help

```bash
# General help
gosqlx --help

# Command-specific help
gosqlx validate --help
gosqlx format --help
gosqlx lint --help

# Show version
gosqlx --version
```

---

## SQL Dialect Support

GoSQLX supports multiple SQL dialects with dialect-specific features:

### Supported Dialects

| Dialect | Identifier | Special Features |
|---------|-----------|------------------|
| PostgreSQL | `postgresql` | JSONB, arrays, LATERAL JOIN, DISTINCT ON, FILTER clause |
| MySQL | `mysql` | Backtick identifiers, MySQL-specific functions |
| SQL Server | `sqlserver` | Bracket identifiers, T-SQL syntax |
| Oracle | `oracle` | Oracle-specific syntax and functions |
| SQLite | `sqlite` | SQLite-specific features |
| Generic | `generic` | Standard SQL only |

### Advanced SQL Features Supported

- **Window Functions**: ROW_NUMBER, RANK, DENSE_RANK, LAG, LEAD, FIRST_VALUE, LAST_VALUE, NTILE
- **CTEs**: WITH clause, recursive CTEs
- **Set Operations**: UNION, UNION ALL, EXCEPT, INTERSECT
- **JOINs**: LEFT, RIGHT, INNER, FULL OUTER, CROSS, NATURAL, LATERAL
- **Advanced Expressions**: BETWEEN, IN, LIKE, IS NULL, CASE WHEN
- **Modern SQL**: Materialized views, MERGE statements, GROUPING SETS, ROLLUP, CUBE
- **PostgreSQL Extensions**: JSON/JSONB operators, DISTINCT ON, FILTER clause, RETURNING clause

---

## Contributing

To contribute to the GoSQLX CLI:

1. Fork the repository
2. Create a feature branch
3. Add tests for new CLI features
4. Submit a pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for detailed guidelines.

---

## Related Documentation

- [LSP Guide](LSP_GUIDE.md) - Complete LSP server documentation and IDE integration
- [Linting Rules](LINTING_RULES.md) - All 10 linting rules (L001-L010) reference
- [Configuration Guide](CONFIGURATION.md) - Configuration file (.gosqlx.yml) guide
- [Getting Started](GETTING_STARTED.md) - Quick start guide for new users
- [Usage Guide](USAGE_GUIDE.md) - Comprehensive usage guide
- [SQL Compatibility](SQL_COMPATIBILITY.md) - SQL dialect compatibility matrix

---

## License

GoSQLX CLI is licensed under the Apache License 2.0. See [LICENSE](../LICENSE) for details.

---

**Last Updated**: December 2025
**Version**: v1.6.0
