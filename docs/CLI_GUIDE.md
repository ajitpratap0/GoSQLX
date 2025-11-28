# GoSQLX CLI Guide

The GoSQLX Command Line Interface (CLI) provides high-performance SQL parsing, validation, formatting, and analysis capabilities directly from your terminal.

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

## Quick Start

### Basic Usage
```bash
# Validate a SQL query
gosqlx validate "SELECT * FROM users WHERE active = true"

# Format a SQL file
gosqlx format query.sql

# Parse and analyze SQL
gosqlx analyze "SELECT COUNT(*) FROM orders GROUP BY status"
```

## Configuration

GoSQLX supports configuration files for persistent settings across all commands. This enables team-wide consistency and reduces the need for command-line flags.

### Configuration File Locations

Configuration files are searched in the following order (highest priority first):

1. **Current directory**: `.gosqlx.yml`
2. **Home directory**: `~/.gosqlx.yml`
3. **System-wide**: `/etc/gosqlx.yml`

CLI flags always override configuration file settings.

### Configuration Commands

```bash
# Create a new configuration file
gosqlx config init
gosqlx config init --path ~/.gosqlx.yml

# Validate configuration file
gosqlx config validate
gosqlx config validate --file /path/to/config.yml

# Show current configuration
gosqlx config show
gosqlx config show --format json
```

### Configuration Schema

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
```

### Configuration Example

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
```

### Configuration Precedence

Settings are merged in this order (highest to lowest priority):
1. CLI flags
2. Current directory `.gosqlx.yml`
3. Home directory `~/.gosqlx.yml`
4. System-wide `/etc/gosqlx.yml`
5. Built-in defaults

## Commands

### `gosqlx validate`
Validate SQL syntax and report errors.

```bash
# Validate direct SQL
gosqlx validate "SELECT id, name FROM users"

# Validate SQL file
gosqlx validate query.sql

# Validate multiple files
gosqlx validate query1.sql query2.sql

# Validate with glob pattern
gosqlx validate "*.sql"

# Recursively validate directory
gosqlx validate -r ./queries/

# Quiet mode (exit code only)
gosqlx validate --quiet query.sql

# Show performance statistics
gosqlx validate --stats ./queries/

# SARIF output for GitHub Code Scanning
gosqlx validate --output-format sarif --output-file results.sarif queries/

# Validate from stdin
echo "SELECT * FROM users" | gosqlx validate
cat query.sql | gosqlx validate
gosqlx validate -
gosqlx validate < query.sql
```

**Options:**
- `-r, --recursive`: Recursively process directories
- `-p, --pattern`: File pattern for recursive processing (default: "*.sql")
- `-q, --quiet`: Quiet mode (exit code only)
- `-s, --stats`: Show performance statistics
- `--dialect`: SQL dialect (postgresql, mysql, sqlserver, oracle, sqlite)
- `--strict`: Enable strict validation mode
- `--output-format`: Output format (text, json, sarif)
- `--output-file`: Output file path (default: stdout)

**Output Formats:**
- `text`: Human-readable output (default)
- `json`: JSON format for programmatic consumption
- `sarif`: SARIF 2.1.0 format for GitHub Code Scanning integration

**Performance**: <10ms for typical queries, 100+ files/second in batch mode

### `gosqlx format`
Format SQL queries with intelligent indentation and style.

```bash
# Format to stdout
gosqlx format query.sql

# Format in-place
gosqlx format -i query.sql

# Custom indentation (4 spaces)
gosqlx format --indent 4 query.sql

# Keep original keyword case
gosqlx format --no-uppercase query.sql

# Compact format
gosqlx format --compact query.sql

# Check if formatting is needed (CI mode)
gosqlx format --check query.sql

# Format all SQL files with glob
gosqlx format "*.sql"

# Save to specific file
gosqlx format -o formatted.sql query.sql

# Format from stdin
echo "SELECT * FROM users" | gosqlx format
cat query.sql | gosqlx format
gosqlx format -
gosqlx format < query.sql
cat query.sql | gosqlx format > formatted.sql
```

**Options:**
- `-i, --in-place`: Edit files in place (not supported with stdin)
- `--indent INT`: Indentation size in spaces (default: 2)
- `--uppercase`: Uppercase SQL keywords (default: true)
- `--no-uppercase`: Keep original keyword case
- `--compact`: Minimal whitespace format
- `--check`: Check if files need formatting (CI mode)
- `--max-line INT`: Maximum line length (default: 80)

**Performance**: 100x faster than SQLFluff for equivalent operations

### `gosqlx analyze`
Analyze SQL queries for security vulnerabilities, performance issues, and complexity metrics.

```bash
# Basic analysis
gosqlx analyze query.sql

# Analyze direct SQL
gosqlx analyze "SELECT u.name, COUNT(o.id) FROM users u JOIN orders o ON u.id = o.user_id GROUP BY u.name"

# Security vulnerability scan
gosqlx analyze --security query.sql

# Performance optimization hints
gosqlx analyze --performance query.sql

# Complexity scoring
gosqlx analyze --complexity query.sql

# Comprehensive analysis
gosqlx analyze --all query.sql

# Analyze with JSON output
gosqlx analyze -f json query.sql

# Analyze from stdin
echo "SELECT * FROM users" | gosqlx analyze
cat query.sql | gosqlx analyze
gosqlx analyze -
gosqlx analyze < query.sql
```

**Options:**
- `--security`: Focus on security vulnerability analysis
- `--performance`: Focus on performance optimization analysis
- `--complexity`: Focus on complexity metrics
- `--all`: Comprehensive analysis

**Analysis capabilities:**
- SQL injection pattern detection
- Performance optimization suggestions
- Query complexity scoring
- Best practices validation
- Multi-dialect compatibility checks

**Note**: This is a basic implementation. Advanced analysis features are in Phase 4 of the roadmap.

### `gosqlx parse`
Parse SQL into Abstract Syntax Tree (AST) representation.

```bash
# Parse and display AST
gosqlx parse query.sql

# Parse direct SQL
gosqlx parse "SELECT * FROM users WHERE age > 18"

# Show detailed AST structure
gosqlx parse --ast query.sql

# Show tokenization output
gosqlx parse --tokens query.sql

# Show tree visualization
gosqlx parse --tree query.sql

# Parse to JSON for integration
gosqlx parse -f json query.sql > ast.json

# Parse to YAML
gosqlx parse -f yaml query.sql

# Parse from stdin
echo "SELECT * FROM users" | gosqlx parse
cat query.sql | gosqlx parse
gosqlx parse -
gosqlx parse < query.sql
```

**Options:**
- `--ast`: Show detailed AST structure
- `--tokens`: Show tokenization output
- `--tree`: Show tree visualization

**Output formats:**
- `json`: JSON output
- `yaml`: YAML output
- `table`: Table format
- `tree`: Tree visualization

### `gosqlx lint`
Check SQL files for style issues and best practices.

```bash
# Lint SQL files
gosqlx lint query.sql

# Lint multiple files
gosqlx lint query1.sql query2.sql

# Lint with glob pattern
gosqlx lint "*.sql"

# Lint directory recursively
gosqlx lint -r ./queries

# Auto-fix violations where possible
gosqlx lint --auto-fix query.sql

# Set maximum line length
gosqlx lint --max-length 120 query.sql

# Fail on warnings (useful for CI)
gosqlx lint --fail-on-warn query.sql

# Lint from stdin
echo "SELECT * FROM users" | gosqlx lint
cat query.sql | gosqlx lint
gosqlx lint -
```

**Available lint rules:**
- L001: Trailing whitespace at end of lines
- L002: Mixed tabs and spaces for indentation
- L005: Lines exceeding maximum length

**Options:**
- `-r, --recursive`: Recursively process directories
- `-p, --pattern`: File pattern for recursive processing (default: "*.sql")
- `--auto-fix`: Automatically fix violations where possible
- `--max-length`: Maximum line length for L005 rule (default: 100)
- `--fail-on-warn`: Exit with error code on warnings

**Exit Codes:**
- 0: No violations found
- 1: Errors or warnings found (warnings only if --fail-on-warn is set)

### `gosqlx lsp`
Start the Language Server Protocol (LSP) server for IDE integration.

```bash
# Start LSP server on stdio
gosqlx lsp

# Start with logging enabled
gosqlx lsp --log /tmp/lsp.log
```

**Features:**
- Real-time syntax error detection
- SQL formatting
- Keyword documentation on hover
- SQL keyword and function completion

**IDE Integration:**

See `gosqlx lsp --help` for VSCode, Neovim, and Emacs integration examples.

### `gosqlx completion`
Generate autocompletion script for your shell.

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

## Global Flags

Available for all commands:

- `-v, --verbose`: Enable verbose output
- `-o, --output FILE`: Output to file instead of stdout
- `-f, --format FORMAT`: Output format (auto, json, yaml, table, tree)
- `-h, --help`: Help for any command
- `--version`: Show version information

## File Input

GoSQLX automatically detects whether input is a file path or direct SQL:

```bash
# Direct SQL (detected automatically)
gosqlx validate "SELECT 1"

# File input (detected automatically)
gosqlx validate /path/to/query.sql

# Directory input (processes all .sql files)
gosqlx validate /path/to/sql/files/

# Glob patterns
gosqlx validate "queries/*.sql"
```

**Supported file extensions:**
- `.sql` - SQL files
- `.txt` - Text files containing SQL
- Files without extension are also supported

**Security limits and protections:**

GoSQLX CLI implements comprehensive security validation to protect against malicious input:

1. **File Size Limits**:
   - Maximum file size: 10MB (10,485,760 bytes)
   - Maximum direct SQL query length: 10MB
   - Prevents DoS attacks via oversized files

2. **Path Traversal Protection**:
   - Blocks attempts to access files outside intended directories
   - Detects and rejects paths with multiple `..` sequences
   - Example blocked: `../../../../../../etc/passwd`

3. **Symlink Protection**:
   - Symlinks are blocked by default for security
   - Prevents symlink-based attacks to system files
   - All symlink chains are rejected

4. **File Type Restrictions**:
   - **Allowed**: `.sql`, `.txt`, files without extension
   - **Blocked**: `.exe`, `.bat`, `.sh`, `.py`, `.js`, `.dll`, `.so`, `.jar`, and all other executable/binary formats
   - Prevents execution of malicious code

5. **Special File Protection**:
   - Blocks device files (`/dev/null`, `/dev/random`, etc.)
   - Rejects directories, pipes, and sockets
   - Only regular files are accepted

6. **Permission Validation**:
   - Verifies read permissions before processing
   - Fails gracefully with clear error messages

**Security error examples:**
```bash
# Path traversal attempt
$ gosqlx validate "../../etc/passwd"
Error: security validation failed: path traversal detected

# Executable file rejection
$ gosqlx validate malware.exe
Error: unsupported file extension: .exe (allowed: [.sql .txt ])

# Oversized file rejection
$ gosqlx validate huge.sql
Error: file too large: 11534336 bytes (max 10485760 bytes)

# Device file rejection
$ gosqlx validate /dev/null
Error: not a regular file: /dev/null
```

For more details, see the [Security Validation Package](../cmd/gosqlx/internal/validate/README.md).

## Advanced Features

### CI/CD Integration
Perfect for continuous integration:

```bash
# Format checking (exits with code 1 if formatting needed)
gosqlx format --check src/

# Validation in CI pipeline
gosqlx validate -r --strict queries/

# SARIF output for GitHub Code Scanning
gosqlx validate --output-format sarif --output-file results.sarif queries/

# Generate reports for analysis
gosqlx analyze -f json src/ > analysis-report.json

# Lint with fail on warnings
gosqlx lint --fail-on-warn -r queries/
```

### SQL Dialect Support
Supports multiple SQL dialects:

- PostgreSQL (including arrays, JSONB)
- MySQL (including backticks)
- SQL Server (including brackets)
- Oracle SQL
- SQLite

### Advanced SQL Features Supported

- **Window Functions**: ROW_NUMBER, RANK, DENSE_RANK, LAG, LEAD, FIRST_VALUE, LAST_VALUE, etc.
- **CTEs**: WITH clause, recursive CTEs
- **Set Operations**: UNION, EXCEPT, INTERSECT
- **JOINs**: LEFT, RIGHT, INNER, FULL OUTER, CROSS, NATURAL
- **Advanced Expressions**: BETWEEN, IN, LIKE, IS NULL, CASE WHEN
- **Modern SQL**: Materialized views, MERGE statements, GROUPING SETS, ROLLUP, CUBE

## Performance

GoSQLX CLI delivers exceptional performance:

| Operation | Throughput | Performance Target |
|-----------|------------|-------------------|
| **Validation** | 100+ files/sec | <10ms for typical queries |
| **Formatting** | 100x faster than SQLFluff | High-performance processing |
| **Analysis** | 1.38M+ ops/sec | Production-ready |
| **Parsing** | 1.5M+ ops/sec | Direct AST inspection |

**Core Library Performance:**
- 1.38M+ operations/second sustained throughput
- 1.5M peak with memory-efficient object pooling
- 60-80% memory reduction through object pooling
- Zero-copy tokenization
- Concurrent processing support

## Error Handling

GoSQLX provides detailed error messages with context:

```bash
$ gosqlx validate "SELECT * FORM users"
Error at line 1, column 10: expected FROM, got IDENT 'FORM'
  SELECT * FORM users
           ^^^^
Hint: Did you mean 'FROM'?
```

## Usage Examples

### Validate and Format
```bash
# Validate all SQL files
gosqlx validate "src/**/*.sql"

# Format with consistent style
gosqlx format -i --indent 4 src/**/*.sql

# CI format check
gosqlx format --check src/ || exit 1
```

### Analysis and Linting
```bash
# Analyze complex query
gosqlx analyze --all complex_query.sql

# Lint with strict rules
gosqlx lint --fail-on-warn -r queries/
```

## Integration

### Editor Integration
GoSQLX provides LSP server for rich IDE integration:

```bash
# Start LSP server (for IDE integration)
gosqlx lsp

# Or use CLI commands for simple editor integration:

# Format selection in editor (via stdin)
cat selection.sql | gosqlx format

# Validate on save
gosqlx validate current_file.sql

# Lint on save
gosqlx lint current_file.sql
```

### Build Tools Integration
```yaml
# Taskfile.yml example (using go-task)
version: '3'

tasks:
  sql:lint:
    desc: Validate SQL files
    cmds:
      - gosqlx validate src/**/*.sql

  sql:format:
    desc: Format SQL files in place
    cmds:
      - gosqlx format -i src/**/*.sql

  sql:check:
    desc: Check SQL formatting
    cmds:
      - gosqlx format --check src/**/*.sql
```

Run with: `task sql:lint`, `task sql:format`, or `task sql:check`

## Troubleshooting

### Common Issues

**File not found:**
```bash
$ gosqlx validate missing.sql
Error: cannot access file missing.sql: no such file or directory
```

**Invalid SQL:**
```bash
$ gosqlx validate "SELECT * WHERE"
Error at line 1, column 11: expected FROM clause
  SELECT * WHERE
           ^^^^^
```

**Large file:**
```bash
$ gosqlx validate huge.sql
Error: file too large: 15728640 bytes (max 10485760 bytes)
```

### Performance Tips

1. Use batch processing for multiple files with glob patterns
2. Enable verbose output only when needed
3. Use appropriate output format (JSON for scripts, table for humans)
4. Leverage SARIF format for GitHub Code Scanning integration

## Contributing

To contribute to the GoSQLX CLI:

1. Fork the repository
2. Create a feature branch
3. Add tests for new CLI features
4. Submit a pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for detailed guidelines.

## License

GoSQLX CLI is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See [LICENSE](../LICENSE) for details.