# GoSQLX CLI Guide

The GoSQLX Command Line Interface (CLI) provides high-performance SQL parsing, validation, formatting, and analysis capabilities directly from your terminal.

## Installation

### Build from Source
```bash
git clone https://github.com/ajitpratap0/GoSQLX.git
cd GoSQLX
go build -o gosqlx ./cmd/gosqlx
```

### Install via Go
```bash
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
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

#### `gosqlx config init`
Create a new configuration file with default settings:

```bash
# Create .gosqlx.yml in current directory
gosqlx config init

# Create config in home directory
gosqlx config init --path ~/.gosqlx.yml

# Create config in custom location
gosqlx config init --path /path/to/config.yml
```

#### `gosqlx config validate`
Validate configuration file syntax and values:

```bash
# Validate default config location
gosqlx config validate

# Validate specific config file
gosqlx config validate --file /path/to/config.yml
```

#### `gosqlx config show`
Display current configuration (merged from all sources):

```bash
# Show current configuration as YAML
gosqlx config show

# Show as JSON
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

### Configuration Examples

**Team configuration for PostgreSQL projects** (`.gosqlx.yml`):
```yaml
format:
  indent: 2
  uppercase_keywords: true
  max_line_length: 100

validate:
  dialect: postgresql
  strict_mode: true

output:
  format: table
```

**Personal configuration for MySQL** (`~/.gosqlx.yml`):
```yaml
format:
  indent: 4
  uppercase_keywords: false
  compact: true

validate:
  dialect: mysql
  recursive: true

analyze:
  all: true
```

**CI/CD configuration** (`.gosqlx.yml`):
```yaml
format:
  indent: 2
  uppercase_keywords: true
  max_line_length: 80

validate:
  dialect: postgresql
  strict_mode: true

output:
  format: json
  verbose: false
```

### Configuration Precedence

When multiple configuration sources exist, settings are merged with this precedence:

1. **CLI flags** (highest priority)
2. **Current directory** `.gosqlx.yml`
3. **Home directory** `~/.gosqlx.yml`
4. **System-wide** `/etc/gosqlx.yml`
5. **Built-in defaults** (lowest priority)

Example:
```bash
# Config file has: indent: 2
# CLI flag overrides: --indent 4
# Result: Uses indent: 4

gosqlx format --indent 4 query.sql
```

## Commands

### `gosqlx validate`
Validate SQL syntax and report errors.

```bash
# Validate direct SQL
gosqlx validate "SELECT id, name FROM users"

# Validate SQL file
gosqlx validate query.sql

# Validate multiple files
gosqlx validate *.sql

# Batch validation with verbose output
gosqlx validate -v queries/
```

**Performance**: 1.38M+ operations/second sustained throughput

### `gosqlx format`
Format SQL queries with intelligent indentation and style.

```bash
# Format to stdout
gosqlx format query.sql

# Format in-place
gosqlx format -i query.sql

# Custom indentation (4 spaces)
gosqlx format --indent 4 query.sql

# Compact format
gosqlx format --compact query.sql

# Check if formatting is needed (CI mode)
gosqlx format --check *.sql
```

**Options:**
- `-i, --in-place`: Edit files in place
- `--indent SIZE`: Indentation size in spaces (default: 2)
- `--uppercase`: Uppercase SQL keywords (default: true)
- `--no-uppercase`: Keep original keyword case
- `--compact`: Minimal whitespace format
- `--check`: Exit with error if files need formatting

**Performance**: 2,600+ files/second throughput

### `gosqlx analyze`
Deep analysis of SQL queries with detailed reports.

```bash
# Analyze SQL structure
gosqlx analyze "SELECT u.name, COUNT(o.id) FROM users u JOIN orders o ON u.id = o.user_id GROUP BY u.name"

# Analyze with JSON output
gosqlx analyze -f json query.sql

# Analyze multiple files
gosqlx analyze queries/*.sql

# Detailed analysis with security checks
gosqlx analyze -v --security query.sql
```

**Output formats:**
- `table` (default): Human-readable table format
- `json`: JSON output for programmatic use
- `yaml`: YAML output
- `tree`: AST tree visualization

### `gosqlx parse`
Parse SQL into Abstract Syntax Tree (AST) representation.

```bash
# Parse and display AST
gosqlx parse "SELECT * FROM users WHERE age > 18"

# Parse with tree visualization
gosqlx parse -f tree complex_query.sql

# Parse to JSON for integration
gosqlx parse -f json query.sql > ast.json
```

### `gosqlx watch`
Monitor SQL files for changes and validate/format in real-time.

```bash
# Watch current directory for SQL file changes
gosqlx watch

# Watch specific directory with validation
gosqlx watch ./queries --validate

# Watch with formatting on save
gosqlx watch ./queries --format

# Watch with custom pattern
gosqlx watch ./queries --pattern "*.sql"
```

**Options:**
- `--validate`: Run validation on file changes
- `--format`: Auto-format files on save
- `--pattern PATTERN`: File pattern to watch (default: "*.sql")

**Use Case:** Real-time SQL development with automatic validation/formatting

### `gosqlx lint`
Check SQL files for style issues and best practices.

```bash
# Lint SQL files
gosqlx lint query.sql

# Lint with specific rules
gosqlx lint --rules L001,L002,L005 query.sql

# Lint directory recursively
gosqlx lint -r ./queries
```

**Available lint rules:**
- L001: Missing semicolon at end of statement
- L002: Inconsistent keyword casing
- L005: Unused table alias

**Options:**
- `--rules RULES`: Comma-separated list of rule codes to check
- `-r, --recursive`: Recursively process directories

**Use Case:** Enforce SQL coding standards and best practices

## Global Flags

- `-v, --verbose`: Enable verbose output
- `-o, --output FILE`: Output to file instead of stdout
- `-f, --format FORMAT`: Output format (auto, json, yaml, table, tree)

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

### Batch Processing
Process multiple files efficiently:

```bash
# Process entire directory
gosqlx format -i sql_files/

# Process with pattern matching
gosqlx validate "src/**/*.sql"

# Parallel processing for performance
gosqlx analyze queries/ -v
```

### CI/CD Integration
Perfect for continuous integration:

```bash
# Format checking (exits with code 1 if formatting needed)
gosqlx format --check src/

# Validation in CI pipeline
gosqlx validate --strict queries/

# Generate reports for analysis
gosqlx analyze -f json src/ > analysis-report.json
```

### SQL Dialect Support
Supports multiple SQL dialects:

- PostgreSQL (including arrays, JSONB)
- MySQL (including backticks)
- SQL Server (including brackets)
- Oracle SQL
- SQLite

### Advanced SQL Features Supported

**Window Functions (Phase 2.5 - v1.3.0)**
```sql
SELECT 
    name, 
    salary,
    ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) as rank,
    LAG(salary, 1) OVER (ORDER BY hire_date) as prev_salary
FROM employees;
```

**Common Table Expressions (CTEs)**
```sql
WITH RECURSIVE employee_hierarchy AS (
    SELECT id, name, manager_id, 1 as level 
    FROM employees WHERE manager_id IS NULL
    UNION ALL
    SELECT e.id, e.name, e.manager_id, eh.level + 1 
    FROM employees e 
    JOIN employee_hierarchy eh ON e.manager_id = eh.id
)
SELECT * FROM employee_hierarchy;
```

**Set Operations**
```sql
SELECT product FROM inventory 
UNION SELECT product FROM orders
EXCEPT SELECT product FROM discontinued
INTERSECT SELECT product FROM active_catalog;
```

**Complete JOIN Support**
```sql
SELECT u.name, o.order_date, p.product_name
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
INNER JOIN products p ON o.product_id = p.id
WHERE u.active = true;
```

## Performance

GoSQLX CLI delivers exceptional performance:

| Operation | Throughput | Latency |
|-----------|------------|---------|
| **Validation** | 1.38M+ ops/sec | <1μs |
| **Formatting** | 2,600+ files/sec | <1ms |
| **Analysis** | 1M+ queries/sec | <2μs |
| **Parsing** | 1.5M+ ops/sec | <1μs |

**Memory efficiency:**
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

## Examples

### 1. Validate and Format SQL Files
```bash
# Validate all SQL files in project
gosqlx validate src/**/*.sql

# Format with consistent style
gosqlx format -i --indent 4 --uppercase src/**/*.sql

# Check formatting in CI
gosqlx format --check src/ || exit 1
```

### 2. SQL Analysis Workflow
```bash
# Analyze complex query
gosqlx analyze -v "
WITH sales_summary AS (
    SELECT region, SUM(amount) as total 
    FROM sales 
    GROUP BY region
    HAVING SUM(amount) > 1000
)
SELECT * FROM sales_summary 
WHERE total > (SELECT AVG(total) FROM sales_summary)
"
```

### 3. Batch Processing
```bash
# Process multiple files with different operations
find sql/ -name "*.sql" -exec gosqlx validate {} \;
find sql/ -name "*.sql" -exec gosqlx format -i {} \;
find sql/ -name "*.sql" -exec gosqlx analyze -f json {} \; > analysis.json
```

## Integration

### Editor Integration
GoSQLX can be integrated with editors for SQL linting and formatting:

```bash
# Format selection in editor
gosqlx format --stdin < selection.sql

# Validate on save
gosqlx validate current_file.sql
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

1. **Use batch processing** for multiple files
2. **Enable verbose output** only when needed
3. **Use appropriate output format** (JSON for scripts, table for humans)
4. **Process files concurrently** when possible

## Contributing

To contribute to the GoSQLX CLI:

1. Fork the repository
2. Create a feature branch
3. Add tests for new CLI features
4. Submit a pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for detailed guidelines.

## License

GoSQLX CLI is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See [LICENSE](../LICENSE) for details.