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

**Security limits:**
- Maximum file size: 10MB
- Maximum SQL query length: 10MB

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
```makefile
# Makefile example
.PHONY: sql-lint sql-format sql-check

sql-lint:
	gosqlx validate src/**/*.sql

sql-format:
	gosqlx format -i src/**/*.sql

sql-check:
	gosqlx format --check src/**/*.sql
```

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

GoSQLX CLI is licensed under the MIT License. See [LICENSE](../LICENSE) for details.