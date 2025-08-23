# SQL Validator

A command-line SQL validation tool powered by GoSQLX.

## Features

- Validate SQL syntax for multiple dialects
- Process single queries or entire SQL files
- Detailed error reporting with line/column information
- Support for multiple queries in one file
- Dialect-specific warnings
- Pipe support for integration with other tools

## Installation

```bash
go install github.com/ajitpratap0/GoSQLX/examples/sql-validator@latest
```

## Usage

### Validate a single query
```bash
sql-validator -query "SELECT * FROM users WHERE id = 1"
```

### Validate a SQL file
```bash
sql-validator -file queries.sql
```

### Validate with specific dialect
```bash
sql-validator -query "SELECT * FROM `users`" -dialect mysql
```

### Pipe SQL from another command
```bash
cat migration.sql | sql-validator
```

### Verbose output
```bash
sql-validator -file complex.sql -verbose
```

## Options

- `-query`: SQL query to validate
- `-file`: SQL file to validate
- `-dialect`: SQL dialect (postgres, mysql, mssql, oracle, sqlite)
- `-verbose`: Show detailed output including token count and tables

## Examples

### Basic validation
```bash
$ sql-validator -query "SELECT id, name FROM users"
Validating 1 SQL query using postgres dialect...
✅ Query 1: VALID

=== Summary ===
Total queries: 1
Valid: 1
Invalid: 0
```

### Error detection
```bash
$ sql-validator -query "SELECT * FORM users"
Validating 1 SQL query using postgres dialect...
❌ Query 1: INVALID
   Error: unexpected token: FORM
   Location: Line 1, Column 10

=== Summary ===
Total queries: 1
Valid: 0
Invalid: 1
```

### Multiple queries
```bash
$ sql-validator -file migrations.sql
Validating 5 SQL queries using postgres dialect...
✅ Query 1: VALID
✅ Query 2: VALID
❌ Query 3: INVALID
   Error: syntax error near 'FORM'
✅ Query 4: VALID
✅ Query 5: VALID

=== Summary ===
Total queries: 5
Valid: 4
Invalid: 1
```

## Exit Codes

- `0`: All queries are valid
- `1`: One or more queries are invalid

## Integration

Use in CI/CD pipelines:

```yaml
# GitHub Actions example
- name: Validate SQL migrations
  run: sql-validator -file migrations/*.sql
```

```bash
# Pre-commit hook example
#!/bin/bash
sql-validator -file $(git diff --cached --name-only | grep '.sql$')
```