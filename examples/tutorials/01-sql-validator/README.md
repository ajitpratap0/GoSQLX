# Tutorial 1: SQL Validator for CI/CD

This is the working code example for Tutorial 1. It demonstrates how to build a SQL validator using GoSQLX.

## Quick Start

```bash
# Build the validator
go build -o sql-validator

# Validate a single file
./sql-validator testdata/valid.sql

# Validate all SQL files in a directory
./sql-validator testdata/
```

## What It Does

This validator:
- Scans directories recursively for `.sql` files
- Validates SQL syntax using GoSQLX tokenizer and parser
- Reports errors with detailed messages
- Returns proper exit codes for CI/CD integration

## Expected Output

### Valid SQL File

```
Validating file: testdata/valid.sql

=== SQL Validation Results ===

✓ testdata/valid.sql

=== Summary ===
Total files: 1
Valid: 1
Invalid: 0

All SQL files are valid!
```

### Invalid SQL File

```
Validating file: testdata/invalid.sql

=== SQL Validation Results ===

✗ testdata/invalid.sql
  Error: parse error: ...

=== Summary ===
Total files: 1
Valid: 0
Invalid: 1
```

## Integration

See `.github/workflows/test-github-action.yml` for GitHub Actions integration example.

For the complete tutorial, see: `docs/tutorials/01-sql-validator-cicd.md`
