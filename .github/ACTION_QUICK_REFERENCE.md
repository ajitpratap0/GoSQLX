# GoSQLX GitHub Action - Quick Reference

## Basic Usage

```yaml
- uses: ajitpratap0/GoSQLX@v1
  with:
    files: '**/*.sql'
```

## All Input Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `files` | string | `**/*.sql` | Glob pattern for SQL files |
| `validate` | boolean | `true` | Enable validation |
| `lint` | boolean | `false` | Enable linting |
| `format-check` | boolean | `false` | Check formatting |
| `fail-on-error` | boolean | `true` | Fail build on errors |
| `config` | string | `` | Config file path |
| `dialect` | string | `` | SQL dialect |
| `strict` | boolean | `false` | Strict mode |
| `show-stats` | boolean | `false` | Show statistics |
| `gosqlx-version` | string | `latest` | GoSQLX version |
| `working-directory` | string | `.` | Working directory |

## Common Patterns

### Validate Only

```yaml
- uses: ajitpratap0/GoSQLX@v1
  with:
    files: '**/*.sql'
    validate: true
```

### Validate + Format Check

```yaml
- uses: ajitpratap0/GoSQLX@v1
  with:
    files: '**/*.sql'
    validate: true
    format-check: true
```

### Specific Dialect

```yaml
- uses: ajitpratap0/GoSQLX@v1
  with:
    files: 'queries/*.sql'
    dialect: 'postgresql'
    strict: true
```

### Custom Configuration

```yaml
- uses: ajitpratap0/GoSQLX@v1
  with:
    files: '**/*.sql'
    config: '.gosqlx.yml'
```

### Specific Directory

```yaml
- uses: ajitpratap0/GoSQLX@v1
  with:
    files: '*.sql'
    working-directory: './migrations'
```

## File Patterns

| Pattern | Matches |
|---------|---------|
| `**/*.sql` | All SQL files recursively |
| `*.sql` | SQL files in root only |
| `queries/**/*.sql` | All SQL in queries/ |
| `{migrations,queries}/**/*.sql` | Multiple dirs |

## Outputs

Access outputs using step ID:

```yaml
- uses: ajitpratap0/GoSQLX@v1
  id: validate
  with:
    files: '**/*.sql'

- run: echo "Validated ${{ steps.validate.outputs.validated-files }} files"
```

Available outputs:
- `validated-files` - Files validated
- `invalid-files` - Files with errors
- `formatted-files` - Files needing format
- `validation-time` - Time in milliseconds

## SQL Dialects

Supported dialects:
- `postgresql` - PostgreSQL
- `mysql` - MySQL/MariaDB
- `sqlserver` - Microsoft SQL Server
- `oracle` - Oracle Database
- `sqlite` - SQLite

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Validation errors (if `fail-on-error: true`) |
| 1 | Format issues (if `format-check: true` and `fail-on-error: true`) |

## Performance Targets

- Validation: <10ms per typical query
- Throughput: 100+ files/second
- Total time: <2 minutes for 100 files

## Troubleshooting

### No files found
```yaml
# Use absolute pattern
files: '**/*.sql'

# Or specify working directory
working-directory: './sql'
files: '*.sql'
```

### Unexpected failures
```yaml
# Try without strict mode
strict: false

# Check specific dialect
dialect: 'postgresql'
```

### Performance issues
```yaml
# Validate only changed files
# (Use with changed-files action)
files: ${{ steps.changed.outputs.all_changed_files }}
```

## Complete Example

```yaml
name: SQL Quality Check

on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Validate SQL
        uses: ajitpratap0/GoSQLX@v1
        id: validate
        with:
          files: '**/*.sql'
          validate: true
          format-check: true
          strict: true
          show-stats: true

      - name: Report
        if: always()
        run: |
          echo "Files: ${{ steps.validate.outputs.validated-files }}"
          echo "Errors: ${{ steps.validate.outputs.invalid-files }}"
          echo "Time: ${{ steps.validate.outputs.validation-time }}ms"
```

## Links

- [Full Documentation](../ACTION_README.md)
- [Testing Guide](../ACTION_TESTING_GUIDE.md)
- [Publishing Guide](../MARKETPLACE_PUBLISHING.md)
- [Example Workflows](../workflows/examples/)
