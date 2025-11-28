# Tutorial 2: Custom SQL Formatter

This is the working code example for Tutorial 2. It demonstrates how to build a configurable SQL formatter using GoSQLX.

## Quick Start

```bash
# Build the formatter
go build -o sql-formatter

# Create default config file
./sql-formatter init

# Format a SQL file (output to stdout)
./sql-formatter format testdata/input.sql

# Format a SQL file in-place
./sql-formatter format -i testdata/input.sql

# Use custom config
./sql-formatter format -c custom-config.json query.sql
```

## What It Does

This formatter:
- Parses SQL into an AST using GoSQLX
- Applies custom formatting rules from a JSON config file
- Supports keyword casing, indentation, comma style, and more
- Can format files in-place or output to stdout

## Configuration

The default `.sqlformat.json` config:

```json
{
  "keyword_case": "upper",
  "indent_spaces": 4,
  "max_line_length": 80,
  "comma_style": "leading",
  "space_around_operators": true,
  "align_joins": true,
  "uppercase_functions": true
}
```

## Example

### Input (testdata/input.sql)

```sql
select id,name,email from users where active=true and role in('admin','user')order by created_at desc;
```

### Output (with default config)

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

## Integration

See `.pre-commit-config.yaml` for pre-commit hook integration example.

For the complete tutorial, see: `docs/tutorials/02-custom-sql-formatter.md`
