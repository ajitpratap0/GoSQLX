# PyGoSQLX

Python bindings for [GoSQLX](https://github.com/ajitpratap0/GoSQLX) -- a high-performance SQL parser written in Go. Parses, validates, formats, and analyzes SQL statements at native speed via a shared library (ctypes FFI).

Powered by Go's compiled performance, PyGoSQLX is 100x+ faster than pure Python SQL parsers while providing a simple, Pythonic API.

## Installation

### Step 1: Build the shared library

Requires a Go toolchain matching the repository's `go.mod` (Go 1.26+) with cgo enabled.

```bash
cd pkg/cbinding
./build.sh
```

This compiles the Go code into a shared library (`libgosqlx.so` on Linux, `libgosqlx.dylib` on macOS, `libgosqlx.dll` on Windows) and places it in `python/pygosqlx/lib/`.

You can customize the output directory:

```bash
OUTPUT_DIR=/path/to/output ./build.sh
```

### Step 2: Install the Python package

```bash
cd python
pip install .
```

For development:

```bash
pip install -e ".[dev]"
```

If the library is not bundled in the package, set the environment variable:

```bash
export GOSQLX_LIB_PATH=/path/to/libgosqlx.so
```

## Quick Start

```python
import pygosqlx

# Parse SQL - raises ParseError on invalid SQL
result = pygosqlx.parse("SELECT id, name FROM users WHERE active = true")
print(result.statement_count)  # 1
print(result.statement_types)  # ['SELECT']

# Validate SQL syntax
is_valid = pygosqlx.validate("SELECT * FROM users")
print(is_valid)  # True

is_valid = pygosqlx.validate("SELEC * FORM users")
print(is_valid)  # False

# Validate with detailed error info
detail = pygosqlx.validate_detailed("SELEC * FORM users")
if not detail.valid:
    print(detail.error)        # Error message
    print(detail.error_line)   # Line number
    print(detail.error_column) # Column number

# Format SQL
formatted = pygosqlx.format("select id,name from users where id=1")
print(formatted)

# Extract table names
tables = pygosqlx.extract_tables(
    "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id"
)
print(tables)  # ['users', 'orders']

# Extract column names
columns = pygosqlx.extract_columns("SELECT id, name, email FROM users")
print(columns)  # ['id', 'name', 'email']

# Extract function calls
functions = pygosqlx.extract_functions(
    "SELECT COUNT(*), AVG(price) FROM orders"
)
print(functions)  # ['COUNT', 'AVG']

# Extract all metadata at once
meta = pygosqlx.extract_metadata(
    "SELECT u.name, COUNT(o.id) FROM users u JOIN orders o ON u.id = o.user_id GROUP BY u.name"
)
print(meta.tables)     # ['users', 'orders']
print(meta.columns)    # ['name', 'id']
print(meta.functions)  # ['COUNT']
# Qualified names available too:
for qn in meta.tables_qualified:
    print(f"{qn.schema}.{qn.name}" if qn.schema else qn.name)
```

### Dialects

Every parsing function takes an optional keyword-only `dialect=` argument.
Without it (or with `dialect=None`) the default parser is used, exactly as in
earlier releases.

```python
print(pygosqlx.dialects())
# ['generic', 'postgresql', 'mysql', 'mariadb', 'sqlserver', 'oracle',
#  'sqlite', 'snowflake', 'bigquery', 'redshift', 'clickhouse']

sql = "SELECT TOP 5 [id] FROM [dbo].[users]"
pygosqlx.validate(sql)                       # False - not generic SQL
pygosqlx.validate(sql, dialect="sqlserver")  # True
pygosqlx.extract_tables(sql, dialect="sqlserver")  # ['dbo.users']
pygosqlx.format("SELECT `id` FROM `users`", dialect="mysql")

# An unknown dialect raises UnsupportedDialectError (also a ValueError)
pygosqlx.parse("SELECT 1", dialect="postgres")  # use "postgresql"
```

### Linting

`lint()` runs the same rule set as the `gosqlx lint` CLI command (L001-L010:
whitespace, indentation, line length, column alignment, keyword case, comma
placement, aliasing). SQL that does not parse is still linted by the text and
token rules.

```python
result = pygosqlx.lint("select id from users  ", max_line_length=100)
for v in result.violations:
    print(v.rule, v.severity, v.line, v.column, v.message)
# L001 warning 1 21 Line has trailing whitespace
# L007 warning 1 1 Keyword 'select' should be uppercase: 'SELECT'
# ...
print(result.is_clean, result.violation_count)
```

### Security scanning

`security_scan()` looks for SQL injection patterns (tautologies, comment
bypasses, stacked queries, UNION injection, time-based and out-of-band
techniques, dangerous functions). The scan works on the raw text, so payloads
that are not valid SQL are scanned too.

```python
scan = pygosqlx.security_scan("SELECT * FROM users WHERE id = 1 OR 1=1 --")
print(scan.is_clean, scan.has_critical)  # False True
for f in scan.findings:
    print(f.severity, f.pattern, f.description)
```

### Transpiling

```python
pygosqlx.transpile(
    "CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY)", "mysql", "postgresql"
)
# 'CREATE TABLE t (id SERIAL PRIMARY KEY)'
```

Dedicated rewrites exist for MySQL to PostgreSQL, PostgreSQL to MySQL and
PostgreSQL to SQLite. Other pairs are parsed with the source dialect and
re-rendered without rewrites.

### Library compatibility

The functions and the `dialect=` argument added in 0.3.0 need a shared
library built from a matching GoSQLX checkout. With an older library, calls
without `dialect=` keep working, while `dialect=`, `lint()`,
`security_scan()`, `transpile()` and `dialects()` raise `GoSQLXError` asking
you to rebuild the library.

### Error Handling

```python
from pygosqlx import parse, validate, extract_tables
from pygosqlx.exceptions import ParseError, FormatError, GoSQLXError

# parse() raises ParseError on invalid SQL
try:
    result = parse("SELECT * FORM users")
except ParseError as e:
    print(f"Error: {e.message}")
    print(f"At line {e.line}, column {e.column}")

# validate() returns a boolean (never raises)
if not validate("BAD SQL"):
    print("Invalid SQL")

# extract_*() functions raise ParseError on invalid SQL
try:
    tables = extract_tables("NOT VALID SQL")
except ParseError as e:
    print(f"Parse error: {e}")

# All exceptions inherit from GoSQLXError
try:
    parse("???")
except GoSQLXError as e:
    print(f"Caught: {e}")
```

## API Reference

| Function | Returns | Description |
|---|---|---|
| `parse(sql, *, dialect=None)` | `ParseResult` | Parse SQL; raises `ParseError` on failure |
| `validate(sql, *, dialect=None)` | `bool` | Check if SQL is syntactically valid |
| `validate_detailed(sql, *, dialect=None)` | `ValidationResult` | Validate with error line/column details |
| `format(sql, *, dialect=None)` | `str` | Format/pretty-print a SQL statement |
| `extract_tables(sql, *, dialect=None)` | `list[str]` | Extract all table names |
| `extract_columns(sql, *, dialect=None)` | `list[str]` | Extract all column names |
| `extract_functions(sql, *, dialect=None)` | `list[str]` | Extract all function calls |
| `extract_metadata(sql, *, dialect=None)` | `Metadata` | Extract tables, columns, functions, and qualified names |
| `lint(sql, *, dialect=None, max_line_length=None)` | `LintResult` | Lint with the `gosqlx lint` rule set (L001-L010); `max_line_length` defaults to 100 |
| `security_scan(sql)` | `SecurityScanResult` | Scan for SQL injection patterns |
| `transpile(sql, from_dialect, to_dialect)` | `str` | Convert SQL between dialects; raises `TranspileError` on failure |
| `dialects()` | `list[str]` | Names accepted by every `dialect` argument |
| `version()` | `str` | Get the GoSQLX library version |

`dialect` must be one of the names returned by `dialects()`; an unknown name
raises `UnsupportedDialectError`.

### Data Types

| Type | Fields |
|---|---|
| `ParseResult` | `statement_count: int`, `statement_types: list[str]` |
| `ValidationResult` | `valid: bool`, `error: str?`, `error_line: int?`, `error_column: int?` |
| `Metadata` | `tables`, `columns`, `functions`, `tables_qualified`, `columns_qualified` |
| `QualifiedName` | `name: str`, `schema: str`, `table: str` |
| `LintResult` | `violations: list[LintViolation]`; properties `violation_count`, `is_clean` |
| `LintViolation` | `rule`, `rule_name`, `severity`, `message`, `line`, `column`, `suggestion`, `can_auto_fix` |
| `SecurityScanResult` | `findings: list[SecurityFinding]`, `total_count`, `critical_count`, `high_count`, `medium_count`, `low_count`; properties `is_clean`, `has_critical`, `has_high` |
| `SecurityFinding` | `severity`, `pattern`, `description`, `risk`, `line: int?`, `column: int?`, `sql`, `suggestion` |

### Exceptions

| Exception | Base | When |
|---|---|---|
| `GoSQLXError` | `Exception` | Base for all PyGoSQLX errors |
| `ParseError` | `GoSQLXError` | SQL parsing fails |
| `FormatError` | `GoSQLXError` | SQL formatting fails |
| `ValidationError` | `GoSQLXError` | SQL validation fails |
| `TranspileError` | `GoSQLXError` | `transpile()` cannot parse or rewrite the SQL |
| `UnsupportedDialectError` | `GoSQLXError`, `ValueError` | A `dialect` argument is not a supported dialect (`code` is `E4002`) |

All exceptions have `message`, `code`, `line`, and `column` attributes.

## Platform Support

| Platform | Library Extension | Status |
|---|---|---|
| Linux (x86_64, arm64) | `.so` | Supported |
| macOS (x86_64, arm64) | `.dylib` | Supported |
| Windows (via MSYS2/MinGW) | `.dll` | Supported |

## Performance

PyGoSQLX calls into compiled Go code via ctypes, avoiding the overhead of pure Python parsing. Typical performance characteristics:

- **1M+ operations/sec** for simple queries
- **Sub-microsecond** validation for short SQL statements
- **Zero-copy** tokenization in the Go layer
- **Object pooling** for minimal GC pressure

This makes PyGoSQLX suitable for high-throughput use cases such as SQL proxies, query analyzers, and CI/CD validation pipelines.

## Development

### Building from source

```bash
# Clone the repository
git clone https://github.com/ajitpratap0/GoSQLX.git
cd GoSQLX

# Build the shared library
cd pkg/cbinding
./build.sh
cd ../../python

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest
```

### Running tests

```bash
cd python
pytest -v                    # All tests
pytest tests/test_types.py   # Type/exception tests (no shared library needed)
pytest tests/test_integration.py  # Integration tests (requires shared library)
pytest --cov=pygosqlx        # With coverage
```

### Project structure

```
python/
  pygosqlx/
    __init__.py       # Package entry point, public API
    core.py           # ctypes bindings to the Go shared library
    exceptions.py     # Custom exception hierarchy
    py.typed          # PEP 561 type hint marker
    lib/              # Shared library output directory (built artifacts)
  tests/
    test_types.py                  # Type and exception tests (no shared library needed)
    test_package_version.py        # Version metadata consistency
    test_integration.py            # Integration tests with shared library
    test_dialect_and_analysis.py   # dialect=, lint, security_scan, transpile, dialects
  pyproject.toml      # Package metadata and build config
  setup.py            # Legacy build support
```

## License

Apache-2.0. See the [LICENSE](../LICENSE) file in the repository root.
