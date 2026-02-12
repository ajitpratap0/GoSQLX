# PyGoSQLX

Python bindings for [GoSQLX](https://github.com/ajitpratap0/GoSQLX) -- a high-performance SQL parser written in Go. Parses, validates, formats, and analyzes SQL statements at native speed via a shared library (ctypes FFI).

Powered by Go's compiled performance, PyGoSQLX is 100x+ faster than pure Python SQL parsers while providing a simple, Pythonic API.

## Installation

### Step 1: Build the shared library

Requires Go 1.24+ installed.

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
| `parse(sql)` | `ParseResult` | Parse SQL; raises `ParseError` on failure |
| `validate(sql)` | `bool` | Check if SQL is syntactically valid |
| `validate_detailed(sql)` | `ValidationResult` | Validate with error line/column details |
| `format(sql)` | `str` | Format/pretty-print a SQL statement |
| `extract_tables(sql)` | `list[str]` | Extract all table names |
| `extract_columns(sql)` | `list[str]` | Extract all column names |
| `extract_functions(sql)` | `list[str]` | Extract all function calls |
| `extract_metadata(sql)` | `Metadata` | Extract tables, columns, functions, and qualified names |
| `version()` | `str` | Get the GoSQLX library version |

### Data Types

| Type | Fields |
|---|---|
| `ParseResult` | `statement_count: int`, `statement_types: list[str]` |
| `ValidationResult` | `valid: bool`, `error: str?`, `error_line: int?`, `error_column: int?` |
| `Metadata` | `tables`, `columns`, `functions`, `tables_qualified`, `columns_qualified` |
| `QualifiedName` | `name: str`, `schema: str`, `table: str` |

### Exceptions

| Exception | Base | When |
|---|---|---|
| `GoSQLXError` | `Exception` | Base for all PyGoSQLX errors |
| `ParseError` | `GoSQLXError` | SQL parsing fails |
| `FormatError` | `GoSQLXError` | SQL formatting fails |
| `ValidationError` | `GoSQLXError` | SQL validation fails |

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
    test_types.py         # Type and exception tests (40 tests)
    test_integration.py   # Integration tests with shared library (36 tests)
  pyproject.toml      # Package metadata and build config
  setup.py            # Legacy build support
```

## License

AGPL-3.0. See the [LICENSE](../LICENSE) file in the repository root.
