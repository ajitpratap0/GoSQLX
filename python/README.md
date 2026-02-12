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

# Parse SQL and inspect the AST
result = pygosqlx.parse("SELECT id, name FROM users WHERE active = true")
print(result.success)          # True
print(result.statement_count)  # 1
print(result.statement_types)  # ['SELECT']

# Validate SQL syntax
is_valid = pygosqlx.validate("SELECT * FROM users")
print(is_valid)  # True

is_valid = pygosqlx.validate("SELEC * FORM users")
print(is_valid)  # False

# Format SQL
formatted = pygosqlx.format("select id,name from users where id=1")
print(formatted)
# SELECT
#   id,
#   name
# FROM
#   users
# WHERE
#   id = 1

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
print(meta["tables"])     # ['users', 'orders']
print(meta["columns"])    # ['name', 'id']
print(meta["functions"])  # ['COUNT']
```

### Error Handling

```python
import pygosqlx

# parse() returns error info in the result
result = pygosqlx.parse("SELECT * FORM users")
if not result.success:
    print(f"Error: {result.error}")

# validate() returns a boolean
if not pygosqlx.validate("BAD SQL"):
    print("Invalid SQL")

# extract_tables() raises ValueError on parse failure
try:
    tables = pygosqlx.extract_tables("NOT VALID SQL")
except ValueError as e:
    print(f"Parse error: {e}")
```

## API Reference

| Function | Returns | Description |
|---|---|---|
| `parse(sql)` | `ParseResult` | Parse SQL; returns statement types, count, and errors |
| `validate(sql)` | `bool` | Check if SQL is syntactically valid |
| `format(sql)` | `str` | Format/pretty-print a SQL statement |
| `extract_tables(sql)` | `list[str]` | Extract all table names from a SQL statement |
| `extract_columns(sql)` | `list[str]` | Extract all column names from a SQL statement |
| `extract_functions(sql)` | `list[str]` | Extract all function calls from a SQL statement |
| `extract_metadata(sql)` | `dict` | Extract tables, columns, and functions in one call |
| `version()` | `str` | Get the GoSQLX library version |

### `ParseResult` Fields

| Field | Type | Description |
|---|---|---|
| `success` | `bool` | Whether parsing succeeded |
| `statement_count` | `int` | Number of statements parsed |
| `statement_types` | `list[str]` | Statement types (e.g., `['SELECT']`, `['INSERT']`) |
| `error` | `str or None` | Error message if parsing failed |

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
pytest -v
pytest --cov=pygosqlx
```

### Project structure

```
python/
  pygosqlx/
    __init__.py     # Package entry point, public API
    core.py         # ctypes bindings to the Go shared library
    lib/            # Shared library output directory (built artifacts)
  tests/
    test_core.py    # Unit tests
  pyproject.toml    # Package metadata and build config
  setup.py          # Legacy build support
```

## License

AGPL-3.0. See the [LICENSE](../LICENSE) file in the repository root.
