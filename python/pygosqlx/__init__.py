"""PyGoSQLX - Python bindings for GoSQLX SQL parser.

A high-performance SQL parser powered by GoSQLX's Go engine.
100x+ faster than pure Python SQL parsers.

Usage:
    import pygosqlx

    # Parse SQL
    result = pygosqlx.parse("SELECT * FROM users")
    print(result.statement_types)  # ['SELECT']

    # Validate SQL
    is_valid = pygosqlx.validate("SELECT * FROM users")
    print(is_valid)  # True

    # Validate with details
    result = pygosqlx.validate_detailed("SELECT * FROM")
    if not result.valid:
        print(result.error)

    # Format SQL
    formatted = pygosqlx.format("select * from users")
    print(formatted)

    # Extract tables
    tables = pygosqlx.extract_tables("SELECT * FROM users JOIN orders ON ...")
    print(tables)  # ['users', 'orders']

    # Extract columns
    columns = pygosqlx.extract_columns("SELECT name, email FROM users")
    print(columns)  # ['name', 'email']

    # Extract functions
    functions = pygosqlx.extract_functions("SELECT COUNT(*), UPPER(name) FROM users")
    print(functions)  # ['COUNT', 'UPPER']

    # Extract all metadata
    metadata = pygosqlx.extract_metadata("SELECT COUNT(*) FROM users u JOIN orders o ON u.id = o.user_id")
    print(metadata.tables)     # ['users', 'orders']
    print(metadata.functions)  # ['COUNT']

    # Dialect-aware parsing (every function above accepts dialect=)
    pygosqlx.parse("SELECT TOP 5 [id] FROM [users]", dialect="sqlserver")
    print(pygosqlx.dialects())  # ['generic', 'postgresql', 'mysql', ...]

    # Lint with the `gosqlx lint` rule set (L001-L010)
    for v in pygosqlx.lint("select id from users").violations:
        print(v.rule, v.message)

    # Scan for SQL injection patterns
    scan = pygosqlx.security_scan("SELECT * FROM users WHERE id = 1 OR 1=1 --")
    print(scan.is_clean, scan.has_critical)

    # Convert between dialects
    print(pygosqlx.transpile("CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY)",
                             "mysql", "postgresql"))
"""

from pygosqlx.core import (
    LintResult,
    LintViolation,
    Metadata,
    ParseResult,
    QualifiedName,
    SecurityFinding,
    SecurityScanResult,
    ValidationResult,
    dialects,
    extract_columns,
    extract_functions,
    extract_metadata,
    extract_tables,
    format,
    lint,
    parse,
    security_scan,
    transpile,
    validate,
    validate_detailed,
    version,
)
from pygosqlx.exceptions import (
    FormatError,
    GoSQLXError,
    ParseError,
    TranspileError,
    UnsupportedDialectError,
    ValidationError,
)

__version__ = "1.17.0"
__all__ = [
    # Functions
    "parse",
    "validate",
    "validate_detailed",
    "format",
    "extract_tables",
    "extract_columns",
    "extract_functions",
    "extract_metadata",
    "lint",
    "security_scan",
    "transpile",
    "dialects",
    "version",
    # Data types
    "ParseResult",
    "ValidationResult",
    "Metadata",
    "QualifiedName",
    "LintResult",
    "LintViolation",
    "SecurityScanResult",
    "SecurityFinding",
    # Exceptions
    "GoSQLXError",
    "ParseError",
    "FormatError",
    "ValidationError",
    "TranspileError",
    "UnsupportedDialectError",
]
