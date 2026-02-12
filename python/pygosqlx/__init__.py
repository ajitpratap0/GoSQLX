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

    # Extract tables
    tables = pygosqlx.extract_tables("SELECT * FROM users JOIN orders ON ...")
    print(tables)  # ['users', 'orders']
"""

from pygosqlx.core import parse, validate, extract_tables, version

__version__ = "0.1.0"
__all__ = ["parse", "validate", "extract_tables", "version"]
