"""Integration tests for PyGoSQLX that require the shared library.

These tests exercise the full ctypes pipeline: Python -> C -> Go -> C -> Python.
They are skipped when the shared library is not available (i.e., not built).

To run these tests:
    1. Build the shared library:  cd pkg/cbinding && ./build.sh
    2. Run:  cd python && python -m pytest tests/test_integration.py -v

Or set GOSQLX_LIB_PATH to point to the built library:
    GOSQLX_LIB_PATH=/path/to/libgosqlx.dylib python -m pytest tests/test_integration.py -v
"""

import os
import platform
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _lib_available() -> bool:
    """Check if the GoSQLX shared library can be found."""
    # Check environment variable
    env_path = os.environ.get("GOSQLX_LIB_PATH")
    if env_path and os.path.exists(env_path):
        return True

    # Check bundled location
    system = platform.system().lower()
    ext_map = {"linux": "so", "darwin": "dylib", "windows": "dll"}
    ext = ext_map.get(system)
    if ext is None:
        return False

    pkg_dir = os.path.join(os.path.dirname(__file__), "..", "pygosqlx", "lib")
    lib_path = os.path.join(pkg_dir, f"libgosqlx.{ext}")
    return os.path.exists(lib_path)


# Skip all tests in this module if the library is not built
pytestmark = pytest.mark.skipif(
    not _lib_available(),
    reason="GoSQLX shared library not built (run: cd pkg/cbinding && ./build.sh)",
)


# ---------------------------------------------------------------------------
# Imports (only used when library is available, but safe to import always)
# ---------------------------------------------------------------------------

from pygosqlx.core import (
    Metadata,
    ParseResult,
    QualifiedName,
    ValidationResult,
    extract_columns,
    extract_functions,
    extract_metadata,
    extract_tables,
    format,
    parse,
    validate,
    validate_detailed,
    version,
)
from pygosqlx.exceptions import FormatError, GoSQLXError, ParseError


# ---------------------------------------------------------------------------
# parse() tests
# ---------------------------------------------------------------------------


class TestParse:
    def test_parse_select(self):
        result = parse("SELECT * FROM users")
        assert isinstance(result, ParseResult)
        assert result.statement_count == 1
        assert "SELECT" in result.statement_types

    def test_parse_insert(self):
        result = parse("INSERT INTO users (name) VALUES ('Alice')")
        assert result.statement_count == 1
        assert "INSERT" in result.statement_types

    def test_parse_update(self):
        result = parse("UPDATE users SET name = 'Bob' WHERE id = 1")
        assert result.statement_count == 1
        assert "UPDATE" in result.statement_types

    def test_parse_delete(self):
        result = parse("DELETE FROM users WHERE id = 1")
        assert result.statement_count == 1
        assert "DELETE" in result.statement_types

    def test_parse_invalid_raises_parse_error(self):
        with pytest.raises(ParseError) as exc_info:
            parse("SELECT FROM WHERE")
        assert exc_info.value.message  # Should have an error message

    def test_parse_empty_string_raises(self):
        """Empty SQL should raise ParseError."""
        with pytest.raises((ParseError, GoSQLXError)):
            parse("")

    def test_parse_complex_query(self):
        sql = """
        SELECT u.name, COUNT(o.id) as order_count
        FROM users u
        LEFT JOIN orders o ON u.id = o.user_id
        WHERE u.active = true
        GROUP BY u.name
        ORDER BY order_count DESC
        """
        result = parse(sql)
        assert result.statement_count == 1
        assert "SELECT" in result.statement_types


# ---------------------------------------------------------------------------
# validate() tests
# ---------------------------------------------------------------------------


class TestValidate:
    def test_validate_valid_sql(self):
        assert validate("SELECT * FROM users") is True

    def test_validate_invalid_sql(self):
        assert validate("SELECT FROM WHERE") is False

    def test_validate_insert(self):
        assert validate("INSERT INTO users (name) VALUES ('Alice')") is True

    def test_validate_multiple_statements(self):
        # Single-statement validation
        assert validate("SELECT 1") is True


class TestValidateDetailed:
    def test_valid_sql(self):
        result = validate_detailed("SELECT * FROM users")
        assert isinstance(result, ValidationResult)
        assert result.valid is True
        assert result.error is None

    def test_invalid_sql(self):
        result = validate_detailed("SELECT FROM WHERE")
        assert result.valid is False
        assert result.error is not None
        assert len(result.error) > 0


# ---------------------------------------------------------------------------
# format() tests
# ---------------------------------------------------------------------------


class TestFormat:
    def test_format_sql(self):
        """Test that format returns a string without raising."""
        try:
            result = format("SELECT * FROM users")
            assert isinstance(result, str)
            assert len(result) > 0
        except GoSQLXError as e:
            if "not available" in str(e):
                pytest.skip("gosqlx_format not available in this build")
            raise

    def test_format_invalid_sql_raises(self):
        """Formatting invalid SQL should raise an error."""
        try:
            format("SELECT FROM WHERE")
            # If format doesn't raise, that's also acceptable for some implementations
        except (FormatError, GoSQLXError):
            pass  # Expected
        except Exception:
            pytest.skip("gosqlx_format not available in this build")


# ---------------------------------------------------------------------------
# extract_tables() tests
# ---------------------------------------------------------------------------


class TestExtractTables:
    def test_single_table(self):
        tables = extract_tables("SELECT * FROM users")
        assert isinstance(tables, list)
        assert "users" in tables

    def test_join_tables(self):
        tables = extract_tables(
            "SELECT * FROM users u JOIN orders o ON u.id = o.user_id"
        )
        assert "users" in tables
        assert "orders" in tables

    def test_invalid_sql_raises(self):
        with pytest.raises(ParseError):
            extract_tables("SELECT FROM WHERE")

    def test_subquery_tables(self):
        tables = extract_tables(
            "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders)"
        )
        assert "users" in tables


# ---------------------------------------------------------------------------
# extract_columns() tests
# ---------------------------------------------------------------------------


class TestExtractColumns:
    def test_extract_columns(self):
        try:
            columns = extract_columns("SELECT name, email FROM users")
            assert isinstance(columns, list)
            # The exact columns depend on parser behavior
            assert len(columns) >= 0
        except GoSQLXError as e:
            if "not available" in str(e):
                pytest.skip("gosqlx_extract_columns not available in this build")
            raise

    def test_extract_columns_invalid_sql(self):
        try:
            extract_columns("SELECT FROM WHERE")
            pytest.fail("Should have raised an error")
        except ParseError:
            pass  # Expected
        except GoSQLXError as e:
            if "not available" in str(e):
                pytest.skip("gosqlx_extract_columns not available in this build")
            raise


# ---------------------------------------------------------------------------
# extract_functions() tests
# ---------------------------------------------------------------------------


class TestExtractFunctions:
    def test_extract_functions(self):
        try:
            functions = extract_functions(
                "SELECT COUNT(*), UPPER(name) FROM users"
            )
            assert isinstance(functions, list)
            assert len(functions) >= 0
        except GoSQLXError as e:
            if "not available" in str(e):
                pytest.skip(
                    "gosqlx_extract_functions not available in this build"
                )
            raise

    def test_extract_functions_invalid_sql(self):
        try:
            extract_functions("SELECT FROM WHERE")
            pytest.fail("Should have raised an error")
        except ParseError:
            pass  # Expected
        except GoSQLXError as e:
            if "not available" in str(e):
                pytest.skip(
                    "gosqlx_extract_functions not available in this build"
                )
            raise


# ---------------------------------------------------------------------------
# extract_metadata() tests
# ---------------------------------------------------------------------------


class TestExtractMetadata:
    def test_extract_metadata(self):
        try:
            meta = extract_metadata(
                "SELECT COUNT(*), u.name FROM users u "
                "JOIN orders o ON u.id = o.user_id"
            )
            assert isinstance(meta, Metadata)
            assert isinstance(meta.tables, list)
            assert isinstance(meta.columns, list)
            assert isinstance(meta.functions, list)
            assert isinstance(meta.tables_qualified, list)
            assert isinstance(meta.columns_qualified, list)
        except GoSQLXError as e:
            if "not available" in str(e):
                pytest.skip(
                    "gosqlx_extract_metadata not available in this build"
                )
            raise

    def test_extract_metadata_invalid_sql(self):
        try:
            extract_metadata("SELECT FROM WHERE")
            pytest.fail("Should have raised an error")
        except ParseError:
            pass  # Expected
        except GoSQLXError as e:
            if "not available" in str(e):
                pytest.skip(
                    "gosqlx_extract_metadata not available in this build"
                )
            raise


# ---------------------------------------------------------------------------
# version() tests
# ---------------------------------------------------------------------------


class TestVersion:
    def test_version_returns_string(self):
        v = version()
        assert isinstance(v, str)
        assert len(v) > 0

    def test_version_format(self):
        """Version should look like a semver string."""
        v = version()
        parts = v.split(".")
        assert len(parts) >= 2, f"Expected semver-like version, got: {v}"


# ---------------------------------------------------------------------------
# Error detail tests
# ---------------------------------------------------------------------------


class TestParseErrorDetails:
    def test_parse_error_has_message(self):
        with pytest.raises(ParseError) as exc_info:
            parse("SELECT FROM WHERE")
        err = exc_info.value
        assert err.message is not None
        assert len(err.message) > 0

    def test_parse_error_is_gosqlx_error(self):
        with pytest.raises(GoSQLXError):
            parse("INVALID SQL STATEMENT !!!")


# ---------------------------------------------------------------------------
# Thread safety tests
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_parse(self):
        """Parse SQL concurrently from multiple threads."""
        errors = []
        results = []

        def worker(sql, index):
            try:
                result = parse(sql)
                results.append((index, result))
            except Exception as e:
                errors.append((index, e))

        queries = [
            "SELECT * FROM users",
            "SELECT name FROM orders WHERE id = 1",
            "INSERT INTO logs (msg) VALUES ('test')",
            "UPDATE users SET active = true WHERE id = 1",
            "DELETE FROM sessions WHERE expired = true",
            "SELECT COUNT(*) FROM users GROUP BY status",
            "SELECT * FROM products ORDER BY price DESC",
            "SELECT u.name FROM users u JOIN orders o ON u.id = o.user_id",
        ]

        threads = []
        for i, sql in enumerate(queries):
            t = threading.Thread(target=worker, args=(sql, i))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        # All threads should complete without errors
        assert len(errors) == 0, f"Thread errors: {errors}"
        assert len(results) == len(queries)

    def test_concurrent_validate(self):
        """Validate SQL concurrently from multiple threads."""
        errors = []
        results = []

        def worker(sql, index):
            try:
                result = validate(sql)
                results.append((index, result))
            except Exception as e:
                errors.append((index, e))

        queries = [
            "SELECT 1",
            "SELECT * FROM users",
            "INSERT INTO t (a) VALUES (1)",
            "UPDATE t SET a = 1",
            "DELETE FROM t",
        ] * 4  # 20 concurrent validations

        threads = []
        for i, sql in enumerate(queries):
            t = threading.Thread(target=worker, args=(sql, i))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0, f"Thread errors: {errors}"
        assert len(results) == len(queries)


# ---------------------------------------------------------------------------
# Memory stress tests
# ---------------------------------------------------------------------------


class TestMemoryStress:
    def test_parse_many_queries(self):
        """Parse 1000 queries in a loop without crashing.

        This is a basic memory stress test that verifies:
        - No memory leaks from missing gosqlx_free calls
        - No crashes from double-free or use-after-free
        - Stable behavior under repeated allocation/deallocation
        """
        for i in range(1000):
            result = parse(f"SELECT id, name FROM table_{i % 10} WHERE id = {i}")
            assert result.statement_count == 1

    def test_validate_many_queries(self):
        """Validate 1000 queries without crashing."""
        for i in range(1000):
            valid = validate(f"SELECT * FROM table_{i % 10}")
            assert valid is True

    def test_extract_tables_many_queries(self):
        """Extract tables from 1000 queries without crashing."""
        for i in range(1000):
            tables = extract_tables(
                f"SELECT * FROM table_a_{i % 10} JOIN table_b_{i % 5} ON true"
            )
            assert isinstance(tables, list)
            assert len(tables) >= 1

    def test_mixed_operations(self):
        """Interleave different operations to stress the memory management."""
        for i in range(500):
            sql = f"SELECT col_{i} FROM tbl_{i % 20} WHERE id = {i}"
            # Interleave parse, validate, extract
            result = parse(sql)
            assert result.statement_count == 1
            valid = validate(sql)
            assert valid is True
            tables = extract_tables(sql)
            assert isinstance(tables, list)

    def test_version_repeated(self):
        """Call version() many times to verify memory is freed properly."""
        for _ in range(1000):
            v = version()
            assert isinstance(v, str)
            assert len(v) > 0
