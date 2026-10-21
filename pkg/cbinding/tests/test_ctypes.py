#!/usr/bin/env python3
"""
pkg/cbinding/tests/test_ctypes.py

Integration tests for the GoSQLX C binding via Python ctypes.

Requires the shared library to be built first:
    cd pkg/cbinding && bash build.sh

The tests skip gracefully when the library has not been built.
"""
import ctypes
import json
import os
import sys
import unittest

# ---------------------------------------------------------------------------
# Library loading
# ---------------------------------------------------------------------------

# Search paths relative to this file (one level up = pkg/cbinding/).
_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LIB_PATHS = [
    os.path.join(_BASE, "libgosqlx.so"),    # Linux
    os.path.join(_BASE, "libgosqlx.dylib"),  # macOS
    os.path.join(_BASE, "libgosqlx.dll"),    # Windows
]

_RESULT_FUNCTIONS = [
    "gosqlx_parse",
    "gosqlx_validate",
    "gosqlx_format",
    "gosqlx_extract_tables",
    "gosqlx_extract_columns",
    "gosqlx_extract_functions",
    "gosqlx_extract_metadata",
    "gosqlx_version",
]


def _load_library():
    """Load the first libgosqlx shared library found, configure return types."""
    for path in _LIB_PATHS:
        if os.path.exists(path):
            lib = ctypes.CDLL(path)
            # Results are declared c_void_p (not c_char_p) so ctypes hands back
            # the original malloc'd pointer. With c_char_p, ctypes converts the
            # result to a Python bytes copy and gosqlx_free would then be given
            # a pointer it never allocated.
            for fn_name in _RESULT_FUNCTIONS:
                fn = getattr(lib, fn_name, None)
                if fn is not None:
                    fn.restype = ctypes.c_void_p
                    if fn_name != "gosqlx_version":
                        fn.argtypes = [ctypes.c_char_p]
            lib.gosqlx_free.argtypes = [ctypes.c_void_p]
            lib.gosqlx_free.restype = None
            return lib
    raise RuntimeError(
        "Could not find libgosqlx. Build it first with:\n"
        "  cd pkg/cbinding && bash build.sh\n"
        f"Searched: {_LIB_PATHS}"
    )


try:
    _lib = _load_library()
    _SKIP_REASON = None
except RuntimeError as _e:
    _lib = None
    _SKIP_REASON = str(_e)
    print(f"SKIP: {_e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _call(fn_name: str, sql: str) -> dict:
    """Call a gosqlx function and return the parsed JSON result dict."""
    fn = getattr(_lib, fn_name)
    result_ptr = fn(sql.encode("utf-8"))
    if result_ptr is None:
        raise RuntimeError(f"{fn_name} returned NULL")
    try:
        result_json = ctypes.string_at(result_ptr).decode("utf-8")
    finally:
        _lib.gosqlx_free(result_ptr)
    return json.loads(result_json)


def _skip_if_no_lib(test_class):
    """Class decorator: skip entire class when the library is unavailable."""
    if _SKIP_REASON:
        return unittest.skip(_SKIP_REASON)(test_class)
    return test_class


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------

@_skip_if_no_lib
class TestGosqlxParse(unittest.TestCase):
    """Tests for gosqlx_parse."""

    def test_valid_select(self):
        r = _call("gosqlx_parse", "SELECT id, name FROM users WHERE active = 1")
        self.assertTrue(r["success"])
        self.assertEqual(r["statement_count"], 1)
        self.assertEqual(r["statement_types"][0], "SELECT")

    def test_invalid_sql(self):
        r = _call("gosqlx_parse", "THIS IS NOT SQL AT ALL !!!!")
        self.assertFalse(r["success"])
        self.assertIn("error", r)
        self.assertNotEqual(r["error"], "")

    def test_multiple_statements(self):
        r = _call("gosqlx_parse", "SELECT 1; SELECT 2; SELECT 3")
        self.assertTrue(r["success"])
        self.assertEqual(r["statement_count"], 3)

    def test_insert_statement(self):
        r = _call("gosqlx_parse", "INSERT INTO orders (user_id, amount) VALUES (1, 99.99)")
        self.assertTrue(r["success"])
        self.assertEqual(r["statement_types"][0], "INSERT")

    def test_update_statement(self):
        r = _call("gosqlx_parse", "UPDATE products SET price = 19.99 WHERE id = 5")
        self.assertTrue(r["success"])
        self.assertEqual(r["statement_types"][0], "UPDATE")

    def test_delete_statement(self):
        r = _call("gosqlx_parse", "DELETE FROM sessions WHERE expires_at < NOW()")
        self.assertTrue(r["success"])
        self.assertEqual(r["statement_types"][0], "DELETE")

    def test_empty_sql(self):
        # Must not crash; statement count is 0.
        r = _call("gosqlx_parse", "")
        self.assertIn("statement_count", r)

    def test_cte_query(self):
        r = _call("gosqlx_parse", "WITH cte AS (SELECT id FROM users) SELECT * FROM cte")
        self.assertTrue(r["success"])

    def test_window_function(self):
        r = _call("gosqlx_parse",
                  "SELECT id, ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) FROM employees")
        self.assertTrue(r["success"])

    def test_unicode_sql(self):
        r = _call("gosqlx_parse",
                  "SELECT * FROM users WHERE name = '日本語テスト' AND city = 'München'")
        self.assertTrue(r["success"])


@_skip_if_no_lib
class TestGosqlxValidate(unittest.TestCase):
    """Tests for gosqlx_validate."""

    def test_valid_select(self):
        r = _call("gosqlx_validate", "SELECT * FROM users WHERE id > 0")
        self.assertTrue(r["valid"])

    def test_invalid_sql(self):
        r = _call("gosqlx_validate", "SELECT FROM")
        self.assertFalse(r["valid"])
        self.assertIn("error", r)

    def test_valid_join(self):
        r = _call("gosqlx_validate",
                  "SELECT u.id, o.total FROM users u INNER JOIN orders o ON u.id = o.user_id")
        self.assertTrue(r["valid"])

    def test_empty_sql(self):
        # Must not crash.
        r = _call("gosqlx_validate", "")
        self.assertIn("valid", r)


@_skip_if_no_lib
class TestGosqlxFormat(unittest.TestCase):
    """Tests for gosqlx_format."""

    def test_formats_lowercase_sql(self):
        r = _call("gosqlx_format", "select id,name from users where id=1")
        self.assertTrue(r["success"])
        self.assertIn("SELECT", r["formatted"].upper())

    def test_formatted_not_empty(self):
        r = _call("gosqlx_format", "SELECT * FROM users")
        self.assertTrue(r["success"])
        self.assertGreater(len(r["formatted"]), 0)


@_skip_if_no_lib
class TestGosqlxExtract(unittest.TestCase):
    """Tests for gosqlx_extract_tables, _columns, _functions, _metadata."""

    SQL = "SELECT u.id, COUNT(o.id) FROM users u JOIN orders o ON u.id = o.user_id GROUP BY u.id"

    def test_extract_tables(self):
        r = _call("gosqlx_extract_tables", self.SQL)
        self.assertIn("tables", r)
        self.assertGreater(len(r["tables"]), 0)

    def test_extract_columns(self):
        r = _call("gosqlx_extract_columns", self.SQL)
        self.assertIn("columns", r)
        self.assertGreater(len(r["columns"]), 0)

    def test_extract_functions(self):
        r = _call("gosqlx_extract_functions", self.SQL)
        self.assertIn("functions", r)
        fn_names = [f.upper() for f in r["functions"]]
        self.assertIn("COUNT", fn_names, f"COUNT not found in functions: {r['functions']}")

    def test_extract_metadata_has_all_keys(self):
        r = _call("gosqlx_extract_metadata", self.SQL)
        self.assertIn("tables", r)
        self.assertIn("columns", r)
        self.assertIn("functions", r)

    def test_extract_tables_invalid_sql(self):
        r = _call("gosqlx_extract_tables", "GARBAGE SQL")
        # Must return valid JSON (either error or empty tables).
        self.assertIsInstance(r, dict)

    def test_extract_columns_invalid_sql(self):
        r = _call("gosqlx_extract_columns", "GARBAGE SQL")
        self.assertIsInstance(r, dict)

    def test_extract_functions_invalid_sql(self):
        r = _call("gosqlx_extract_functions", "GARBAGE SQL")
        self.assertIsInstance(r, dict)


@_skip_if_no_lib
class TestGosqlxVersion(unittest.TestCase):
    """Tests for gosqlx_version (caller-owned string — must be freed with gosqlx_free)."""

    def test_version_is_semver(self):
        result_ptr = _lib.gosqlx_version()
        try:
            version = ctypes.string_at(result_ptr).decode("utf-8")
        finally:
            _lib.gosqlx_free(result_ptr)
        self.assertGreater(len(version), 0)
        parts = version.split(".")
        self.assertEqual(len(parts), 3, f"Expected semver X.Y.Z, got: {version}")
        for part in parts:
            self.assertTrue(part.isdigit(), f"Non-numeric semver part: {part!r} in {version!r}")

    def test_version_is_stable(self):
        """Two calls return equal strings in distinct allocations, both freeable."""
        ptr1 = _lib.gosqlx_version()
        ptr2 = _lib.gosqlx_version()
        try:
            self.assertNotEqual(ptr1, ptr2, "gosqlx_version must return a fresh allocation")
            v1 = ctypes.string_at(ptr1).decode("utf-8")
            v2 = ctypes.string_at(ptr2).decode("utf-8")
            self.assertEqual(v1, v2)
        finally:
            _lib.gosqlx_free(ptr1)
            if ptr2 != ptr1:
                _lib.gosqlx_free(ptr2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
