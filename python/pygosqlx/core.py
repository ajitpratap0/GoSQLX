"""Core module providing Python bindings to GoSQLX via ctypes.

This module loads the GoSQLX shared library (built from Go with cgo) and
provides a Pythonic API for SQL parsing, validation, formatting, and
metadata extraction.

IMPORTANT: All C function return types are declared as c_void_p (not c_char_p)
to prevent ctypes from auto-converting the C pointer to a Python bytes object.
This preserves the original pointer so it can be correctly passed to gosqlx_free
for proper memory management.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from pygosqlx.exceptions import FormatError, GoSQLXError, ParseError


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ParseResult:
    """Result of parsing a SQL statement."""

    statement_count: int
    statement_types: List[str]


@dataclass
class ValidationResult:
    """Result of validating a SQL statement with error details."""

    valid: bool
    error: Optional[str] = None
    error_line: Optional[int] = None
    error_column: Optional[int] = None


@dataclass
class QualifiedName:
    """A qualified SQL identifier (e.g., schema.table or table.column)."""

    name: str
    schema: str = ""
    table: str = ""

    def __str__(self) -> str:
        parts = []
        if self.schema:
            parts.append(self.schema)
        if self.table:
            parts.append(self.table)
        if self.name:
            parts.append(self.name)
        return ".".join(parts)


@dataclass
class Metadata:
    """Comprehensive metadata extracted from a SQL query."""

    tables: List[str] = field(default_factory=list)
    columns: List[str] = field(default_factory=list)
    functions: List[str] = field(default_factory=list)
    tables_qualified: List[QualifiedName] = field(default_factory=list)
    columns_qualified: List[QualifiedName] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Library loading
# ---------------------------------------------------------------------------

_lib = None
_lib_lock = threading.Lock()


def _get_lib_path() -> str:
    """Find the shared library path.

    Search order:
    1. GOSQLX_LIB_PATH environment variable
    2. Bundled library in pygosqlx/lib/
    """
    system = platform.system().lower()
    if system == "linux":
        ext = "so"
    elif system == "darwin":
        ext = "dylib"
    elif system == "windows":
        ext = "dll"
    else:
        raise OSError(f"Unsupported platform: {system}")

    # Check environment variable first (explicit override)
    env_path = os.environ.get("GOSQLX_LIB_PATH")
    if env_path and os.path.exists(env_path):
        return env_path

    # Look in package lib directory
    pkg_dir = Path(__file__).parent
    lib_path = pkg_dir / "lib" / f"libgosqlx.{ext}"
    if lib_path.exists():
        return str(lib_path)

    raise FileNotFoundError(
        f"GoSQLX shared library not found. "
        f"Searched: GOSQLX_LIB_PATH env var, {lib_path}. "
        f"Build it with: cd pkg/cbinding && ./build.sh"
    )


def _load_library() -> ctypes.CDLL:
    """Load the GoSQLX shared library and configure function signatures.

    All functions that return C strings use c_void_p as restype to prevent
    ctypes from auto-converting the pointer to bytes (which would lose the
    original pointer needed for gosqlx_free).
    """
    lib_path = _get_lib_path()
    lib = ctypes.CDLL(lib_path)

    # --- gosqlx_parse ---
    lib.gosqlx_parse.argtypes = [ctypes.c_char_p]
    lib.gosqlx_parse.restype = ctypes.c_void_p

    # --- gosqlx_validate ---
    lib.gosqlx_validate.argtypes = [ctypes.c_char_p]
    lib.gosqlx_validate.restype = ctypes.c_void_p

    # --- gosqlx_extract_tables ---
    lib.gosqlx_extract_tables.argtypes = [ctypes.c_char_p]
    lib.gosqlx_extract_tables.restype = ctypes.c_void_p

    # --- gosqlx_free ---
    lib.gosqlx_free.argtypes = [ctypes.c_void_p]
    lib.gosqlx_free.restype = None

    # --- gosqlx_version ---
    lib.gosqlx_version.argtypes = []
    lib.gosqlx_version.restype = ctypes.c_void_p

    # --- Optional functions (may not exist in older builds) ---
    _bind_optional(lib, "gosqlx_format", [ctypes.c_char_p], ctypes.c_void_p)
    _bind_optional(
        lib, "gosqlx_extract_columns", [ctypes.c_char_p], ctypes.c_void_p
    )
    _bind_optional(
        lib, "gosqlx_extract_functions", [ctypes.c_char_p], ctypes.c_void_p
    )
    _bind_optional(
        lib, "gosqlx_extract_metadata", [ctypes.c_char_p], ctypes.c_void_p
    )

    return lib


def _bind_optional(
    lib: ctypes.CDLL,
    name: str,
    argtypes: list,
    restype: Any,
) -> None:
    """Bind a C function if it exists in the library, silently skip otherwise."""
    try:
        func = getattr(lib, name)
        func.argtypes = argtypes
        func.restype = restype
    except AttributeError:
        pass


def _get_lib() -> ctypes.CDLL:
    """Get the shared library, loading it lazily with thread-safe initialization."""
    global _lib
    if _lib is not None:
        return _lib
    with _lib_lock:
        # Double-checked locking
        if _lib is None:
            _lib = _load_library()
        return _lib


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _call_and_decode(func: Any, *args: Any) -> Dict[str, Any]:
    """Call a C function that returns a JSON string, decode, and free memory.

    The function must return a c_void_p (not c_char_p) so we can properly
    free the pointer after decoding.

    Args:
        func: A ctypes function object whose restype is c_void_p.
        *args: Arguments to pass to the C function.

    Returns:
        Parsed JSON as a Python dict.

    Raises:
        GoSQLXError: If the C function returns NULL.
    """
    result_ptr = func(*args)
    if result_ptr is None:
        raise GoSQLXError("C function returned NULL — possible out-of-memory")
    try:
        result_bytes = ctypes.string_at(result_ptr)
        return json.loads(result_bytes.decode("utf-8"))
    finally:
        _get_lib().gosqlx_free(result_ptr)


def _has_func(name: str) -> bool:
    """Check if a function exists in the loaded library."""
    try:
        getattr(_get_lib(), name)
        return True
    except AttributeError:
        return False


def _parse_error_from_json(data: Dict[str, Any]) -> ParseError:
    """Create a ParseError from a JSON error response."""
    error_msg = data.get("error", "Unknown parse error")
    error_line = data.get("error_line")
    error_column = data.get("error_column")
    error_code = data.get("error_code")
    return ParseError(
        message=error_msg,
        code=error_code,
        line=error_line,
        column=error_column,
    )


def _parse_qualified_names(raw_list: List[Dict[str, str]]) -> List[QualifiedName]:
    """Convert a list of raw dicts to QualifiedName objects."""
    result = []
    for item in raw_list:
        if isinstance(item, dict):
            result.append(
                QualifiedName(
                    name=item.get("name", item.get("Name", "")),
                    schema=item.get("schema", item.get("Schema", "")),
                    table=item.get("table", item.get("Table", "")),
                )
            )
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse(sql: str) -> ParseResult:
    """Parse a SQL statement and return the result.

    Args:
        sql: The SQL string to parse.

    Returns:
        ParseResult with statement_count and statement_types.

    Raises:
        ParseError: If the SQL is syntactically invalid.
        GoSQLXError: If the shared library is not available or returns NULL.
    """
    lib = _get_lib()
    data = _call_and_decode(lib.gosqlx_parse, sql.encode("utf-8"))

    if not data.get("success", False):
        raise _parse_error_from_json(data)

    return ParseResult(
        statement_count=data.get("statement_count", 0),
        statement_types=data.get("statement_types", []),
    )


def validate(sql: str) -> bool:
    """Validate SQL syntax.

    Args:
        sql: The SQL string to validate.

    Returns:
        True if the SQL is syntactically valid, False otherwise.
    """
    lib = _get_lib()
    data = _call_and_decode(lib.gosqlx_validate, sql.encode("utf-8"))
    return data.get("valid", False)


def validate_detailed(sql: str) -> ValidationResult:
    """Validate SQL syntax with detailed error information.

    Args:
        sql: The SQL string to validate.

    Returns:
        ValidationResult with valid flag and optional error details.
    """
    lib = _get_lib()
    data = _call_and_decode(lib.gosqlx_validate, sql.encode("utf-8"))
    return ValidationResult(
        valid=data.get("valid", False),
        error=data.get("error") or None,
        error_line=data.get("error_line"),
        error_column=data.get("error_column"),
    )


def format(sql: str) -> str:
    """Format a SQL statement for readability.

    Args:
        sql: The SQL string to format.

    Returns:
        The formatted SQL string.

    Raises:
        FormatError: If the SQL cannot be formatted (e.g., invalid syntax).
        GoSQLXError: If the gosqlx_format function is not available.
    """
    if not _has_func("gosqlx_format"):
        raise GoSQLXError(
            "gosqlx_format not available in this library build. "
            "Rebuild the shared library with the latest cbinding."
        )
    lib = _get_lib()
    data = _call_and_decode(lib.gosqlx_format, sql.encode("utf-8"))

    if "error" in data and data["error"]:
        raise FormatError(message=data["error"])

    return data.get("formatted", data.get("result", sql))


def extract_tables(sql: str) -> List[str]:
    """Extract table names from a SQL statement.

    Args:
        sql: The SQL string to analyze.

    Returns:
        List of table names referenced in the SQL.

    Raises:
        ParseError: If the SQL is syntactically invalid.
    """
    lib = _get_lib()
    data = _call_and_decode(lib.gosqlx_extract_tables, sql.encode("utf-8"))

    if "error" in data and data["error"]:
        raise _parse_error_from_json(data)

    return data.get("tables", [])


def extract_columns(sql: str) -> List[str]:
    """Extract column names from a SQL statement.

    Args:
        sql: The SQL string to analyze.

    Returns:
        List of column names referenced in the SQL.

    Raises:
        ParseError: If the SQL is syntactically invalid.
        GoSQLXError: If the gosqlx_extract_columns function is not available.
    """
    if not _has_func("gosqlx_extract_columns"):
        raise GoSQLXError(
            "gosqlx_extract_columns not available in this library build. "
            "Rebuild the shared library with the latest cbinding."
        )
    lib = _get_lib()
    data = _call_and_decode(lib.gosqlx_extract_columns, sql.encode("utf-8"))

    if "error" in data and data["error"]:
        raise _parse_error_from_json(data)

    return data.get("columns", [])


def extract_functions(sql: str) -> List[str]:
    """Extract function names from a SQL statement.

    Args:
        sql: The SQL string to analyze.

    Returns:
        List of function names used in the SQL.

    Raises:
        ParseError: If the SQL is syntactically invalid.
        GoSQLXError: If the gosqlx_extract_functions function is not available.
    """
    if not _has_func("gosqlx_extract_functions"):
        raise GoSQLXError(
            "gosqlx_extract_functions not available in this library build. "
            "Rebuild the shared library with the latest cbinding."
        )
    lib = _get_lib()
    data = _call_and_decode(lib.gosqlx_extract_functions, sql.encode("utf-8"))

    if "error" in data and data["error"]:
        raise _parse_error_from_json(data)

    return data.get("functions", [])


def extract_metadata(sql: str) -> Metadata:
    """Extract comprehensive metadata from a SQL statement.

    This returns tables, columns, functions, and their qualified variants
    in a single call.

    Args:
        sql: The SQL string to analyze.

    Returns:
        Metadata object containing all extracted information.

    Raises:
        ParseError: If the SQL is syntactically invalid.
        GoSQLXError: If the gosqlx_extract_metadata function is not available.
    """
    if not _has_func("gosqlx_extract_metadata"):
        raise GoSQLXError(
            "gosqlx_extract_metadata not available in this library build. "
            "Rebuild the shared library with the latest cbinding."
        )
    lib = _get_lib()
    data = _call_and_decode(lib.gosqlx_extract_metadata, sql.encode("utf-8"))

    if "error" in data and data["error"]:
        raise _parse_error_from_json(data)

    return Metadata(
        tables=data.get("tables", []),
        columns=data.get("columns", []),
        functions=data.get("functions", []),
        tables_qualified=_parse_qualified_names(
            data.get("tables_qualified", [])
        ),
        columns_qualified=_parse_qualified_names(
            data.get("columns_qualified", [])
        ),
    )


def version() -> str:
    """Get the GoSQLX library version.

    Returns:
        Version string (e.g., "1.7.0").
    """
    lib = _get_lib()
    result_ptr = lib.gosqlx_version()
    if result_ptr is None:
        raise GoSQLXError("gosqlx_version returned NULL")
    try:
        result_bytes = ctypes.string_at(result_ptr)
        return result_bytes.decode("utf-8")
    finally:
        lib.gosqlx_free(result_ptr)
