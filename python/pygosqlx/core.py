"""Core module providing Python bindings to GoSQLX via ctypes."""

import ctypes
import json
import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class ParseResult:
    """Result of parsing a SQL statement."""

    success: bool
    statement_count: int
    statement_types: List[str]
    error: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of validating a SQL statement."""

    valid: bool
    error: Optional[str] = None


def _get_lib_path() -> str:
    """Find the shared library path."""
    system = platform.system().lower()
    if system == "linux":
        ext = "so"
    elif system == "darwin":
        ext = "dylib"
    elif system == "windows":
        ext = "dll"
    else:
        raise OSError(f"Unsupported platform: {system}")

    # Look in package lib directory
    pkg_dir = Path(__file__).parent
    lib_path = pkg_dir / "lib" / f"libgosqlx.{ext}"

    if lib_path.exists():
        return str(lib_path)

    # Look in environment variable
    env_path = os.environ.get("GOSQLX_LIB_PATH")
    if env_path and os.path.exists(env_path):
        return env_path

    raise FileNotFoundError(
        f"GoSQLX shared library not found at {lib_path}. "
        f"Build it with: cd pkg/cbinding && ./build.sh"
    )


def _load_library():
    """Load the GoSQLX shared library."""
    lib_path = _get_lib_path()
    lib = ctypes.CDLL(lib_path)

    # Set up function signatures
    lib.gosqlx_parse.argtypes = [ctypes.c_char_p]
    lib.gosqlx_parse.restype = ctypes.c_char_p

    lib.gosqlx_validate.argtypes = [ctypes.c_char_p]
    lib.gosqlx_validate.restype = ctypes.c_char_p

    lib.gosqlx_extract_tables.argtypes = [ctypes.c_char_p]
    lib.gosqlx_extract_tables.restype = ctypes.c_char_p

    lib.gosqlx_free.argtypes = [ctypes.c_char_p]
    lib.gosqlx_free.restype = None

    lib.gosqlx_version.argtypes = []
    lib.gosqlx_version.restype = ctypes.c_char_p

    return lib


# Lazy-load library
_lib = None


def _get_lib():
    global _lib
    if _lib is None:
        _lib = _load_library()
    return _lib


def parse(sql: str) -> ParseResult:
    """Parse a SQL statement and return the result.

    Args:
        sql: The SQL string to parse.

    Returns:
        ParseResult with success status, statement count, and types.

    Raises:
        RuntimeError: If the shared library is not available.
    """
    lib = _get_lib()
    result_ptr = lib.gosqlx_parse(sql.encode("utf-8"))
    try:
        result_json = json.loads(result_ptr.decode("utf-8"))
    finally:
        lib.gosqlx_free(result_ptr)

    return ParseResult(
        success=result_json.get("success", False),
        statement_count=result_json.get("statement_count", 0),
        statement_types=result_json.get("statement_types", []),
        error=result_json.get("error"),
    )


def validate(sql: str) -> bool:
    """Validate SQL syntax.

    Args:
        sql: The SQL string to validate.

    Returns:
        True if the SQL is syntactically valid, False otherwise.
    """
    lib = _get_lib()
    result_ptr = lib.gosqlx_validate(sql.encode("utf-8"))
    try:
        result_json = json.loads(result_ptr.decode("utf-8"))
    finally:
        lib.gosqlx_free(result_ptr)

    return result_json.get("valid", False)


def extract_tables(sql: str) -> List[str]:
    """Extract table names from a SQL statement.

    Args:
        sql: The SQL string to analyze.

    Returns:
        List of table names referenced in the SQL.
    """
    lib = _get_lib()
    result_ptr = lib.gosqlx_extract_tables(sql.encode("utf-8"))
    try:
        result_json = json.loads(result_ptr.decode("utf-8"))
    finally:
        lib.gosqlx_free(result_ptr)

    if "error" in result_json:
        raise ValueError(f"Parse error: {result_json['error']}")

    return result_json.get("tables", [])


def version() -> str:
    """Get the GoSQLX library version.

    Returns:
        Version string (e.g., "1.7.0").
    """
    lib = _get_lib()
    result_ptr = lib.gosqlx_version()
    return result_ptr.decode("utf-8")
