"""Core module providing Python bindings to GoSQLX via ctypes.

This module loads the GoSQLX shared library (built from Go with cgo) and
provides a Pythonic API for SQL parsing, validation, formatting, and
metadata extraction, plus dialect-aware variants, linting, SQL injection
scanning, and dialect transpilation.

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
from types import MappingProxyType
from typing import Any, Dict, List, Optional

try:
    import orjson
except ImportError:
    _loads = json.loads
    _DECODER = "json"
else:
    _loads = orjson.loads
    _DECODER = "orjson"

from pygosqlx.exceptions import (
    FormatError,
    GoSQLXError,
    ParseError,
    TranspileError,
    UnsupportedDialectError,
)


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


@dataclass
class LintViolation:
    """A single lint rule violation reported by :func:`lint`."""

    rule: str
    rule_name: str
    severity: str
    message: str
    line: int
    column: int
    suggestion: str = ""
    can_auto_fix: bool = False


@dataclass
class LintResult:
    """Result of linting SQL with :func:`lint`."""

    violations: List[LintViolation] = field(default_factory=list)

    @property
    def violation_count(self) -> int:
        """Number of violations found."""
        return len(self.violations)

    @property
    def is_clean(self) -> bool:
        """True when no rule reported a violation."""
        return not self.violations


@dataclass
class SecurityFinding:
    """A potential SQL injection pattern reported by :func:`security_scan`."""

    severity: str
    pattern: str
    description: str
    risk: str = ""
    line: Optional[int] = None
    column: Optional[int] = None
    sql: str = ""
    suggestion: str = ""


@dataclass
class SecurityScanResult:
    """Result of scanning SQL with :func:`security_scan`."""

    findings: List[SecurityFinding] = field(default_factory=list)
    total_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    @property
    def is_clean(self) -> bool:
        """True when no injection pattern was found."""
        return self.total_count == 0

    @property
    def has_critical(self) -> bool:
        """True when at least one CRITICAL finding was reported."""
        return self.critical_count > 0

    @property
    def has_high(self) -> bool:
        """True when at least one HIGH or CRITICAL finding was reported."""
        return self.critical_count + self.high_count > 0


# ---------------------------------------------------------------------------
# Library loading
# ---------------------------------------------------------------------------

_bindings = None
_lib_lock = threading.Lock()

# Original single-argument exports mapped to their dialect-aware variants.
_DIALECT_EXPORTS = {
    "gosqlx_parse": "gosqlx_parse_dialect",
    "gosqlx_validate": "gosqlx_validate_dialect",
    "gosqlx_format": "gosqlx_format_dialect",
    "gosqlx_extract_tables": "gosqlx_extract_tables_dialect",
    "gosqlx_extract_columns": "gosqlx_extract_columns_dialect",
    "gosqlx_extract_functions": "gosqlx_extract_functions_dialect",
    "gosqlx_extract_metadata": "gosqlx_extract_metadata_dialect",
}

# error_code the library reports for an unknown dialect name.
_ERR_UNSUPPORTED_DIALECT = "E4002"


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
        f"No prebuilt wheel bundles it for this platform; build it from "
        f"source (cd pkg/cbinding && ./build.sh) and reinstall, or set "
        f"GOSQLX_LIB_PATH. See 'Building from source' in "
        f"https://github.com/ajitpratap0/GoSQLX/blob/main/python/README.md"
    )


@dataclass(frozen=True)
class _Bindings:
    """One immutable set of exports and their owning library/free function."""

    __slots__ = (
        'lib',
        'free',
        'exports',
        'gosqlx_parse',
        'gosqlx_validate',
        'gosqlx_extract_tables',
        'gosqlx_version',
        'gosqlx_format',
        'gosqlx_extract_columns',
        'gosqlx_extract_functions',
        'gosqlx_extract_metadata',
        'gosqlx_parse_dialect',
        'gosqlx_validate_dialect',
        'gosqlx_format_dialect',
        'gosqlx_extract_tables_dialect',
        'gosqlx_extract_columns_dialect',
        'gosqlx_extract_functions_dialect',
        'gosqlx_extract_metadata_dialect',
        'gosqlx_lint',
        'gosqlx_security_scan',
        'gosqlx_transpile',
        'gosqlx_dialects',
    )

    lib: Any
    free: Any
    exports: Any
    gosqlx_parse: Any
    gosqlx_validate: Any
    gosqlx_extract_tables: Any
    gosqlx_version: Any
    gosqlx_format: Any
    gosqlx_extract_columns: Any
    gosqlx_extract_functions: Any
    gosqlx_extract_metadata: Any
    gosqlx_parse_dialect: Any
    gosqlx_validate_dialect: Any
    gosqlx_format_dialect: Any
    gosqlx_extract_tables_dialect: Any
    gosqlx_extract_columns_dialect: Any
    gosqlx_extract_functions_dialect: Any
    gosqlx_extract_metadata_dialect: Any
    gosqlx_lint: Any
    gosqlx_security_scan: Any
    gosqlx_transpile: Any
    gosqlx_dialects: Any


def _load_library() -> _Bindings:
    """Resolve and configure every export once before publishing the set."""
    lib = ctypes.CDLL(_get_lib_path())

    def bind(name: str, argtypes: list, optional: bool = False) -> Any:
        try:
            func = getattr(lib, name)
        except AttributeError:
            if optional:
                return None
            raise
        func.argtypes = argtypes
        func.restype = None if name == "gosqlx_free" else ctypes.c_void_p
        return func

    free = bind("gosqlx_free", [ctypes.c_void_p])
    exports = {}
    required = {"gosqlx_parse", "gosqlx_validate", "gosqlx_extract_tables", "gosqlx_version"}
    for name in _Bindings.__slots__[3:]:
        if name in {"gosqlx_version", "gosqlx_dialects"}:
            args = []
        elif name == "gosqlx_transpile":
            args = [ctypes.c_char_p] * 3
        elif name.endswith("_dialect") or name == "gosqlx_lint":
            args = [ctypes.c_char_p] * 2
        else:
            args = [ctypes.c_char_p]
        exports[name] = bind(name, args, optional=name not in required)
    return _Bindings(lib=lib, free=free, exports=MappingProxyType(exports), **exports)


def _get_bindings() -> _Bindings:
    """Publish a complete binding set with thread-safe lazy initialization."""
    global _bindings
    if _bindings is None:
        with _lib_lock:
            if _bindings is None:
                _bindings = _load_library()
    return _bindings


def _get_lib() -> ctypes.CDLL:
    """Return the loaded CDLL for compatibility with existing callers."""
    bindings = _bindings
    if bindings is None:
        bindings = _get_bindings()
    return bindings.lib


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _call_and_decode(bindings: _Bindings, func: Any, *args: Any) -> Dict[str, Any]:
    """Copy a native JSON result and free it with its originating library."""
    result_ptr = func(*args)
    if result_ptr is None:
        raise GoSQLXError("C function returned NULL — possible out-of-memory")
    try:
        result_bytes = ctypes.string_at(result_ptr)
    finally:
        bindings.free(result_ptr)
    return _loads(result_bytes)


def _has_func(name: str) -> bool:
    """Check the cached export set without resolving a symbol again."""
    return _get_bindings().exports.get(name) is not None


def _require_func(name: str, bindings: Optional[_Bindings] = None) -> Any:
    """Return an export, or preserve the older-library compatibility error."""
    if bindings is None:
        bindings = _get_bindings()
    func = bindings.exports.get(name)
    if func is None:
        raise GoSQLXError(
            f"{name} not available in this library build. "
            "Rebuild the shared library with the latest cbinding."
        )
    return func


def _check_dialect_arg(dialect: Optional[str], arg: str = "dialect") -> None:
    if dialect is not None and not isinstance(dialect, str):
        raise TypeError(f"{arg} must be a str or None, not {type(dialect).__name__}")


def _check_dialect_error(data: Dict[str, Any]) -> None:
    """Raise UnsupportedDialectError when the library rejected the dialect."""
    if data.get("error_code") == _ERR_UNSUPPORTED_DIALECT:
        raise UnsupportedDialectError(
            message=data.get("error", "unsupported dialect"),
            code=_ERR_UNSUPPORTED_DIALECT,
        )


def _call_sql(name: str, sql: str, dialect: Optional[str]) -> Dict[str, Any]:
    """Call a SQL export, or its ``_dialect`` variant when a dialect is given.

    Without a dialect the original export is used, so these calls keep working
    against libraries built before the dialect-aware exports existed. With a
    dialect, an older library raises GoSQLXError, and an unknown dialect raises
    UnsupportedDialectError.
    """
    _check_dialect_arg(dialect)
    bindings = _bindings
    if bindings is None:
        bindings = _get_bindings()
    if dialect is None:
        func = bindings.gosqlx_parse if name == "gosqlx_parse" else bindings.exports[name]
        if func is None:
            _require_func(name, bindings)
        return _call_and_decode(bindings, func, sql.encode("utf-8"))
    dialect_name = _DIALECT_EXPORTS[name]
    func = bindings.exports[dialect_name]
    if func is None:
        _require_func(dialect_name, bindings)
    data = _call_and_decode(
        bindings, func, sql.encode("utf-8"), dialect.encode("utf-8")
    )
    _check_dialect_error(data)
    return data


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


def _check_parse_error(data: Dict[str, Any]) -> None:
    """Check a JSON response for parse errors and raise if found.

    Detects errors using both the ``success`` flag (used by gosqlx_parse)
    and the ``error`` string (used by extract_* functions).  This ensures
    every public function that should raise on invalid SQL uses the same
    detection logic.
    """
    has_error_field = bool(data.get("error"))
    has_success_false = "success" in data and not data["success"]

    if has_error_field or has_success_false:
        raise _parse_error_from_json(data)


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


def parse(sql: str, *, dialect: Optional[str] = None) -> ParseResult:
    """Parse a SQL statement and return the result.

    Args:
        sql: The SQL string to parse.
        dialect: Optional SQL dialect name (see :func:`dialects`), e.g.
            ``"postgresql"`` or ``"sqlserver"``. ``None`` uses the default
            parser.

    Returns:
        ParseResult with statement_count and statement_types.

    Raises:
        ParseError: If the SQL is syntactically invalid.
        UnsupportedDialectError: If ``dialect`` is not a supported dialect.
        GoSQLXError: If the shared library is not available, returns NULL,
            or (with ``dialect``) predates dialect support.
    """
    data = _call_sql("gosqlx_parse", sql, dialect)

    _check_parse_error(data)

    return ParseResult(
        statement_count=data.get("statement_count", 0),
        statement_types=data.get("statement_types", []),
    )


def validate(sql: str, *, dialect: Optional[str] = None) -> bool:
    """Validate SQL syntax.

    Args:
        sql: The SQL string to validate.
        dialect: Optional SQL dialect name (see :func:`dialects`).

    Returns:
        True if the SQL is syntactically valid, False otherwise.

    Raises:
        UnsupportedDialectError: If ``dialect`` is not a supported dialect.
    """
    data = _call_sql("gosqlx_validate", sql, dialect)
    return data.get("valid", False)


def validate_detailed(sql: str, *, dialect: Optional[str] = None) -> ValidationResult:
    """Validate SQL syntax with detailed error information.

    Args:
        sql: The SQL string to validate.
        dialect: Optional SQL dialect name (see :func:`dialects`).

    Returns:
        ValidationResult with valid flag and optional error details.

    Raises:
        UnsupportedDialectError: If ``dialect`` is not a supported dialect.
    """
    data = _call_sql("gosqlx_validate", sql, dialect)
    return ValidationResult(
        valid=data.get("valid", False),
        error=data.get("error") or None,
        error_line=data.get("error_line"),
        error_column=data.get("error_column"),
    )


def format(sql: str, *, dialect: Optional[str] = None) -> str:
    """Format a SQL statement for readability.

    Args:
        sql: The SQL string to format.
        dialect: Optional SQL dialect name (see :func:`dialects`). The SQL is
            parsed with this dialect and rendered for it.

    Returns:
        The formatted SQL string.

    Raises:
        FormatError: If the SQL cannot be formatted (e.g., invalid syntax).
        UnsupportedDialectError: If ``dialect`` is not a supported dialect.
        GoSQLXError: If the gosqlx_format function is not available.
    """
    data = _call_sql("gosqlx_format", sql, dialect)

    if data.get("error"):
        raise FormatError(message=data["error"])

    return data.get("formatted", data.get("result", sql))


def extract_tables(sql: str, *, dialect: Optional[str] = None) -> List[str]:
    """Extract table names from a SQL statement.

    Args:
        sql: The SQL string to analyze.
        dialect: Optional SQL dialect name (see :func:`dialects`).

    Returns:
        List of table names referenced in the SQL.

    Raises:
        ParseError: If the SQL is syntactically invalid.
        UnsupportedDialectError: If ``dialect`` is not a supported dialect.
    """
    data = _call_sql("gosqlx_extract_tables", sql, dialect)

    _check_parse_error(data)

    return data.get("tables", [])


def extract_columns(sql: str, *, dialect: Optional[str] = None) -> List[str]:
    """Extract column names from a SQL statement.

    Args:
        sql: The SQL string to analyze.
        dialect: Optional SQL dialect name (see :func:`dialects`).

    Returns:
        List of column names referenced in the SQL.

    Raises:
        ParseError: If the SQL is syntactically invalid.
        UnsupportedDialectError: If ``dialect`` is not a supported dialect.
        GoSQLXError: If the gosqlx_extract_columns function is not available.
    """
    data = _call_sql("gosqlx_extract_columns", sql, dialect)

    _check_parse_error(data)

    return data.get("columns", [])


def extract_functions(sql: str, *, dialect: Optional[str] = None) -> List[str]:
    """Extract function names from a SQL statement.

    Args:
        sql: The SQL string to analyze.
        dialect: Optional SQL dialect name (see :func:`dialects`).

    Returns:
        List of function names used in the SQL.

    Raises:
        ParseError: If the SQL is syntactically invalid.
        UnsupportedDialectError: If ``dialect`` is not a supported dialect.
        GoSQLXError: If the gosqlx_extract_functions function is not available.
    """
    data = _call_sql("gosqlx_extract_functions", sql, dialect)

    _check_parse_error(data)

    return data.get("functions", [])


def extract_metadata(sql: str, *, dialect: Optional[str] = None) -> Metadata:
    """Extract comprehensive metadata from a SQL statement.

    This returns tables, columns, functions, and their qualified variants
    in a single call.

    Args:
        sql: The SQL string to analyze.
        dialect: Optional SQL dialect name (see :func:`dialects`).

    Returns:
        Metadata object containing all extracted information.

    Raises:
        ParseError: If the SQL is syntactically invalid.
        UnsupportedDialectError: If ``dialect`` is not a supported dialect.
        GoSQLXError: If the gosqlx_extract_metadata function is not available.
    """
    data = _call_sql("gosqlx_extract_metadata", sql, dialect)

    _check_parse_error(data)

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


def lint(
    sql: str,
    *,
    dialect: Optional[str] = None,
    max_line_length: Optional[int] = None,
) -> LintResult:
    """Lint SQL with the rule set of the ``gosqlx lint`` CLI command.

    The rules are L001-L010 (whitespace, indentation, line length, column
    alignment, keyword case, comma placement, aliasing). SQL that does not
    parse is still linted by the text and token rules.

    Args:
        sql: The SQL string to lint.
        dialect: Optional SQL dialect name (see :func:`dialects`).
        max_line_length: Maximum line length for rule L005 (default 100,
            like ``gosqlx lint --max-length``). Must be a positive int.

    Returns:
        LintResult with the list of violations.

    Raises:
        ValueError: If ``max_line_length`` is not a positive int.
        UnsupportedDialectError: If ``dialect`` is not a supported dialect.
        GoSQLXError: If the library predates gosqlx_lint or linting fails.
    """
    _check_dialect_arg(dialect)
    options: Dict[str, Any] = {}
    if dialect is not None:
        options["dialect"] = dialect
    if max_line_length is not None:
        if (
            isinstance(max_line_length, bool)
            or not isinstance(max_line_length, int)
            or max_line_length <= 0
        ):
            raise ValueError(
                f"max_line_length must be a positive int, got {max_line_length!r}"
            )
        options["max_line_length"] = max_line_length

    bindings = _get_bindings()
    func = _require_func("gosqlx_lint", bindings)
    data = _call_and_decode(
        bindings, func, sql.encode("utf-8"), json.dumps(options).encode("utf-8")
    )
    _check_dialect_error(data)
    if not data.get("success", False):
        raise GoSQLXError(
            message=data.get("error", "lint failed"),
            code=data.get("error_code") or None,
        )

    violations = [
        LintViolation(
            rule=v.get("rule", ""),
            rule_name=v.get("rule_name", ""),
            severity=v.get("severity", ""),
            message=v.get("message", ""),
            line=v.get("line", 0),
            column=v.get("column", 0),
            suggestion=v.get("suggestion", ""),
            can_auto_fix=bool(v.get("can_auto_fix", False)),
        )
        for v in data.get("violations") or []
        if isinstance(v, dict)
    ]
    return LintResult(violations=violations)


def security_scan(sql: str) -> SecurityScanResult:
    """Scan SQL for SQL injection patterns.

    Detects tautologies (``OR 1=1``), comment bypasses, stacked queries,
    UNION-based injection, time-based and out-of-band techniques, and
    dangerous functions. The scan works on the raw text, so payloads that are
    not valid SQL are scanned too; empty input is clean.

    Args:
        sql: The SQL string to scan.

    Returns:
        SecurityScanResult with findings and per-severity counts.

    Raises:
        GoSQLXError: If the library predates gosqlx_security_scan.
    """
    bindings = _get_bindings()
    func = _require_func("gosqlx_security_scan", bindings)
    data = _call_and_decode(bindings, func, sql.encode("utf-8"))
    if data.get("error"):
        raise GoSQLXError(message=data["error"])

    findings = [
        SecurityFinding(
            severity=f.get("severity", ""),
            pattern=f.get("pattern", ""),
            description=f.get("description", ""),
            risk=f.get("risk", ""),
            line=f.get("line"),
            column=f.get("column"),
            sql=f.get("sql", ""),
            suggestion=f.get("suggestion", ""),
        )
        for f in data.get("findings") or []
        if isinstance(f, dict)
    ]
    return SecurityScanResult(
        findings=findings,
        total_count=data.get("total_count", len(findings)),
        critical_count=data.get("critical_count", 0),
        high_count=data.get("high_count", 0),
        medium_count=data.get("medium_count", 0),
        low_count=data.get("low_count", 0),
    )


def transpile(sql: str, from_dialect: str, to_dialect: str) -> str:
    """Convert SQL from one dialect to another.

    Dedicated rewrites exist for MySQL -> PostgreSQL, PostgreSQL -> MySQL and
    PostgreSQL -> SQLite (e.g. ``AUTO_INCREMENT`` <-> ``SERIAL``); other pairs
    are parsed with the source dialect and re-rendered without rewrites.

    Args:
        sql: The SQL string to convert.
        from_dialect: Source dialect name (see :func:`dialects`).
        to_dialect: Target dialect name (see :func:`dialects`).

    Returns:
        The transpiled SQL.

    Raises:
        UnsupportedDialectError: If either dialect is missing or unsupported.
        TranspileError: If the SQL cannot be parsed or rewritten.
        GoSQLXError: If the library predates gosqlx_transpile.
    """
    _check_dialect_arg(from_dialect, "from_dialect")
    _check_dialect_arg(to_dialect, "to_dialect")
    for value, arg in ((from_dialect, "from_dialect"), (to_dialect, "to_dialect")):
        if not value:
            raise UnsupportedDialectError(
                message=f"{arg} is required", code=_ERR_UNSUPPORTED_DIALECT
            )
    bindings = _get_bindings()
    func = _require_func("gosqlx_transpile", bindings)
    data = _call_and_decode(
        bindings, func,
        sql.encode("utf-8"),
        (from_dialect or "").encode("utf-8"),
        (to_dialect or "").encode("utf-8"),
    )
    _check_dialect_error(data)
    if not data.get("success", False):
        raise TranspileError(message=data.get("error", "transpile failed"))
    return data.get("sql", "")


def dialects() -> List[str]:
    """List the SQL dialect names accepted by every ``dialect`` argument.

    Returns:
        Dialect names such as ``["generic", "postgresql", "mysql", ...]``.

    Raises:
        GoSQLXError: If the library predates gosqlx_dialects.
    """
    bindings = _get_bindings()
    func = _require_func("gosqlx_dialects", bindings)
    data = _call_and_decode(bindings, func)
    return list(data.get("dialects", []))


def version() -> str:
    """Get the GoSQLX library version.

    Returns:
        Version string (e.g., "1.7.0").
    """
    bindings = _get_bindings()
    result_ptr = bindings.gosqlx_version()
    if result_ptr is None:
        raise GoSQLXError("gosqlx_version returned NULL")
    try:
        result_bytes = ctypes.string_at(result_ptr)
        return result_bytes.decode("utf-8")
    finally:
        bindings.free(result_ptr)
