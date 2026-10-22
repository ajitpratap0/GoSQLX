"""Tests for the pygosqlx 0.3.0 API: dialect=, lint(), security_scan(),
transpile() and dialects().

Tests in the ``TestOlderLibrary`` and ``TestArgumentValidation`` classes run
without the shared library. The rest exercise the real library and are skipped
when it is not built (run: cd pkg/cbinding && ./build.sh).
"""

import threading

import pytest

import pygosqlx
from pygosqlx import core
from pygosqlx import (
    GoSQLXError,
    FormatError,
    LintResult,
    LintViolation,
    Metadata,
    ParseError,
    ParseResult,
    SecurityFinding,
    SecurityScanResult,
    TranspileError,
    UnsupportedDialectError,
    ValidationResult,
)


def _lib_available() -> bool:
    """Check if pygosqlx can locate the GoSQLX shared library.

    Uses the package's own lookup (GOSQLX_LIB_PATH, then the bundled
    pygosqlx/lib/), so it also works against an installed wheel.
    """
    try:
        core._get_lib_path()
    except OSError:  # FileNotFoundError or unsupported platform
        return False
    return True


requires_lib = pytest.mark.skipif(
    not _lib_available(),
    reason="GoSQLX shared library not built (run: cd pkg/cbinding && ./build.sh)",
)

EXPECTED_DIALECTS = [
    "generic",
    "postgresql",
    "mysql",
    "mariadb",
    "sqlserver",
    "oracle",
    "sqlite",
    "snowflake",
    "bigquery",
    "redshift",
    "clickhouse",
]

SQLSERVER_SQL = "SELECT TOP 5 [id] FROM [dbo].[users]"
PORTABLE_SQL = "SELECT id, COUNT(*) FROM orders WHERE total > 10 GROUP BY id"

DIALECT_CALLS = [
    ("parse", lambda sql, d: pygosqlx.parse(sql, dialect=d)),
    ("validate", lambda sql, d: pygosqlx.validate(sql, dialect=d)),
    ("validate_detailed", lambda sql, d: pygosqlx.validate_detailed(sql, dialect=d)),
    ("format", lambda sql, d: pygosqlx.format(sql, dialect=d)),
    ("extract_tables", lambda sql, d: pygosqlx.extract_tables(sql, dialect=d)),
    ("extract_columns", lambda sql, d: pygosqlx.extract_columns(sql, dialect=d)),
    ("extract_functions", lambda sql, d: pygosqlx.extract_functions(sql, dialect=d)),
    ("extract_metadata", lambda sql, d: pygosqlx.extract_metadata(sql, dialect=d)),
]


# ---------------------------------------------------------------------------
# No shared library required
# ---------------------------------------------------------------------------


class TestPublicAPI:
    def test_new_names_exported(self):
        for name in [
            "lint",
            "security_scan",
            "transpile",
            "dialects",
            "LintResult",
            "LintViolation",
            "SecurityScanResult",
            "SecurityFinding",
            "TranspileError",
            "UnsupportedDialectError",
        ]:
            assert name in pygosqlx.__all__
            assert hasattr(pygosqlx, name)

    def test_version_is_0_3_0(self):
        assert pygosqlx.__version__ == "0.3.0"

    def test_dialect_is_keyword_only(self):
        with pytest.raises(TypeError):
            pygosqlx.parse("SELECT 1", "mysql")  # type: ignore[misc]

    def test_unsupported_dialect_error_hierarchy(self):
        err = UnsupportedDialectError("bad", code="E4002")
        assert isinstance(err, GoSQLXError)
        assert isinstance(err, ValueError)
        assert str(err) == "[E4002] bad"

    def test_transpile_error_hierarchy(self):
        assert issubclass(TranspileError, GoSQLXError)


class TestResultTypes:
    def test_lint_result_properties(self):
        v = LintViolation(
            rule="L007",
            rule_name="Keyword Case Consistency",
            severity="warning",
            message="m",
            line=1,
            column=1,
        )
        assert v.suggestion == "" and v.can_auto_fix is False
        r = LintResult(violations=[v])
        assert r.violation_count == 1
        assert not r.is_clean
        assert LintResult().is_clean
        assert LintResult().violation_count == 0

    def test_security_scan_result_properties(self):
        clean = SecurityScanResult()
        assert clean.is_clean and not clean.has_critical and not clean.has_high
        high = SecurityScanResult(total_count=1, high_count=1)
        assert not high.is_clean and high.has_high and not high.has_critical
        crit = SecurityScanResult(total_count=1, critical_count=1)
        assert crit.has_critical and crit.has_high

    def test_security_finding_defaults(self):
        f = SecurityFinding(severity="LOW", pattern="P", description="d")
        assert f.line is None and f.column is None
        assert f.risk == "" and f.sql == "" and f.suggestion == ""


class TestArgumentValidation:
    """Argument errors are raised before the library is touched."""

    @pytest.mark.parametrize("value", [0, -1, True, 1.5, "100"])
    def test_lint_rejects_bad_max_line_length(self, value):
        with pytest.raises(ValueError):
            pygosqlx.lint("SELECT 1", max_line_length=value)

    @pytest.mark.parametrize("name,call", DIALECT_CALLS)
    def test_non_string_dialect_rejected(self, name, call):
        with pytest.raises(TypeError):
            call("SELECT 1", 42)

    def test_lint_non_string_dialect_rejected(self):
        with pytest.raises(TypeError):
            pygosqlx.lint("SELECT 1", dialect=b"mysql")  # type: ignore[arg-type]

    def test_transpile_non_string_dialect_rejected(self):
        with pytest.raises(TypeError):
            pygosqlx.transpile("SELECT 1", 1, "mysql")  # type: ignore[arg-type]


class TestOlderLibrary:
    """A library built before 0.3.0 lacks the new exports: fail cleanly."""

    @pytest.fixture
    def old_library(self, monkeypatch):
        new_exports = set(core._DIALECT_EXPORTS.values()) | {
            "gosqlx_lint",
            "gosqlx_security_scan",
            "gosqlx_transpile",
            "gosqlx_dialects",
        }

        def fake_has_func(name):
            if name in new_exports:
                return False
            return True

        monkeypatch.setattr(core, "_has_func", fake_has_func)

    @pytest.mark.parametrize("name,call", DIALECT_CALLS)
    def test_dialect_argument_needs_new_library(self, old_library, name, call):
        with pytest.raises(GoSQLXError, match=r"_dialect not available"):
            call("SELECT 1", "mysql")

    @pytest.mark.parametrize(
        "symbol,call",
        [
            ("gosqlx_lint", lambda: pygosqlx.lint("SELECT 1")),
            ("gosqlx_security_scan", lambda: pygosqlx.security_scan("SELECT 1")),
            (
                "gosqlx_transpile",
                lambda: pygosqlx.transpile("SELECT 1", "mysql", "postgresql"),
            ),
            ("gosqlx_dialects", lambda: pygosqlx.dialects()),
        ],
    )
    def test_new_functions_need_new_library(self, old_library, symbol, call):
        with pytest.raises(GoSQLXError, match=f"{symbol} not available"):
            call()

    @requires_lib
    def test_calls_without_dialect_still_work(self, old_library):
        # dialect=None goes through the original exports.
        assert pygosqlx.parse("SELECT 1").statement_count == 1
        assert pygosqlx.validate("SELECT 1")
        assert pygosqlx.extract_tables("SELECT a FROM t") == ["t"]


# ---------------------------------------------------------------------------
# Shared library required
# ---------------------------------------------------------------------------


@requires_lib
class TestDialects:
    def test_dialects_list(self):
        assert pygosqlx.dialects() == EXPECTED_DIALECTS

    def test_dialects_returns_fresh_list(self):
        a = pygosqlx.dialects()
        a.append("x")
        assert "x" not in pygosqlx.dialects()


@requires_lib
class TestDialectArgument:
    @pytest.mark.parametrize("dialect", EXPECTED_DIALECTS)
    def test_every_dialect_parses_portable_sql(self, dialect):
        result = pygosqlx.parse(PORTABLE_SQL, dialect=dialect)
        assert result.statement_types == ["SELECT"]
        assert pygosqlx.validate(PORTABLE_SQL, dialect=dialect)
        assert pygosqlx.extract_tables(PORTABLE_SQL, dialect=dialect) == ["orders"]
        assert "COUNT" in pygosqlx.extract_functions(PORTABLE_SQL, dialect=dialect)

    @pytest.mark.parametrize("name,call", DIALECT_CALLS)
    def test_none_and_empty_match_default(self, name, call):
        sql = "SELECT u.id, UPPER(u.name) FROM users u WHERE u.id = 1"
        assert call(sql, None) == call(sql, "")

    def test_sqlserver_syntax(self):
        result = pygosqlx.parse(SQLSERVER_SQL, dialect="sqlserver")
        assert isinstance(result, ParseResult)
        assert result.statement_count == 1
        assert pygosqlx.validate(SQLSERVER_SQL, dialect="sqlserver")
        detail = pygosqlx.validate_detailed(SQLSERVER_SQL, dialect="sqlserver")
        assert isinstance(detail, ValidationResult) and detail.valid
        assert pygosqlx.extract_tables(SQLSERVER_SQL, dialect="sqlserver") == ["dbo.users"]
        assert pygosqlx.extract_columns(SQLSERVER_SQL, dialect="sqlserver") == ["id"]
        meta = pygosqlx.extract_metadata(SQLSERVER_SQL, dialect="sqlserver")
        assert isinstance(meta, Metadata)
        assert "TOP" in pygosqlx.format(SQLSERVER_SQL, dialect="sqlserver").upper()

    @pytest.mark.parametrize("name,call", DIALECT_CALLS)
    @pytest.mark.parametrize("dialect", ["fakesql", "MySQL", "postgres"])
    def test_unknown_dialect_raises(self, name, call, dialect):
        with pytest.raises(UnsupportedDialectError) as exc_info:
            call("SELECT 1", dialect)
        err = exc_info.value
        assert err.code == "E4002"
        assert dialect in err.message
        assert "valid dialects: generic" in err.message

    def test_unknown_dialect_is_value_error(self):
        with pytest.raises(ValueError):
            pygosqlx.validate("SELECT 1", dialect="nope")

    def test_invalid_sql_with_dialect(self):
        with pytest.raises(ParseError) as exc_info:
            pygosqlx.parse("SELECT * FROM", dialect="postgresql")
        assert not isinstance(exc_info.value, UnsupportedDialectError)
        assert not pygosqlx.validate("SELECT * FROM", dialect="mysql")
        detail = pygosqlx.validate_detailed("SELECT *\nFROM t WHERE", dialect="mysql")
        assert not detail.valid and detail.error and detail.error_line
        with pytest.raises(FormatError):
            pygosqlx.format("SELECT * FROM", dialect="mysql")
        for fn in (
            pygosqlx.extract_tables,
            pygosqlx.extract_columns,
            pygosqlx.extract_functions,
            pygosqlx.extract_metadata,
        ):
            with pytest.raises(ParseError):
                fn("SELECT * FROM", dialect="mysql")

    def test_empty_sql_with_dialect(self):
        with pytest.raises(ParseError):
            pygosqlx.parse("", dialect="mysql")
        assert not pygosqlx.validate("", dialect="mysql")
        with pytest.raises(FormatError):
            pygosqlx.format("", dialect="mysql")


@requires_lib
class TestLint:
    def test_lint_reports_violations(self):
        result = pygosqlx.lint("select id from users  ")
        assert isinstance(result, LintResult)
        rules = {v.rule for v in result.violations}
        assert {"L001", "L007"} <= rules
        assert result.violation_count == len(result.violations)
        for v in result.violations:
            assert isinstance(v, LintViolation)
            assert v.line >= 1 and v.column >= 1
            assert v.severity in {"error", "warning", "info"}
            assert v.rule_name and v.message
            # Only the `gosqlx lint` rule set (L001-L010) runs.
            assert v.rule <= "L010"

    def test_lint_clean_sql(self):
        result = pygosqlx.lint("SELECT id FROM users")
        assert result.is_clean
        assert result.violations == []

    def test_lint_empty_sql(self):
        assert pygosqlx.lint("").is_clean

    def test_lint_unparseable_sql_still_linted(self):
        result = pygosqlx.lint("select * from  ")
        assert any(v.rule == "L001" for v in result.violations)

    def test_lint_max_line_length(self):
        sql = "SELECT " + "a" * 60 + " FROM t"
        assert not any(v.rule == "L005" for v in pygosqlx.lint(sql).violations)
        result = pygosqlx.lint(sql, max_line_length=40)
        assert any(v.rule == "L005" for v in result.violations)

    def test_lint_dialect(self):
        result = pygosqlx.lint(SQLSERVER_SQL, dialect="sqlserver")
        assert isinstance(result, LintResult)

    def test_lint_unknown_dialect(self):
        with pytest.raises(UnsupportedDialectError):
            pygosqlx.lint("SELECT 1", dialect="fakesql")


@requires_lib
class TestSecurityScan:
    def test_detects_tautology(self):
        result = pygosqlx.security_scan("SELECT * FROM users WHERE id = 1 OR 1=1 --")
        assert isinstance(result, SecurityScanResult)
        assert not result.is_clean
        assert result.has_critical and result.has_high
        assert result.total_count == len(result.findings)
        assert (
            result.critical_count
            + result.high_count
            + result.medium_count
            + result.low_count
            == result.total_count
        )
        patterns = {f.pattern for f in result.findings}
        assert "TAUTOLOGY" in patterns
        for f in result.findings:
            assert isinstance(f, SecurityFinding)
            assert f.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
            assert f.description

    def test_clean_query(self):
        result = pygosqlx.security_scan("SELECT id FROM users WHERE id = $1")
        assert result.is_clean
        assert result.findings == []

    def test_empty_input_is_clean(self):
        assert pygosqlx.security_scan("").is_clean

    def test_unparseable_payload_scanned(self):
        assert not pygosqlx.security_scan("'; DROP TABLE users; --").is_clean


@requires_lib
class TestTranspile:
    def test_mysql_to_postgresql(self):
        out = pygosqlx.transpile(
            "CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY)", "mysql", "postgresql"
        )
        assert "SERIAL" in out.upper()
        assert "AUTO_INCREMENT" not in out.upper()

    def test_passthrough_pair(self):
        out = pygosqlx.transpile("SELECT a FROM t", "generic", "snowflake")
        assert out.upper().startswith("SELECT")

    @pytest.mark.parametrize(
        "src,dst", [("fakesql", "mysql"), ("mysql", "postgres"), ("", "mysql")]
    )
    def test_bad_dialects(self, src, dst):
        with pytest.raises(UnsupportedDialectError):
            pygosqlx.transpile("SELECT 1", src, dst)

    def test_none_dialect(self):
        with pytest.raises(UnsupportedDialectError):
            pygosqlx.transpile("SELECT 1", None, "mysql")  # type: ignore[arg-type]

    def test_invalid_sql(self):
        with pytest.raises(TranspileError):
            pygosqlx.transpile("SELECT * FROM", "mysql", "postgresql")

    def test_empty_sql(self):
        with pytest.raises(TranspileError):
            pygosqlx.transpile("", "mysql", "postgresql")


@requires_lib
class TestNewFunctionsThreadSafety:
    def test_concurrent_calls(self):
        errors = []

        def worker(dialect):
            try:
                for _ in range(50):
                    pygosqlx.parse(PORTABLE_SQL, dialect=dialect)
                    pygosqlx.lint("select a from t", dialect=dialect)
                    pygosqlx.security_scan("SELECT * FROM t WHERE 1=1 OR 'a'='a'")
                    pygosqlx.transpile("SELECT a FROM t", "mysql", dialect)
                    pygosqlx.dialects()
            except Exception as exc:  # pragma: no cover - reported below
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(d,)) for d in EXPECTED_DIALECTS
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
