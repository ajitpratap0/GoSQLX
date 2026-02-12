"""Test Python type definitions without requiring the shared library.

These tests validate the dataclass constructors, field defaults, string
representations, and exception inheritance hierarchy. They run purely in
Python with no shared library dependency.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pygosqlx.core import (
    Metadata,
    ParseResult,
    QualifiedName,
    ValidationResult,
)
from pygosqlx.exceptions import (
    FormatError,
    GoSQLXError,
    ParseError,
    ValidationError,
)


# ---------------------------------------------------------------------------
# ParseResult tests
# ---------------------------------------------------------------------------


class TestParseResult:
    def test_construction(self):
        r = ParseResult(statement_count=1, statement_types=["SELECT"])
        assert r.statement_count == 1
        assert r.statement_types == ["SELECT"]

    def test_multiple_statements(self):
        r = ParseResult(
            statement_count=3,
            statement_types=["SELECT", "INSERT", "UPDATE"],
        )
        assert r.statement_count == 3
        assert len(r.statement_types) == 3
        assert r.statement_types[0] == "SELECT"
        assert r.statement_types[1] == "INSERT"
        assert r.statement_types[2] == "UPDATE"

    def test_empty_result(self):
        r = ParseResult(statement_count=0, statement_types=[])
        assert r.statement_count == 0
        assert r.statement_types == []

    def test_equality(self):
        a = ParseResult(statement_count=1, statement_types=["SELECT"])
        b = ParseResult(statement_count=1, statement_types=["SELECT"])
        assert a == b

    def test_inequality(self):
        a = ParseResult(statement_count=1, statement_types=["SELECT"])
        b = ParseResult(statement_count=2, statement_types=["SELECT", "INSERT"])
        assert a != b


# ---------------------------------------------------------------------------
# ValidationResult tests
# ---------------------------------------------------------------------------


class TestValidationResult:
    def test_valid(self):
        r = ValidationResult(valid=True)
        assert r.valid is True
        assert r.error is None
        assert r.error_line is None
        assert r.error_column is None

    def test_invalid_with_error(self):
        r = ValidationResult(valid=False, error="unexpected token")
        assert r.valid is False
        assert r.error == "unexpected token"

    def test_invalid_with_location(self):
        r = ValidationResult(
            valid=False,
            error="unexpected token",
            error_line=5,
            error_column=12,
        )
        assert r.valid is False
        assert r.error == "unexpected token"
        assert r.error_line == 5
        assert r.error_column == 12

    def test_defaults(self):
        r = ValidationResult(valid=True)
        assert r.error is None
        assert r.error_line is None
        assert r.error_column is None

    def test_equality(self):
        a = ValidationResult(valid=True)
        b = ValidationResult(valid=True)
        assert a == b


# ---------------------------------------------------------------------------
# QualifiedName tests
# ---------------------------------------------------------------------------


class TestQualifiedName:
    def test_simple_name(self):
        q = QualifiedName(name="users")
        assert q.name == "users"
        assert q.schema == ""
        assert q.table == ""
        assert str(q) == "users"

    def test_schema_qualified(self):
        q = QualifiedName(name="users", schema="public")
        assert str(q) == "public.users"

    def test_table_qualified(self):
        q = QualifiedName(name="email", table="u")
        assert str(q) == "u.email"

    def test_fully_qualified(self):
        q = QualifiedName(name="users", schema="mydb", table="public")
        assert str(q) == "mydb.public.users"

    def test_empty_name(self):
        q = QualifiedName(name="")
        assert str(q) == ""

    def test_defaults(self):
        q = QualifiedName(name="test")
        assert q.schema == ""
        assert q.table == ""

    def test_equality(self):
        a = QualifiedName(name="users", schema="public")
        b = QualifiedName(name="users", schema="public")
        assert a == b

    def test_inequality(self):
        a = QualifiedName(name="users", schema="public")
        b = QualifiedName(name="orders", schema="public")
        assert a != b


# ---------------------------------------------------------------------------
# Metadata tests
# ---------------------------------------------------------------------------


class TestMetadata:
    def test_default_construction(self):
        m = Metadata()
        assert m.tables == []
        assert m.columns == []
        assert m.functions == []
        assert m.tables_qualified == []
        assert m.columns_qualified == []

    def test_with_data(self):
        m = Metadata(
            tables=["users", "orders"],
            columns=["name", "email"],
            functions=["COUNT"],
            tables_qualified=[QualifiedName(name="users", schema="public")],
            columns_qualified=[QualifiedName(name="name", table="u")],
        )
        assert m.tables == ["users", "orders"]
        assert m.columns == ["name", "email"]
        assert m.functions == ["COUNT"]
        assert len(m.tables_qualified) == 1
        assert m.tables_qualified[0].name == "users"
        assert len(m.columns_qualified) == 1
        assert m.columns_qualified[0].table == "u"

    def test_default_factory_isolation(self):
        """Verify that default_factory creates independent lists per instance."""
        m1 = Metadata()
        m2 = Metadata()
        m1.tables.append("users")
        assert m2.tables == []  # Should not be affected


# ---------------------------------------------------------------------------
# Exception tests
# ---------------------------------------------------------------------------


class TestGoSQLXError:
    def test_basic_message(self):
        e = GoSQLXError("something went wrong")
        assert e.message == "something went wrong"
        assert e.code is None
        assert e.line is None
        assert e.column is None
        assert str(e) == "something went wrong"

    def test_with_code(self):
        e = GoSQLXError("bad syntax", code="E2001")
        assert str(e) == "[E2001] bad syntax"

    def test_with_location(self):
        e = GoSQLXError("unexpected token", line=3, column=7)
        assert str(e) == "unexpected token at line 3, column 7"

    def test_with_code_and_location(self):
        e = GoSQLXError("unexpected token", code="E2001", line=3, column=7)
        assert str(e) == "[E2001] unexpected token at line 3, column 7"

    def test_with_line_only(self):
        e = GoSQLXError("unexpected token", line=5)
        assert str(e) == "unexpected token at line 5"

    def test_is_exception(self):
        e = GoSQLXError("test")
        assert isinstance(e, Exception)

    def test_can_be_raised_and_caught(self):
        try:
            raise GoSQLXError("test error", code="E1000")
        except GoSQLXError as e:
            assert e.message == "test error"
            assert e.code == "E1000"


class TestParseError:
    def test_inherits_from_gosqlx_error(self):
        e = ParseError("parse failed")
        assert isinstance(e, GoSQLXError)
        assert isinstance(e, Exception)

    def test_can_be_caught_as_base(self):
        try:
            raise ParseError("unexpected EOF")
        except GoSQLXError as e:
            assert e.message == "unexpected EOF"

    def test_str_representation(self):
        e = ParseError("unexpected token", code="E2001", line=1, column=15)
        assert str(e) == "[E2001] unexpected token at line 1, column 15"


class TestFormatError:
    def test_inherits_from_gosqlx_error(self):
        e = FormatError("format failed")
        assert isinstance(e, GoSQLXError)
        assert isinstance(e, Exception)

    def test_can_be_caught_as_base(self):
        try:
            raise FormatError("cannot format invalid SQL")
        except GoSQLXError:
            pass  # Should be caught


class TestValidationError:
    def test_inherits_from_gosqlx_error(self):
        e = ValidationError("validation failed")
        assert isinstance(e, GoSQLXError)
        assert isinstance(e, Exception)

    def test_can_be_caught_as_base(self):
        try:
            raise ValidationError("invalid SQL")
        except GoSQLXError:
            pass  # Should be caught


class TestExceptionHierarchy:
    """Test the full exception inheritance hierarchy."""

    def test_parse_error_hierarchy(self):
        e = ParseError("test")
        assert isinstance(e, ParseError)
        assert isinstance(e, GoSQLXError)
        assert isinstance(e, Exception)
        assert isinstance(e, BaseException)

    def test_format_error_hierarchy(self):
        e = FormatError("test")
        assert isinstance(e, FormatError)
        assert isinstance(e, GoSQLXError)
        assert isinstance(e, Exception)

    def test_validation_error_hierarchy(self):
        e = ValidationError("test")
        assert isinstance(e, ValidationError)
        assert isinstance(e, GoSQLXError)
        assert isinstance(e, Exception)

    def test_specific_catch_does_not_catch_sibling(self):
        """ParseError catch should not catch FormatError."""
        caught = False
        try:
            raise FormatError("format issue")
        except ParseError:
            caught = True
        except GoSQLXError:
            pass  # Expected path
        assert not caught, "ParseError handler should not catch FormatError"

    def test_all_exceptions_share_fields(self):
        """All exception subclasses should have message, code, line, column."""
        for cls in [ParseError, FormatError, ValidationError]:
            e = cls("msg", code="C1", line=1, column=2)
            assert e.message == "msg"
            assert e.code == "C1"
            assert e.line == 1
            assert e.column == 2
