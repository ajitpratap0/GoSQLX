"""Test Python type definitions without requiring the shared library."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pygosqlx.core import ParseResult, ValidationResult


def test_parse_result():
    r = ParseResult(success=True, statement_count=1, statement_types=["SELECT"])
    assert r.success is True
    assert r.statement_count == 1
    assert r.statement_types == ["SELECT"]
    assert r.error is None


def test_parse_result_with_error():
    r = ParseResult(
        success=False, statement_count=0, statement_types=[], error="syntax error"
    )
    assert r.success is False
    assert r.error == "syntax error"


def test_parse_result_multiple_statements():
    r = ParseResult(
        success=True,
        statement_count=3,
        statement_types=["SELECT", "INSERT", "UPDATE"],
    )
    assert r.success is True
    assert r.statement_count == 3
    assert len(r.statement_types) == 3
    assert r.statement_types[0] == "SELECT"
    assert r.statement_types[1] == "INSERT"
    assert r.statement_types[2] == "UPDATE"


def test_validation_result():
    r = ValidationResult(valid=True)
    assert r.valid is True
    assert r.error is None


def test_validation_result_invalid():
    r = ValidationResult(valid=False, error="unexpected token")
    assert r.valid is False
    assert r.error == "unexpected token"


def test_parse_result_default_error():
    """Verify error defaults to None when not provided."""
    r = ParseResult(success=True, statement_count=0, statement_types=[])
    assert r.error is None


def test_validation_result_default_error():
    """Verify error defaults to None when not provided."""
    r = ValidationResult(valid=True)
    assert r.error is None
