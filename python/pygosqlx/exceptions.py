"""Custom exceptions for PyGoSQLX."""

from __future__ import annotations

from typing import Optional


class GoSQLXError(Exception):
    """Base exception for all GoSQLX errors."""

    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        line: Optional[int] = None,
        column: Optional[int] = None,
    ):
        self.message = message
        self.code = code
        self.line = line
        self.column = column
        super().__init__(str(self))

    def __str__(self) -> str:
        parts = []
        if self.code:
            parts.append(f"[{self.code}]")
        parts.append(self.message)
        if self.line is not None:
            loc = f"line {self.line}"
            if self.column is not None:
                loc += f", column {self.column}"
            parts.append(f"at {loc}")
        return " ".join(parts)


class ParseError(GoSQLXError):
    """Raised when SQL parsing fails."""

    pass


class FormatError(GoSQLXError):
    """Raised when SQL formatting fails."""

    pass


class ValidationError(GoSQLXError):
    """Raised when SQL validation fails."""

    pass
