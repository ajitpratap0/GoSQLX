// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package parser_test

import (
	"errors"
	"strings"
	"testing"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// parseSQL is a helper that tokenises and parses a SQL string, returning the
// resulting error. It ignores the AST on purpose; these tests only care about
// the structure of the returned error.
func parseSQL(t *testing.T, sql string) error {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return err
	}

	p := parser.GetParser()
	defer parser.PutParser(p)

	_, perr := p.ParseFromModelTokens(tokens)
	return perr
}

// parseSQLWithDialect is a helper that parses SQL with a specific dialect.
func parseSQLWithDialect(t *testing.T, sql string, dialect keywords.SQLDialect) error {
	t.Helper()
	_, err := parser.ParseWithDialect(sql, dialect)
	return err
}

// assertStructuredError verifies that err is a *goerrors.Error with the given
// error code.  It also checks that the error message is non-empty (so we don't
// silently accept a malformed builder call).
func assertStructuredError(t *testing.T, err error, wantCode goerrors.ErrorCode) *goerrors.Error {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %s, got nil", wantCode)
	}
	var structured *goerrors.Error
	if !errors.As(err, &structured) {
		t.Fatalf("expected *goerrors.Error, got %T: %v", err, err)
	}
	if structured.Code != wantCode {
		t.Errorf("error code = %s, want %s (msg: %s)", structured.Code, wantCode, structured.Message)
	}
	if structured.Message == "" {
		t.Errorf("structured error has empty message")
	}
	return structured
}

// TestInvalidSyntaxErrors covers sites that convert to InvalidSyntaxError
// (E2004). These are general syntax problems that don't fit a more specific
// category.
func TestInvalidSyntaxErrors(t *testing.T) {
	cases := []struct {
		name          string
		sql           string
		dialect       keywords.SQLDialect
		wantSubstring string
	}{
		{
			name:          "contradictory_sequence_cache_options",
			sql:           "CREATE SEQUENCE s CACHE 10 NOCACHE",
			dialect:       keywords.DialectMariaDB,
			wantSubstring: "CACHE and NOCACHE",
		},
		{
			name:          "malformed_insert_values_expression",
			sql:           "INSERT INTO t (a) VALUES (1 + )",
			wantSubstring: "", // message content depends on inner parser error
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.dialect != "" {
				err = parseSQLWithDialect(t, tc.sql, tc.dialect)
			} else {
				err = parseSQL(t, tc.sql)
			}
			se := assertStructuredError(t, err, goerrors.ErrCodeInvalidSyntax)
			if tc.wantSubstring != "" && !strings.Contains(se.Message, tc.wantSubstring) {
				t.Errorf("error message %q does not contain %q", se.Message, tc.wantSubstring)
			}
		})
	}
}

// TestExpectedTokenErrors covers sites that convert to ExpectedTokenError
// (E2002). These surface when a keyword in a multi-token construct is missing.
func TestExpectedTokenErrors(t *testing.T) {
	cases := []struct {
		name          string
		sql           string
		dialect       keywords.SQLDialect
		wantSubstring string
	}{
		{
			name:          "for_system_time_bad_clause",
			sql:           "SELECT * FROM t FOR SYSTEM_TIME LATER",
			dialect:       keywords.DialectMariaDB,
			wantSubstring: "AS OF, BETWEEN, FROM, or ALL",
		},
		{
			name:          "for_system_time_as_without_of",
			sql:           "SELECT * FROM t FOR SYSTEM_TIME AS X",
			dialect:       keywords.DialectMariaDB,
			wantSubstring: "OF after AS",
		},
		{
			name:          "for_system_time_between_without_and",
			sql:           "SELECT * FROM t FOR SYSTEM_TIME BETWEEN x Y y",
			dialect:       keywords.DialectMariaDB,
			wantSubstring: "AND in FOR SYSTEM_TIME BETWEEN",
		},
		{
			name:          "for_system_time_from_without_to",
			sql:           "SELECT * FROM t FOR SYSTEM_TIME FROM x Y y",
			dialect:       keywords.DialectMariaDB,
			wantSubstring: "TO in FOR SYSTEM_TIME FROM",
		},
		{
			name:          "for_system_time_typed_literal_not_string",
			sql:           "SELECT * FROM t FOR SYSTEM_TIME AS OF TIMESTAMP 5",
			dialect:       keywords.DialectMariaDB,
			wantSubstring: "string literal after TIMESTAMP",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := parseSQLWithDialect(t, tc.sql, tc.dialect)
			se := assertStructuredError(t, err, goerrors.ErrCodeExpectedToken)
			if tc.wantSubstring != "" && !strings.Contains(se.Message, tc.wantSubstring) {
				t.Errorf("error message %q does not contain %q", se.Message, tc.wantSubstring)
			}
			// These errors are raised mid-parse so the location should be set.
			if se.Location.Line == 0 && se.Location.Column == 0 {
				t.Errorf("expected non-zero location, got %+v", se.Location)
			}
		})
	}
}

// TestUnsupportedFeatureErrors covers sites that convert to
// UnsupportedFeatureError (E4001): dialect-specific constructs rejected in
// other dialects.
func TestUnsupportedFeatureErrors(t *testing.T) {
	cases := []struct {
		name          string
		sql           string
		dialect       keywords.SQLDialect
		wantSubstring string
	}{
		{
			name:          "top_rejected_in_postgres",
			sql:           "SELECT TOP 10 * FROM users",
			dialect:       keywords.DialectPostgreSQL,
			wantSubstring: "TOP clause is not supported",
		},
		{
			name:          "top_rejected_in_oracle",
			sql:           "SELECT TOP 10 * FROM users",
			dialect:       keywords.DialectOracle,
			wantSubstring: "TOP clause is not supported in Oracle",
		},
		{
			name:          "limit_rejected_in_sqlserver",
			sql:           "SELECT * FROM users LIMIT 10",
			dialect:       keywords.DialectSQLServer,
			wantSubstring: "LIMIT clause is not supported",
		},
		{
			name:          "ilike_rejected_in_mysql",
			sql:           "SELECT * FROM users WHERE name ILIKE 'ann%'",
			dialect:       keywords.DialectMySQL,
			wantSubstring: "ILIKE is not supported",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := parseSQLWithDialect(t, tc.sql, tc.dialect)
			se := assertStructuredError(t, err, goerrors.ErrCodeUnsupportedFeature)
			if tc.wantSubstring != "" && !strings.Contains(se.Message, tc.wantSubstring) {
				t.Errorf("error message %q does not contain %q", se.Message, tc.wantSubstring)
			}
		})
	}
}

// TestValidateEmptyInputIsStructured verifies that ValidateBytes returns a
// structured IncompleteStatementError (E2005) for empty input, not a loose
// fmt.Errorf.
func TestValidateEmptyInputIsStructured(t *testing.T) {
	err := parser.ValidateBytes([]byte("   "))
	assertStructuredError(t, err, goerrors.ErrCodeIncompleteStatement)
}

// TestValidateUnknownDialectIsStructured verifies that
// ValidateBytesWithDialect returns a structured InvalidSyntaxError when the
// dialect is unknown.
func TestValidateUnknownDialectIsStructured(t *testing.T) {
	err := parser.ValidateBytesWithDialect([]byte("SELECT 1"), "not-a-real-dialect")
	se := assertStructuredError(t, err, goerrors.ErrCodeInvalidSyntax)
	if !strings.Contains(se.Message, "unknown SQL dialect") {
		t.Errorf("error message %q does not mention unknown SQL dialect", se.Message)
	}
}

// TestParseBytesWithDialectUnknown verifies ParseBytesWithDialect returns
// a structured error for unknown dialects.
func TestParseBytesWithDialectUnknown(t *testing.T) {
	_, err := parser.ParseBytesWithDialect([]byte("SELECT 1"), "no-such-dialect")
	se := assertStructuredError(t, err, goerrors.ErrCodeInvalidSyntax)
	if !strings.Contains(se.Message, "unknown SQL dialect") {
		t.Errorf("error message %q does not mention unknown SQL dialect", se.Message)
	}
}

// TestGetCodeWorksForConvertedErrors verifies goerrors.GetCode correctly
// extracts codes from the converted errors.
func TestGetCodeWorksForConvertedErrors(t *testing.T) {
	err := parseSQLWithDialect(t, "SELECT TOP 5 * FROM t", keywords.DialectPostgreSQL)
	if got := goerrors.GetCode(err); got != goerrors.ErrCodeUnsupportedFeature {
		t.Errorf("GetCode = %q, want %q", got, goerrors.ErrCodeUnsupportedFeature)
	}
}

// TestErrorWithCausePreservesUnderlying verifies that converted errors that
// wrap an inner error via WithCause() allow the underlying error to be
// retrieved with errors.Unwrap / errors.Is.
func TestErrorWithCausePreservesUnderlying(t *testing.T) {
	// This SQL fails to parse the VALUES expression; the outer error wraps the
	// inner parseExpression error via WithCause.
	err := parseSQL(t, "INSERT INTO t (a) VALUES (1 +)")
	if err == nil {
		t.Fatal("expected error")
	}
	var se *goerrors.Error
	if !errors.As(err, &se) {
		t.Fatalf("expected *goerrors.Error, got %T", err)
	}
	// The outer message should mention the VALUES row.
	if !strings.Contains(se.Message, "VALUES") {
		t.Errorf("expected outer message to mention VALUES, got %q", se.Message)
	}
	// Unwrap should give us the inner cause.
	if unwrapped := errors.Unwrap(se); unwrapped == nil {
		t.Error("expected non-nil cause, got nil")
	}
}
