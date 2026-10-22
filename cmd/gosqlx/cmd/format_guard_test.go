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

package cmd

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestFormatSQL_RefusesLostQuotes checks that the CLI refuses input whose
// quoted identifiers the renderer would write bare when that changes the
// identifier (reserved word, case folding, special characters). AST.SQL()
// cannot see this: identifiers carry no quoting, and statements such as ALTER
// have no SQL() at all, so the old check compared "" with "".
func TestFormatSQL_RefusesLostQuotes(t *testing.T) {
	tests := []struct {
		name    string
		dialect string
		in      string
	}{
		// Names the AST does not record quoting for (a TABLESPACE name, for
		// example) still render bare, so the CLI must refuse. (CREATE
		// SEQUENCE and ALTER POLICY names are recorded, so their quotes
		// survive.)
		{name: "tablespace mixed case", in: `CREATE TABLE t (a INT) TABLESPACE "Ts"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, opts := range []CLIFormatterOptions{
				{Compact: true, Uppercase: true, Dialect: tc.dialect},
				{IndentSize: 2, Dialect: tc.dialect},
			} {
				out, err := formatWith(tc.in, opts)
				if err == nil {
					t.Fatalf("formatSQL(%q, %+v) = %q, want an error", tc.in, opts, out)
				}
				if out != "" {
					t.Fatalf("formatSQL(%q) returned output %q alongside error %v", tc.in, out, err)
				}
			}
		})
	}
}

// TestFormatSQL_AllowsHarmlessQuotes checks that quoted identifiers that mean
// the same thing bare are still formatted.
func TestFormatSQL_AllowsHarmlessQuotes(t *testing.T) {
	tests := []struct {
		name    string
		dialect string
		in      string
		want    string
	}{
		{name: "lowercase quoted", in: `SELECT "users_id" FROM "users"`, want: "SELECT users_id FROM users"},
		{name: "alter policy mixed case", in: `ALTER POLICY "Pol" ON "Tbl" RENAME TO "Q"`, want: `ALTER POLICY "Pol" ON "Tbl" RENAME TO "Q"`},
		{name: "alter plain", in: "ALTER TABLE t ADD COLUMN c INT", want: "ALTER TABLE t ADD COLUMN c INT"},
		// Reserved words keep their quotes on render (#632), so these format.
		{name: "alter reserved word", in: `ALTER TABLE t ADD COLUMN "order" INT`, want: `ALTER TABLE t ADD COLUMN "order" INT`},
		{name: "alter reserved word postgresql", dialect: "postgresql", in: `ALTER TABLE t ADD COLUMN "order" INT`, want: `ALTER TABLE t ADD COLUMN "order" INT`},
		{name: "mysql backtick plain", dialect: "mysql", in: "ALTER TABLE `Users` ADD COLUMN `c` INT", want: "ALTER TABLE Users ADD COLUMN c INT"},
		{name: "sqlserver bracket kept quoted", dialect: "sqlserver", in: "SELECT [Mixed Name] FROM t", want: "SELECT [Mixed Name] FROM t"},
		{name: "oracle uppercase quoted", dialect: "oracle", in: `SELECT "ABC" FROM t`, want: "SELECT ABC FROM t"},
		{name: "string literal kept", in: "SELECT a FROM t WHERE b = 'it''s'", want: "SELECT a FROM t WHERE b = 'it''s'"},
		{name: "mysql escaped literal", dialect: "mysql", in: `SELECT 'a\nb'`, want: `SELECT 'a\nb'`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := formatWith(tc.in, CLIFormatterOptions{Compact: true, Uppercase: true, Dialect: tc.dialect})
			if err != nil {
				t.Fatalf("formatSQL(%q): %v", tc.in, err)
			}
			if out != tc.want {
				t.Fatalf("formatSQL(%q) = %q, want %q", tc.in, out, tc.want)
			}
		})
	}
}

// TestFormatSQL_KeepsBackslashLiteral checks that a string literal with
// backslashes is written back with the rules of its dialect: untouched where
// the backslash is an ordinary character, re-escaped (and so equal after
// tokenizing) where it escapes. The renderer used to double every backslash,
// so the guard refused these inputs.
func TestFormatSQL_KeepsBackslashLiteral(t *testing.T) {
	const in = `SELECT 'C:\temp\x'`
	for _, tt := range []struct {
		dialect string
		want    string // literal text expected in the output
	}{
		{"sqlserver", `'C:\temp\x'`},
		{"oracle", `'C:\temp\x'`},
		{"sqlite", `'C:\temp\x'`},
		{"postgresql", `'C:\temp\x'`},
		// \t is a tab; \x keeps its backslash, which the output doubles.
		// (Snowflake refuses an incomplete \x escape; see
		// format_string_escape_test.go.)
		{"clickhouse", "'C:\temp\\\\x'"},
	} {
		t.Run(tt.dialect, func(t *testing.T) {
			out, err := formatWith(in, CLIFormatterOptions{Compact: true, Uppercase: true, Dialect: tt.dialect})
			if err != nil {
				t.Fatalf("formatSQL(%q, %s): %v", in, tt.dialect, err)
			}
			if !strings.Contains(out, tt.want) {
				t.Fatalf("formatSQL(%q, %s) = %q, want it to contain %q", in, tt.dialect, out, tt.want)
			}
			again, err := formatWith(out, CLIFormatterOptions{Compact: true, Uppercase: true, Dialect: tt.dialect})
			if err != nil || again != out {
				t.Fatalf("not idempotent: %q then %q (err %v)", out, again, err)
			}
		})
	}
}

// TestVerifyFormattedSQL_StatementsWithoutSQL checks that the verification
// does not trivially pass for statements that have no SQL() method (e.g.
// ALTER), whose AST.SQL() contribution is empty on both sides.
func TestVerifyFormattedSQL_StatementsWithoutSQL(t *testing.T) {
	const in = "ALTER TABLE t ADD COLUMN c INT"
	tkz, release, err := tokenizerForDialect("")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	tokens, err := tkz.TokenizeString(in)
	if err != nil {
		t.Fatal(err)
	}
	orig, err := parserForDialect("").ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(orig)
	if err := verifyFormattedSQL(orig, tokens, "ALTER TABLE t ADD COLUMN c INT", ""); err != nil {
		t.Fatalf("identical output rejected: %v", err)
	}
	if err := verifyFormattedSQL(orig, tokens, "ALTER TABLE t ADD COLUMN d BIGINT", ""); err == nil {
		t.Fatal("output with a different ALTER statement was accepted")
	}
}

// TestFormatSQL_RefusesDescribeObjectKinds checks that DESCRIBE statements
// whose object kind the AST does not keep are refused rather than rewritten
// to a different command (e.g. Snowflake DESCRIBE STAGE -> DESCRIBE).
func TestFormatSQL_RefusesDescribeObjectKinds(t *testing.T) {
	for _, in := range []string{"DESCRIBE STAGE my_stage", "DESCRIBE VIEW user_summary", "DESC TABLE users"} {
		t.Run(in, func(t *testing.T) {
			out, err := formatWith(in, CLIFormatterOptions{Compact: true, Uppercase: true, Dialect: "snowflake"})
			if err == nil {
				t.Fatalf("formatSQL(%q) = %q, want an error", in, out)
			}
		})
	}
}

// TestCheckMySQLDoubleQuotes checks that MySQL/MariaDB output keeps exactly
// the input's double-quoted tokens, and that other dialects are not checked.
func TestCheckMySQLDoubleQuotes(t *testing.T) {
	tok := func(v string, q rune) models.TokenWithSpan {
		return models.TokenWithSpan{Token: models.Token{Type: models.TokenTypeIdentifier, Value: v, Quote: q}}
	}
	type toks = []models.TokenWithSpan
	tests := []struct {
		name    string
		in, out toks
		wantErr bool
	}{
		{"kept", toks{tok("bob", '"')}, toks{tok("bob", '"')}, false},
		{"string written bare", toks{tok("bob", '"')}, toks{tok("bob", 0)}, true},
		{"identifier newly double-quoted", toks{tok("select", '`')}, toks{tok("select", '"')}, true},
		{"count bypass", toks{tok("abc", '"'), tok("my col", '`')}, toks{tok("abc", 0), tok("my col", '"')}, true},
		{"no double quotes", toks{tok("a", '`')}, toks{tok("a", 0)}, false},
		{"ANSI_QUOTES qualifier", toks{tok("users", '"'), tok(".", 0), tok("id", '"')}, toks{tok("users", 0), tok(".", 0), tok("id", 0)}, false},
		{"ANSI_QUOTES table", toks{tok("FROM", 0), tok("users", '"')}, toks{tok("FROM", 0), tok("users", 0)}, false},
	}
	for _, tc := range tests {
		for _, d := range []string{"mysql", "MariaDB"} {
			if err := checkMySQLDoubleQuotes(tc.in, tc.out, d); (err != nil) != tc.wantErr {
				t.Errorf("%s/%s: err = %v, wantErr %v", tc.name, d, err, tc.wantErr)
			}
		}
		for _, d := range []string{"", "postgresql", "sqlserver"} {
			if err := checkMySQLDoubleQuotes(tc.in, tc.out, d); err != nil {
				t.Errorf("%s/%q: %v, want no check outside MySQL/MariaDB", tc.name, d, err)
			}
		}
	}
}

// TestFormatSQL_MySQLDoubleQuotedString checks the end-to-end refusal of a
// MySQL double-quoted string that the renderer would write bare.
func TestFormatSQL_MySQLDoubleQuotedString(t *testing.T) {
	for _, in := range []string{
		`SELECT a FROM t WHERE name = "bob"`,
		"SELECT \"abc\", `my col` FROM t",
	} {
		if out, err := formatWith(in, CLIFormatterOptions{Compact: true, Dialect: "mysql"}); err == nil {
			t.Errorf("formatSQL(%q, mysql) = %q, want an error", in, out)
		}
	}
}
