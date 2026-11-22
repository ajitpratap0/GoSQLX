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
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestFormatSQL_PreservesExplain checks that EXPLAIN <stmt> formats as one
// statement that keeps EXPLAIN and its options, so a non-executing EXPLAIN is
// never rewritten into the executable statement.
func TestFormatSQL_PreservesExplain(t *testing.T) {
	tests := []struct {
		dialect string
		in      string
		want    string // compact, upper-cased output
	}{
		{"", "EXPLAIN VERBOSE DELETE FROM users", "EXPLAIN VERBOSE DELETE FROM users"},
		{"postgresql", "EXPLAIN VERBOSE DELETE FROM users;\n", "EXPLAIN VERBOSE DELETE FROM users"},
		{"", "explain verbose update accounts set balance = 0", "EXPLAIN VERBOSE UPDATE accounts SET balance = 0"},
		{"", "EXPLAIN VERBOSE INSERT INTO t (a) VALUES (1)", "EXPLAIN VERBOSE INSERT INTO t (a) VALUES (1)"},
		{"", "EXPLAIN ANALYZE DELETE FROM users", "EXPLAIN ANALYZE DELETE FROM users"},
		{"mysql", "EXPLAIN ANALYZE SELECT * FROM users", "EXPLAIN ANALYZE SELECT * FROM users"},
		{"", "EXPLAIN SELECT 1", "EXPLAIN SELECT 1"},
	}
	for _, tc := range tests {
		out, err := formatWith(tc.in, CLIFormatterOptions{Compact: true, Uppercase: true, Dialect: tc.dialect})
		if err != nil {
			t.Fatalf("formatSQL(%q): %v", tc.in, err)
		}
		if got := strings.TrimSuffix(strings.TrimSpace(out), ";"); got != tc.want {
			t.Errorf("formatSQL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestFormatSQL_RefusesDescribe guards statements the formatter cannot
// rewrite faithfully: DESCRIBE drops object kinds, and EXPLAIN of a statement
// the parser does not wrap would otherwise be split in two.
func TestFormatSQL_RefusesDescribe(t *testing.T) {
	tests := []struct {
		name    string
		dialect string
		in      string
	}{
		{name: "explain verbose drop", in: "EXPLAIN VERBOSE DROP TABLE users"},
		{name: "explain verbose truncate", in: "EXPLAIN VERBOSE TRUNCATE TABLE users"},
		{name: "describe table", in: "DESCRIBE users"},
		{name: "snowflake describe table kind", dialect: "snowflake", in: "DESCRIBE TABLE users"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, opts := range []CLIFormatterOptions{
				{Compact: true, Uppercase: true, Dialect: tc.dialect},
				{IndentSize: 2, Uppercase: true, Dialect: tc.dialect},
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

// TestFormat_InPlaceLeavesDescribeUnchanged checks the end-to-end format -i
// path: the file must be left untouched and counted as failed.
func TestFormat_InPlaceLeavesDescribeUnchanged(t *testing.T) {
	const original = "DESCRIBE users;\n"
	path := filepath.Join(t.TempDir(), "r.sql")
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	f := NewFormatter(&out, &errBuf, CLIFormatterOptions{InPlace: true, IndentSize: 2, Uppercase: true, Dialect: "postgresql"})
	res, err := f.Format([]string{path})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if res.FailedFiles != 1 || res.FormattedFiles != 0 {
		t.Fatalf("FailedFiles=%d FormattedFiles=%d, want 1 and 0 (stderr: %s)", res.FailedFiles, res.FormattedFiles, errBuf.String())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("format -i rewrote the file:\n%s", got)
	}
}

// TestStatementSegments covers the separator guard that refuses parses with
// more statements than semicolon-separated segments in the input.
func TestStatementSegments(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"SELECT 1", 1},
		{"SELECT 1;", 1},
		{";;SELECT 1;;", 1},
		{"SELECT 1; SELECT 2", 2},
		{"SELECT 1;\n\nSELECT 2;\n", 2},
		{"EXPLAIN VERBOSE DELETE FROM users;", 1},
	}
	for _, tc := range tests {
		tkz, release, err := tokenizerForDialect("")
		if err != nil {
			t.Fatal(err)
		}
		tokens, err := tkz.TokenizeString(tc.in)
		if err != nil {
			release()
			t.Fatalf("tokenize %q: %v", tc.in, err)
		}
		got := statementSegments(tokens)
		release()
		if got != tc.want {
			t.Errorf("statementSegments(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestFormatSQL_UnsupportedStatementMessage checks the refusal names the type.
func TestFormatSQL_UnsupportedStatementMessage(t *testing.T) {
	_, err := formatWith("DESCRIBE users", CLIFormatterOptions{Compact: true})
	if err == nil || !strings.Contains(err.Error(), "DescribeStatement") {
		t.Fatalf("want an error naming DescribeStatement, got %v", err)
	}
}

// TestTSQLStatementBound covers the SQL Server form of the separator guard:
// statements may end without ';', so the bound also counts GO lines and the
// words a T-SQL statement can start with.
func TestTSQLStatementBound(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"SELECT 1", 1},
		{"SELECT 1;", 1},
		{"SELECT 1\nGO\nSELECT 2", 3},
		{"SELECT 1\nGO 2\nSELECT 2 PRINT 'x'", 4},
		{"UPDATE t SET a = 1 WHERE b = 2", 2}, // SET may start a statement
		{"SELECT a, b FROM t WHERE c = 1", 1},
		{"SELECT t.select FROM t", 1}, // a qualified name part is not a start
		{"SELECT [select] FROM t", 1}, // nor is a quoted name
	}
	for _, tc := range tests {
		tkz, release, err := tokenizerForDialect("sqlserver")
		if err != nil {
			t.Fatal(err)
		}
		tokens, err := tkz.TokenizeString(tc.in)
		if err != nil {
			release()
			t.Fatalf("tokenize %q: %v", tc.in, err)
		}
		got := tsqlStatementBound(tokens)
		release()
		if got != tc.want {
			t.Errorf("tsqlStatementBound(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestCheckFormattable_SQLServerGuard checks that the statement-count guard
// runs for SQL Server: a tree with more statements than the input can hold
// (the parser split a statement) is refused, a legitimate one is not.
func TestCheckFormattable_SQLServerGuard(t *testing.T) {
	tkz, release, err := tokenizerForDialect("sqlserver")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	tokens, err := tkz.TokenizeString("SELECT a b")
	if err != nil {
		t.Fatal(err)
	}
	split := &ast.AST{Statements: []ast.Statement{&ast.SelectStatement{}, &ast.SelectStatement{}}}
	if err := checkFormattable(split, tokens, "sqlserver"); err == nil {
		t.Error("a statement split in two was accepted")
	}
	whole := &ast.AST{Statements: []ast.Statement{&ast.SelectStatement{}}}
	if err := checkFormattable(whole, tokens, "sqlserver"); err != nil {
		t.Errorf("one statement refused: %v", err)
	}
	for _, sql := range []string{
		"SELECT 1\nGO\nSELECT 2\nGO 3",
		"SET NOCOUNT ON\nSELECT 1\nUPDATE t SET a = 1\nCOMMIT",
		"IF @a = 1 SELECT 1 ELSE SELECT 2",
	} {
		out, err := formatWith(sql, CLIFormatterOptions{Compact: true, Dialect: "sqlserver"})
		if err != nil {
			t.Errorf("format %q: %v", sql, err)
			continue
		}
		if out == "" {
			t.Errorf("format %q: empty output", sql)
		}
	}
}
