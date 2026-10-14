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
)

// TestFormatSQL_RefusesExplainAndDescribe guards against gosqlx format turning
// a non-executing EXPLAIN into an executable statement. The parser splits
// "EXPLAIN VERBOSE|ANALYZE <stmt>" into a DescribeStatement plus <stmt>, and
// DescribeStatement drops EXPLAIN options and object kinds, so the CLI must
// refuse it instead of writing "DESCRIBE VERBOSE; DELETE FROM users".
func TestFormatSQL_RefusesExplainAndDescribe(t *testing.T) {
	tests := []struct {
		name    string
		dialect string
		in      string
	}{
		{name: "explain verbose delete", in: "EXPLAIN VERBOSE DELETE FROM users"},
		{name: "explain verbose delete postgresql", dialect: "postgresql", in: "EXPLAIN VERBOSE DELETE FROM users;\n"},
		{name: "explain verbose update", in: "EXPLAIN VERBOSE UPDATE accounts SET balance = 0"},
		{name: "explain verbose drop", in: "EXPLAIN VERBOSE DROP TABLE users"},
		{name: "explain verbose truncate", in: "EXPLAIN VERBOSE TRUNCATE TABLE users"},
		{name: "explain verbose insert", in: "EXPLAIN VERBOSE INSERT INTO t (a) VALUES (1)"},
		{name: "explain analyze delete", in: "EXPLAIN ANALYZE DELETE FROM users"},
		{name: "mysql explain analyze select", dialect: "mysql", in: "EXPLAIN ANALYZE SELECT * FROM users"},
		{name: "explain select", in: "EXPLAIN SELECT 1"},
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

// TestFormat_InPlaceLeavesExplainUnchanged checks the end-to-end format -i
// path: the file must be left untouched and counted as failed.
func TestFormat_InPlaceLeavesExplainUnchanged(t *testing.T) {
	const original = "EXPLAIN VERBOSE DELETE FROM users;\n"
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
