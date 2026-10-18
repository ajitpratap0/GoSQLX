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

package bridge

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	gerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

type spanPos struct{ line, col, endLine, endCol int }

func TestErrorSpan_Positions(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want spanPos
		code string
	}{
		{"error at end of input is empty", "SELECT * FROM", spanPos{1, 14, 1, 14}, "E2002"},
		{"unexpected keyword covers the token", "SELECT FROM users", spanPos{1, 8, 1, 12}, "E2002"},
		{"misspelt keyword covers the word", "SELEC 1", spanPos{1, 1, 1, 6}, "E2002"},
		{"second line", "SELECT 1 FROM t\nWHERE a = = 2", spanPos{2, 11, 2, 12}, "E2001"},
		{"trailing statement", "SELECT 1; garbage here", spanPos{1, 11, 1, 18}, "E2002"},
		{"tokenizer error marks one character", "SELECT 'abc", spanPos{1, 8, 1, 9}, "E1002"},
		// The tokenizer counts columns in bytes; the span uses UTF-16 units.
		{"two-byte character before error", "SELECT 'é', x FROM t WHERE ) 1", spanPos{1, 28, 1, 29}, "E2002"},
		{"astral character before error", "SELECT '😀', x FROM t WHERE ) 1", spanPos{1, 29, 1, 30}, "E2002"},
		{"CRLF line endings", "SELECT a,\r\nFROM t", spanPos{2, 1, 2, 5}, "E2001"},
		// The tokenizer counts a tab as four columns; the span counts it as one.
		{"tab before error on the same line", "SELECT 1 FROM t\tWHERE x = = 1", spanPos{1, 27, 1, 28}, "E2001"},
		{"tab indentation before error", "SELECT id\n\tFROM users\n\tWHERE ) AND x = 1", spanPos{3, 8, 3, 9}, "E2002"},
		{"tab indentation at error", "SELECT a,\n\tFROM t", spanPos{2, 2, 2, 6}, "E2001"},
		// A token's Start includes a comment skipped before it; mark the token.
		{"block comment before error", "SELECT * FROM t WHERE x = 1 /* é */ )", spanPos{1, 37, 1, 38}, "E2002"},
		{"line comment before error", "SELECT * FROM t WHERE x = 1 -- c\n )", spanPos{2, 2, 2, 3}, "E2002"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.sql, "generic")
			if err == nil {
				t.Fatalf("expected a parse error for %q", tt.sql)
			}
			span := errorSpan(tt.sql, err)
			if span == nil {
				t.Fatalf("expected a span for %q (error: %v)", tt.sql, err)
			}
			got := spanPos{span.Line, span.Column, span.EndLine, span.EndColumn}
			if got != tt.want {
				t.Errorf("span = %+v, want %+v", got, tt.want)
			}
			if span.Code != tt.code {
				t.Errorf("code = %q, want %q", span.Code, tt.code)
			}
			if span.Message == "" || strings.Contains(span.Message, "\n") {
				t.Errorf("message should be the one-line error text, got %q", span.Message)
			}
		})
	}
}

// Wrapped errors repeat the wrapped error's formatted text (prefix, hint and
// help URL) in their own message; the span reports only the root cause.
func TestErrorSpan_NestedErrorsReportRootCause(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		want    spanPos
		code    string
		message string
	}{
		{"wrapped as cause", "INSERT INTO t VALUES (1, )", spanPos{1, 26, 1, 27},
			"E2001", "unexpected token: RPAREN (')')"},
		{"flattened into the message", "WITH x AS (SELECT 1 SELECT 2) SELECT * FROM x", spanPos{1, 21, 1, 27},
			"E2002", "expected FROM, semicolon, or end of statement, got SELECT"},
		{"tokenizer error under E2004", "SELECT 'abc", spanPos{1, 8, 1, 9},
			"E1002", "unterminated string literal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.sql, "generic")
			if err == nil {
				t.Fatalf("expected a parse error for %q", tt.sql)
			}
			span := errorSpan(tt.sql, err)
			if span == nil {
				t.Fatalf("expected a span for %q (error: %v)", tt.sql, err)
			}
			if got := (spanPos{span.Line, span.Column, span.EndLine, span.EndColumn}); got != tt.want {
				t.Errorf("span = %+v, want %+v", got, tt.want)
			}
			if span.Code != tt.code {
				t.Errorf("code = %q, want %q", span.Code, tt.code)
			}
			if span.Message != tt.message {
				t.Errorf("message = %q, want %q", span.Message, tt.message)
			}
			for _, bad := range []string{"\n", "Hint:", "Help:", "http", "Error E"} {
				if strings.Contains(span.Message, bad) {
					t.Errorf("message contains %q: %q", bad, span.Message)
				}
			}
		})
	}
}

func TestErrorSpan_SummarizeKeepsPlainMessage(t *testing.T) {
	e := &gerrors.Error{Code: "E2002", Message: "expected FROM\n\nHint: x"}
	code, msg := summarize(e)
	if code != "E2002" || msg != "expected FROM" {
		t.Errorf("summarize = (%q, %q), want (%q, %q)", code, msg, "E2002", "expected FROM")
	}
}

func TestErrorSpan_NoPosition(t *testing.T) {
	if span := errorSpan("SELECT 1", errors.New("plain error")); span != nil {
		t.Fatalf("expected no span for an error without a position, got %+v", span)
	}
}

func TestErrorSpan_ClampsOutOfRangeLocation(t *testing.T) {
	lines := []string{"SELECT 1"}
	for _, tc := range []struct {
		name       string
		line, col  int
		wantLine   int
		wantOffset int
	}{
		{"past last line", 5, 3, 1, 8},
		{"past end of line", 1, 40, 1, 8},
		{"in range", 1, 3, 1, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, off := clampLocation(lines, models.Location{Line: tc.line, Column: tc.col})
			if line != tc.wantLine || off != tc.wantOffset {
				t.Errorf("clampLocation = (%d, %d), want (%d, %d)", line, off, tc.wantLine, tc.wantOffset)
			}
		})
	}
}

func TestErrorSpan_ClampLocationCountsTabsAsFourColumns(t *testing.T) {
	lines := []string{"a\tb"}
	for _, tc := range []struct {
		name       string
		col        int
		wantOffset int
	}{
		{"before tab", 1, 0},
		{"at tab", 2, 1},
		{"inside tab span", 4, 1},
		{"after tab", 6, 2},
		{"past end", 9, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, off := clampLocation(lines, models.Location{Line: 1, Column: tc.col})
			if off != tc.wantOffset {
				t.Errorf("clampLocation(col %d) offset = %d, want %d", tc.col, off, tc.wantOffset)
			}
		})
	}
}

func TestParseErrorSpan_InResponses(t *testing.T) {
	const sql = "SELECT * FROM users WHERE"

	lint := Lint(sql, "generic")
	if lint.ParseErrorSpan == nil {
		t.Fatalf("Lint: expected parse_error_span with parse_error %q", lint.ParseError)
	}
	analyze := Analyze(sql, "generic")
	if analyze.ParseErrorSpan == nil {
		t.Fatalf("Analyze: expected parse_error_span with parse_error %q", analyze.ParseError)
	}
	if *lint.ParseErrorSpan != *analyze.ParseErrorSpan {
		t.Errorf("Lint and Analyze disagree: %+v vs %+v", *lint.ParseErrorSpan, *analyze.ParseErrorSpan)
	}

	b, err := json.Marshal(lint)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"parse_error_span"`, `"line"`, `"column"`, `"end_line"`, `"end_column"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("lint JSON missing %s: %s", key, b)
		}
	}

	if ok := Lint("SELECT 1", "generic"); ok.ParseErrorSpan != nil {
		t.Errorf("valid SQL must not carry a parse_error_span, got %+v", ok.ParseErrorSpan)
	}
	if ok := Analyze("SELECT 1", "generic"); ok.ParseErrorSpan != nil {
		t.Errorf("valid SQL must not carry a parse_error_span, got %+v", ok.ParseErrorSpan)
	}
}
