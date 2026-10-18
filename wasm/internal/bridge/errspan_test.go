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
