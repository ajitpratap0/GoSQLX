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

package ast_test

import (
	"bytes"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestLiteralValueStringRendering(t *testing.T) {
	tests := []struct {
		name string
		lit  ast.LiteralValue
		want string
	}{
		{"plain", ast.LiteralValue{Value: "abc", Type: "string"}, `'abc'`},
		{"quote doubled", ast.LiteralValue{Value: "it's", Type: "STRING"}, `'it''s'`},
		{"backslash doubled by default", ast.LiteralValue{Value: `a\b`, Type: "string"}, `'a\\b'`},
		{"newline escaped by default", ast.LiteralValue{Value: "a\nb", Type: "string"}, `'a\nb'`},
		{"raw backslash kept", ast.LiteralValue{Value: `a\b`, Type: "string", RawBackslash: true}, `'a\b'`},
		{"raw regex kept", ast.LiteralValue{Value: `x\.y`, Type: "string", RawBackslash: true}, `'x\.y'`},
		{"raw quote still doubled", ast.LiteralValue{Value: `it's \`, Type: "string", RawBackslash: true}, `'it''s \'`},
		{"raw newline literal", ast.LiteralValue{Value: "a\nb", Type: "string", RawBackslash: true}, "'a\nb'"},
		{"raw ctrl-z literal", ast.LiteralValue{Value: "a\x1ab", Type: "string", RawBackslash: true}, "'a\x1ab'"},
		{"raw NUL dropped", ast.LiteralValue{Value: "a\x00b", Type: "string", RawBackslash: true}, `'ab'`},
		{"raw invalid UTF-8 replaced", ast.LiteralValue{Value: "a\xffb", Type: "string", RawBackslash: true}, "'a�b'"},
		{"national", ast.LiteralValue{Value: "x", Type: "string", Prefix: "N"}, `N'x'`},
		{"hex", ast.LiteralValue{Value: "4D", Type: "string", Prefix: "X"}, `X'4D'`},
		{"bit", ast.LiteralValue{Value: "101", Type: "string", Prefix: "B"}, `B'101'`},
		{"charset introducer", ast.LiteralValue{Value: "abc", Type: "string", Prefix: "_utf8mb4"}, `_utf8mb4'abc'`},
		{"prefix with raw backslash", ast.LiteralValue{Value: `a\b`, Type: "string", Prefix: "N", RawBackslash: true}, `N'a\b'`},
		{"unsafe prefix dropped", ast.LiteralValue{Value: "x", Type: "string", Prefix: "x'; DROP TABLE t; --"}, `'x'`},
		{"E-string escapes", ast.LiteralValue{Value: "a\tb\\c\nd'e", Type: "string", Prefix: "E"}, `E'a\tb\\c\nd''e'`},
		{"E-string ctrl-z is raw", ast.LiteralValue{Value: "\x1a", Type: "string", Prefix: "E"}, "E'\x1a'"},
		{"q-quote default delimiter", ast.LiteralValue{Value: "It's", Type: "string", Prefix: "q"}, `q'[It's]'`},
		{"q-quote picks another delimiter", ast.LiteralValue{Value: "a]'b", Type: "string", Prefix: "q"}, `q'{a]'b}'`},
		{"q-quote falls back to a plain string", ast.LiteralValue{Value: "a\x00b", Type: "string", Prefix: "q"}, `'ab'`},
		{"prefix ignored for numbers", ast.LiteralValue{Value: "5", Type: "int", Prefix: "N"}, `5`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lit := tt.lit
			if got := lit.SQL(); got != tt.want {
				t.Errorf("SQL() = %q, want %q", got, tt.want)
			}
			// writeSQL (used by statement rendering) must agree with SQL().
			sel := &ast.SelectStatement{Columns: []ast.Expression{&lit}}
			var buf bytes.Buffer
			buf.WriteString(sel.SQL())
			if want := "SELECT " + tt.want; buf.String() != want {
				t.Errorf("SelectStatement.SQL() = %q, want %q", buf.String(), want)
			}
		})
	}
}

// TestLiteralValuePoolResetsStringFields checks that a pooled literal comes
// back without the previous user's introducer or escape mode.
func TestLiteralValuePoolResetsStringFields(t *testing.T) {
	lit := ast.GetLiteralValue()
	lit.Value, lit.Type, lit.Prefix, lit.RawBackslash = "x", "string", "N", true
	ast.PutLiteralValue(lit)

	for i := 0; i < 100; i++ {
		got := ast.GetLiteralValue()
		if got.Prefix != "" || got.RawBackslash || got.Value != nil || got.Type != "" {
			t.Fatalf("pooled literal not reset: %+v", *got)
		}
		ast.PutLiteralValue(got)
	}
}
