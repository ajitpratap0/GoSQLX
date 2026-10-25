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
		{"raw backslash kept", literalWithMetadata(`a\b`, "string", ast.LiteralExtras{RawBackslash: true}), `'a\b'`},
		{"raw regex kept", literalWithMetadata(`x\.y`, "string", ast.LiteralExtras{RawBackslash: true}), `'x\.y'`},
		{"raw quote still doubled", literalWithMetadata(`it's \`, "string", ast.LiteralExtras{RawBackslash: true}), `'it''s \'`},
		{"raw newline literal", literalWithMetadata("a\nb", "string", ast.LiteralExtras{RawBackslash: true}), "'a\nb'"},
		{"raw ctrl-z literal", literalWithMetadata("a\x1ab", "string", ast.LiteralExtras{RawBackslash: true}), "'a\x1ab'"},
		{"raw NUL dropped", literalWithMetadata("a\x00b", "string", ast.LiteralExtras{RawBackslash: true}), `'ab'`},
		{"raw invalid UTF-8 replaced", literalWithMetadata("a\xffb", "string", ast.LiteralExtras{RawBackslash: true}), "'a�b'"},
		{"national", literalWithMetadata("x", "string", ast.LiteralExtras{Prefix: "N"}), `N'x'`},
		{"hex", literalWithMetadata("4D", "string", ast.LiteralExtras{Prefix: "X"}), `X'4D'`},
		{"bit", literalWithMetadata("101", "string", ast.LiteralExtras{Prefix: "B"}), `B'101'`},
		{"charset introducer", literalWithMetadata("abc", "string", ast.LiteralExtras{Prefix: "_utf8mb4"}), `_utf8mb4'abc'`},
		{"prefix with raw backslash", literalWithMetadata(`a\b`, "string", ast.LiteralExtras{Prefix: "N", RawBackslash: true}), `N'a\b'`},
		{"unsafe prefix dropped", literalWithMetadata("x", "string", ast.LiteralExtras{Prefix: "x'; DROP TABLE t; --"}), `'x'`},
		{"E-string escapes", literalWithMetadata("a\tb\\c\nd'e", "string", ast.LiteralExtras{Prefix: "E"}), `E'a\tb\\c\nd''e'`},
		{"E-string ctrl-z is raw", literalWithMetadata("\x1a", "string", ast.LiteralExtras{Prefix: "E"}), "E'\x1a'"},
		{"q-quote default delimiter", literalWithMetadata("It's", "string", ast.LiteralExtras{Prefix: "q"}), `q'[It's]'`},
		{"q-quote picks another delimiter", literalWithMetadata("a]'b", "string", ast.LiteralExtras{Prefix: "q"}), `q'{a]'b}'`},
		{"q-quote falls back to a plain string", literalWithMetadata("a\x00b", "string", ast.LiteralExtras{Prefix: "q"}), `'ab'`},
		{"prefix ignored for numbers", literalWithMetadata("5", "int", ast.LiteralExtras{Prefix: "N"}), `5`},
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
	lit.Value, lit.Type, lit.EnsureExtras().Prefix, lit.EnsureExtras().RawBackslash = "x", "string", "N", true
	ast.PutLiteralValue(lit)

	for i := 0; i < 100; i++ {
		got := ast.GetLiteralValue()
		if got.DialectExtras().Prefix != "" || got.DialectExtras().RawBackslash || got.Value != nil || got.Type != "" {
			t.Fatalf("pooled literal not reset: %+v", *got)
		}
		ast.PutLiteralValue(got)
	}
}

func literalWithMetadata(value interface{}, typ string, metadata ast.LiteralExtras) ast.LiteralValue {
	lit := ast.LiteralValue{Value: value, Type: typ}
	*lit.EnsureExtras() = metadata
	return lit
}
