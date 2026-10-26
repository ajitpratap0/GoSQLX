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

package ast

import (
	"bytes"
	"testing"
)

// TestLiteralValueNULRendering pins how a NUL in a string literal's value is
// written. A backslash-escaping literal spells it \0 (it used to be dropped,
// so MySQL 'a\0b' silently became 'ab'), an E-string spells it with three
// octal digits so a following digit is not read into the escape, and a
// literal without backslash escapes has no spelling for it: the byte is
// dropped there, which only a hand-built AST can reach (the tokenizer and
// the transpiler refuse such input).
func TestLiteralValueNULRendering(t *testing.T) {
	tests := []struct {
		name string
		lit  *LiteralValue
		want string
	}{
		{"escaping literal", &LiteralValue{Value: "a\x00b", Type: "string"}, `'a\0b'`},
		{"escaping literal before digit", &LiteralValue{Value: "a\x001", Type: "string"}, `'a\01'`},
		{"escaping literal only NUL", &LiteralValue{Value: "\x00", Type: "STRING"}, `'\0'`},
		{"charset introducer", &LiteralValue{Value: "a\x00", Type: "string", extras: &LiteralExtras{Prefix: "_utf8mb4"}}, `_utf8mb4'a\0'`},
		{"E-string", &LiteralValue{Value: "a\x001", Type: "string", extras: &LiteralExtras{Prefix: "E"}}, `E'a\0001'`},
		{"raw literal", &LiteralValue{Value: "a\x00b", Type: "string", extras: &LiteralExtras{RawBackslash: true}}, `'ab'`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.lit.SQL(); got != tt.want {
				t.Errorf("SQL() = %q, want %q", got, tt.want)
			}
			var buf bytes.Buffer
			tt.lit.writeSQL(&buf)
			if got := buf.String(); got != tt.want {
				t.Errorf("writeSQL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestIdentifierDollarKeepsDelimiters checks that a name containing '$' keeps
// the delimiters the source gave it. Standard SQL, BigQuery and ClickHouse do
// not accept '$' in a bare name, and the renderer does not know the dialect,
// so a delimited "a$b" must not come back bare; a name the source wrote bare
// (Oracle v$session) stays bare.
func TestIdentifierDollarKeepsDelimiters(t *testing.T) {
	tests := []struct {
		name string
		id   *Identifier
		want string
	}{
		{"double-quoted", &Identifier{Name: "a$b", Quoted: true}, `"a$b"`},
		{"backtick", &Identifier{Name: "a$b", QuoteStyle: '`'}, "`a$b`"},
		{"bracket", &Identifier{Name: "a$b", QuoteStyle: '['}, "[a$b]"},
		{"qualified quoted", &Identifier{Name: "a$b", Table: "t", Quoted: true}, `t."a$b"`},
		{"bare stays bare", &Identifier{Name: "v$session"}, "v$session"},
		{"quoted without dollar is normalised", &Identifier{Name: "ab", Quoted: true}, "ab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.id.SQL(); got != tt.want {
				t.Errorf("SQL() = %q, want %q", got, tt.want)
			}
			var buf bytes.Buffer
			tt.id.writeSQL(&buf)
			if got := buf.String(); got != tt.want {
				t.Errorf("writeSQL() = %q, want %q", got, tt.want)
			}
		})
	}
}
