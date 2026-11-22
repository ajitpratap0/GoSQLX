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
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestRequoteDataType(t *testing.T) {
	for _, tc := range []struct {
		typ   string
		style rune
		want  string
	}{
		{`"char"`, '`', "`char`"},
		{`"MySchema"."a]b"[]`, '[', `[MySchema].[a]]b][]`},
		{`[123]`, '"', `"123"`},
		{`[a]]b]`, '"', `"a]b"`},
		{"`a``b`", '"', "\"a`b\""},
		{`"a""b"`, '[', `[a"b]`},
		{`Tuple("a b" INT, "c" TEXT)`, '`', "Tuple(`a b` INT, `c` TEXT)"},
		{`DateTime64(3, 'a"b')`, '`', `DateTime64(3, 'a"b')`},
		{`INT[3]`, '`', `INT[3]`},
		{`"unfinished`, '`', `"unfinished`},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			if got := ast.RequoteDataType(tc.typ, tc.style); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestRestyleDataTypesForDialect(t *testing.T) {
	for _, tc := range []struct {
		dialect string
		typ     string
		want    string
	}{
		{"clickhouse", "Tuple(`x y` UInt8, \"z\" String)", "Tuple(`x y` UInt8, \"z\" String)"},
		{"clickhouse", "[MyType][]", `"MyType"[]`},
		{"clickhouse", "Tuple([x y] UInt8, `z` String)", "Tuple(\"x y\" UInt8, `z` String)"},
		{"mysql", `"MyType"`, "`MyType`"},
		{"mariadb", `"MyType"`, "`MyType`"},
		{"sqlserver", `"MyType"`, "[MyType]"},
		{"postgresql", "`MyType`", `"MyType"`},
	} {
		t.Run(tc.dialect+tc.typ, func(t *testing.T) {
			cast := &ast.CastExpression{Type: tc.typ}
			ast.RestyleDataTypesForDialect(cast, tc.dialect)
			if cast.Type != tc.want {
				t.Fatalf("got %s, want %s", cast.Type, tc.want)
			}
		})
	}
}
