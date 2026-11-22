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

package transpiler_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler"
)

func TestQuotedTypeNames(t *testing.T) {
	for _, tc := range []struct{ sql, typ string }{
		{`SELECT CAST(x AS "MyType")`, `"MyType"`},
		{`SELECT x::"char"`, `"char"`},
		{`CREATE TABLE t (a "MyDomain")`, `"MyDomain"`},
		{`SELECT CAST(x AS "MySchema"."MyType"[])`, `"MySchema"."MyType"[]`},
		{`SELECT CAST(x AS "a""b")`, `"a""b"`},
	} {
		t.Run(tc.sql, func(t *testing.T) {
			tree, err := parser.ParseWithDialect(tc.sql, keywords.DialectPostgreSQL)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			for _, got := range []string{quotedTypeStatementSQL(t, tree.Statements[0]), formatter.FormatAST(tree, ast.CompactStyle())} {
				if !strings.Contains(got, tc.typ) {
					t.Fatalf("type %s lost in %s", tc.typ, got)
				}
				again, err := parser.ParseWithDialect(got, keywords.DialectPostgreSQL)
				if err != nil {
					t.Fatal(err)
				}
				defer ast.ReleaseAST(again)
				if quotedTypeStatementSQL(t, again.Statements[0]) != quotedTypeStatementSQL(t, tree.Statements[0]) {
					t.Fatalf("round trip changed: %s", got)
				}
			}
		})
	}
}

func TestTranspileQuotedTypeNames(t *testing.T) {
	for _, tc := range []struct {
		sql    string
		target keywords.SQLDialect
		want   string
	}{
		{`SELECT CAST(x AS "MyType")`, keywords.DialectMySQL, "CAST(x AS `MyType`)"},
		{`SELECT x::"char"`, keywords.DialectSQLServer, "CAST(x AS [char])"},
		{`CREATE TABLE t (a "MyDomain")`, keywords.DialectMySQL, "a `MyDomain`"},
		{`SELECT CAST(x AS "MySchema"."a]b")`, keywords.DialectSQLServer, "CAST(x AS [MySchema].[a]]b])"},
		{"SELECT CAST(x AS `MyType`)", keywords.DialectPostgreSQL, `CAST(x AS "MyType")`},
	} {
		t.Run(tc.sql+string(tc.target), func(t *testing.T) {
			from := keywords.DialectPostgreSQL
			if strings.Contains(tc.sql, "`") {
				from = keywords.DialectMySQL
			}
			got, err := transpiler.Transpile(tc.sql, from, tc.target)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
			tree, err := parser.ParseWithDialect(got, tc.target)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
		})
	}
}

func quotedTypeStatementSQL(t *testing.T, stmt ast.Statement) string {
	t.Helper()
	renderer, ok := stmt.(interface{ SQL() string })
	if !ok {
		t.Fatalf("statement %T lacks SQL()", stmt)
	}
	return renderer.SQL()
}
