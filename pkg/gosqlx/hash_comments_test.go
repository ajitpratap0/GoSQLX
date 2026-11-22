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

package gosqlx

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestHashCommentsIntegration(t *testing.T) {
	const source = "SELECT a FROM t WHERE x = 1 # c\nAND y = 2"
	for _, d := range []keywords.SQLDialect{keywords.DialectMySQL, keywords.DialectMariaDB} {
		t.Run(string(d), func(t *testing.T) {
			tree, err := ParseWithDialect(source, d)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			if len(tree.Statements) != 1 {
				t.Fatalf("statements = %d", len(tree.Statements))
			}
			sel, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("statement = %T", tree.Statements[0])
			}
			and, ok := sel.Where.(*ast.BinaryExpression)
			if !ok || and.Operator != "AND" {
				t.Fatalf("WHERE = %#v", sel.Where)
			}
			for _, side := range []struct {
				expr ast.Expression
				want string
			}{{and.Left, "x = 1"}, {and.Right, "y = 2"}} {
				eq, ok := side.expr.(*ast.BinaryExpression)
				if !ok || eq.Operator != "=" || eq.SQL() != side.want {
					t.Fatalf("predicate = %#v, want %s", side.expr, side.want)
				}
			}
			trailing, err := ParseWithDialect("SELECT a FROM t # trailing", d)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(trailing)
			formatted, err := FormatWithDialect("SELECT a FROM t # trailing", FormatOptions{}, d)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(formatted, "# trailing") {
				t.Fatalf("comment lost: %q", formatted)
			}
			reparsed, err := ParseWithDialect(formatted, d)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(reparsed)
			if len(reparsed.Statements) != 1 || FormatAST(reparsed) != FormatAST(trailing) {
				t.Fatalf("format changed statement: %q", formatted)
			}
			got, err := Transpile(source, d, keywords.DialectPostgreSQL)
			if err != nil {
				t.Fatal(err)
			}
			if got != "SELECT a FROM t WHERE x = 1 AND y = 2" {
				t.Fatalf("transpiled = %q", got)
			}
		})
	}
}

func TestSplitStatementsHashComments(t *testing.T) {
	for _, d := range []string{"mysql", "mariadb", "postgresql", ""} {
		t.Run(d, func(t *testing.T) {
			got := SplitStatements("SELECT 1; # a;b\nSELECT 2", d)
			want := 3
			if d == "mysql" || d == "mariadb" {
				want = 2
			}
			if len(got) != want || got[0] != "SELECT 1" || !strings.Contains(got[len(got)-1], "SELECT 2") {
				t.Fatalf("split = %#v", got)
			}
		})
	}
	for _, d := range []string{"mysql", "mariadb"} {
		for _, source := range []string{
			"BEGIN # ignored; END\nSELECT 1; SELECT 2; END; SELECT 3",
			"BEGIN # ignored\nNOT # ignored\nATOMIC SELECT 1; SELECT 2; END; SELECT 3",
			"DELIMITER $$\nCREATE PROCEDURE p() BEGIN # ignored $$; END\nSELECT 1; END$$\nDELIMITER ;\nSELECT 2;",
			"BEGIN SELECT 1; END # ignored\nIF; SELECT 2;",
		} {
			if got := SplitStatements(source, d); len(got) != 2 {
				t.Errorf("%s split %q = %#v", d, source, got)
			}
		}
	}
}
