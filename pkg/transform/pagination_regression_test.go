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

package transform

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestPaginationPreservesClauseKind(t *testing.T) {
	tests := []struct {
		name, sql string
		rule      Rule
		want      string
	}{
		{"top", "SELECT TOP 5 * FROM a", SetLimit(3), "SELECT TOP 3 * FROM a"},
		{"parenthesized top", "SELECT TOP (5) * FROM a", SetLimit(3), "SELECT TOP (3) * FROM a"},
		{"fetch first", "SELECT * FROM a FETCH FIRST 5 ROWS ONLY", SetLimit(3), "SELECT * FROM a FETCH FIRST 3 ROWS ONLY"},
		{"fetch next", "SELECT * FROM a ORDER BY id OFFSET 2 ROWS FETCH NEXT 5 ROWS ONLY", SetLimit(3), "SELECT * FROM a ORDER BY id OFFSET 2 ROWS FETCH NEXT 3 ROWS ONLY"},
		{"remove top", "SELECT TOP 5 * FROM a", RemoveLimit(), "SELECT * FROM a"},
		{"remove fetch", "SELECT * FROM a FETCH FIRST 5 ROWS ONLY", RemoveLimit(), "SELECT * FROM a"},
		{"remove fetch retain offset", "SELECT * FROM a ORDER BY id OFFSET 2 ROWS FETCH NEXT 5 ROWS ONLY", RemoveLimit(), "SELECT * FROM a ORDER BY id OFFSET 2 ROWS"},
		{"offset fetch", "SELECT * FROM a ORDER BY id OFFSET 2 ROWS FETCH NEXT 5 ROWS ONLY", SetOffset(3), "SELECT * FROM a ORDER BY id OFFSET 3 ROWS FETCH NEXT 5 ROWS ONLY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := ParseSQLWithDialect(tt.sql, keywords.DialectSQLServer)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			stmt := tree.Statements[0]
			if err := Apply(stmt, tt.rule); err != nil {
				t.Fatal(err)
			}
			for name, out := range map[string]string{"SQL": selectSQL(t, stmt), "FormatAST": strings.TrimSuffix(format(stmt), ";")} {
				if out != tt.want {
					t.Errorf("%s = %q, want %q", name, out, tt.want)
				}
				reparsed, err := ParseSQLWithDialect(out, keywords.DialectSQLServer)
				if err != nil {
					t.Fatalf("reparse: %v", err)
				}
				defer ast.ReleaseAST(reparsed)
				if got := selectSQL(t, reparsed.Statements[0]); got != selectSQL(t, stmt) {
					t.Errorf("round trip = %q, want %q", got, selectSQL(t, stmt))
				}
			}
		})
	}
}

func TestPaginationRejectsAmbiguousModifiers(t *testing.T) {
	for _, sql := range []string{"SELECT TOP 5 PERCENT * FROM a", "SELECT TOP 5 WITH TIES * FROM a ORDER BY id", "SELECT * FROM a FETCH FIRST 5 PERCENT ROWS ONLY", "SELECT * FROM a ORDER BY id FETCH FIRST 5 ROWS WITH TIES"} {
		for name, rule := range map[string]Rule{"limit": SetLimit(3), "remove": RemoveLimit(), "offset": SetOffset(3)} {
			t.Run(sql+name, func(t *testing.T) {
				tree, err := ParseSQLWithDialect(sql, keywords.DialectSQLServer)
				if err != nil {
					t.Fatal(err)
				}
				defer ast.ReleaseAST(tree)
				stmt := tree.Statements[0]
				before := selectSQL(t, stmt)
				if err := Apply(stmt, rule); err == nil {
					t.Fatal("expected error")
				}
				if got := selectSQL(t, stmt); got != before {
					t.Errorf("error mutated statement: %s", got)
				}
			})
		}
	}
}

func selectSQL(t *testing.T, stmt ast.Statement) string {
	t.Helper()
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SELECT, got %T", stmt)
	}
	return sel.SQL()
}

func TestSetOffsetRejectsTop(t *testing.T) {
	tree, err := ParseSQLWithDialect("SELECT TOP 5 * FROM a", keywords.DialectSQLServer)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	stmt := tree.Statements[0]
	before := selectSQL(t, stmt)
	if err := Apply(stmt, SetOffset(3)); err == nil {
		t.Fatal("expected error for TOP with OFFSET")
	}
	if got := selectSQL(t, stmt); got != before {
		t.Errorf("error mutated statement: %s", got)
	}
}

func TestPaginationLegacyFetchOffset(t *testing.T) {
	for name, tt := range map[string]struct {
		rule Rule
		want string
	}{
		"set":           {SetOffset(3), "SELECT * FROM a OFFSET 3 ROWS FETCH NEXT 5 ROWS ONLY"},
		"remove offset": {RemoveOffset(), "SELECT * FROM a FETCH NEXT 5 ROWS ONLY"},
		"remove limit":  {RemoveLimit(), "SELECT * FROM a OFFSET 2 ROWS"},
	} {
		t.Run(name, func(t *testing.T) {
			offset, count := int64(2), int64(5)
			sel := &ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "*"}}, From: []ast.TableReference{{Name: "a"}}, Fetch: &ast.FetchClause{OffsetValue: &offset, FetchValue: &count, FetchType: "NEXT"}}
			if err := Apply(sel, tt.rule); err != nil {
				t.Fatal(err)
			}
			if got := sel.SQL(); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
			if got := strings.TrimSuffix(format(sel), ";"); got != tt.want {
				t.Errorf("formatter got %q, want %q", got, tt.want)
			}
		})
	}
}
