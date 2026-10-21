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

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestParse_CompoundKeywordCase_Issue842 checks that compound keywords the
// tokenizer emits as one generic keyword token (CROSS JOIN, FULL JOIN,
// GROUPING SETS) parse in any letter case, like the other join keywords.
func TestParse_CompoundKeywordCase_Issue842(t *testing.T) {
	joins := []struct {
		sql, joinType string
	}{
		{"select * from t cross join t2", "CROSS"},
		{"SELECT * FROM t cross join t2", "CROSS"},
		{"select * from t Cross Join t2", "CROSS"},
		{"select * from t CROSS JOIN t2", "CROSS"},
		{"select * from t cross\n  join t2", "CROSS"},
		{"select * from t full join t2 on true", "FULL"},
		{"select * from t Full Join t2 on t.a = t2.a", "FULL"},
		{"select * from t full outer join t2 on true", "FULL"},
		{"select * from t left outer join t2 on true", "LEFT"},
		{"select * from t inner join t2 on true", "INNER"},
	}
	for _, d := range []keywords.SQLDialect{"", keywords.DialectPostgreSQL, keywords.DialectMySQL} {
		for _, tc := range joins {
			t.Run(string(d)+"/"+tc.sql, func(t *testing.T) {
				tree, err := ParseWithDialect(tc.sql, d)
				if err != nil {
					t.Fatalf("ParseWithDialect(%q, %q): %v", tc.sql, d, err)
				}
				defer ast.ReleaseAST(tree)
				sel, ok := tree.Statements[0].(*ast.SelectStatement)
				if !ok {
					t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
				}
				if len(sel.Joins) != 1 {
					t.Fatalf("got %d joins, want 1", len(sel.Joins))
				}
				if sel.Joins[0].Type != tc.joinType {
					t.Errorf("join type = %q, want %q", sel.Joins[0].Type, tc.joinType)
				}
			})
		}
	}

	for _, sql := range []string{
		"select a from t group by grouping sets ((a), ())",
		"SELECT a FROM t GROUP BY Grouping Sets ((a), ())",
	} {
		t.Run(sql, func(t *testing.T) {
			tree, err := ParseWithDialect(sql, keywords.DialectPostgreSQL)
			if err != nil {
				t.Fatalf("ParseWithDialect(%q): %v", sql, err)
			}
			defer ast.ReleaseAST(tree)
			sel, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
			}
			if len(sel.GroupBy) != 1 {
				t.Fatalf("got %d GROUP BY items, want 1", len(sel.GroupBy))
			}
			if _, ok := sel.GroupBy[0].(*ast.GroupingSetsExpression); !ok {
				t.Errorf("GROUP BY item = %T, want *ast.GroupingSetsExpression", sel.GroupBy[0])
			}
		})
	}
}

// TestParse_CompoundKeywordValueInStringLiteral checks that a string literal
// spelled like a compound keyword stays a literal.
func TestParse_CompoundKeywordValueInStringLiteral(t *testing.T) {
	for _, sql := range []string{
		"SELECT 'cross join' FROM t",
		"SELECT 'CROSS JOIN' FROM t",
		"SELECT * FROM t WHERE a = 'grouping sets'",
	} {
		tree, err := ParseWithDialect(sql, keywords.DialectPostgreSQL)
		if err != nil {
			t.Fatalf("ParseWithDialect(%q): %v", sql, err)
		}
		sel, ok := tree.Statements[0].(*ast.SelectStatement)
		if !ok {
			t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
		}
		if len(sel.Joins) != 0 {
			t.Errorf("%q: got %d joins, want 0", sql, len(sel.Joins))
		}
		ast.ReleaseAST(tree)
	}
}
