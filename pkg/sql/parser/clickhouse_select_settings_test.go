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

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func parseClickHouseSelect(t *testing.T, sql string) *ast.AST {
	t.Helper()
	tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectClickHouse)
	if err != nil {
		t.Fatalf("parse %q: %v", sql, err)
	}
	if len(tree.Statements) == 0 {
		t.Fatalf("parse %q: no statements", sql)
	}
	return tree
}

// TestClickHouseSelectSettings_Stored verifies that ClickHouse SELECT ...
// SETTINGS assignments are stored on the SelectStatement instead of being
// skipped (#600).
func TestClickHouseSelectSettings_Stored(t *testing.T) {
	t.Run("two_settings", func(t *testing.T) {
		tree := parseClickHouseSelect(t, "SELECT a FROM t SETTINGS max_threads = 4, join_algorithm = 'hash'")
		sel, ok := tree.Statements[0].(*ast.SelectStatement)
		if !ok {
			t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
		}
		if len(sel.Settings) != 2 {
			t.Fatalf("len(Settings) = %d, want 2", len(sel.Settings))
		}
		wantNames := []string{"max_threads", "join_algorithm"}
		for i, s := range sel.Settings {
			if s.Name != wantNames[i] {
				t.Errorf("Settings[%d].Name = %q, want %q", i, s.Name, wantNames[i])
			}
			if _, ok := s.Value.(*ast.LiteralValue); !ok {
				t.Errorf("Settings[%d].Value = %T, want *ast.LiteralValue", i, s.Value)
			}
			if s.Pos.IsZero() {
				t.Errorf("Settings[%d].Pos is zero", i)
			}
		}
	})

	t.Run("union_rightmost", func(t *testing.T) {
		tree := parseClickHouseSelect(t, "SELECT a FROM t UNION ALL SELECT b FROM u SETTINGS max_threads = 4")
		so, ok := tree.Statements[0].(*ast.SetOperation)
		if !ok {
			t.Fatalf("expected *ast.SetOperation, got %T", tree.Statements[0])
		}
		left, ok := so.Left.(*ast.SelectStatement)
		if !ok {
			t.Fatalf("Left: expected *ast.SelectStatement, got %T", so.Left)
		}
		right, ok := so.Right.(*ast.SelectStatement)
		if !ok {
			t.Fatalf("Right: expected *ast.SelectStatement, got %T", so.Right)
		}
		if len(left.Settings) != 0 {
			t.Errorf("Left has %d settings, want 0", len(left.Settings))
		}
		if len(right.Settings) != 1 || right.Settings[0].Name != "max_threads" {
			t.Errorf("Right.Settings = %+v, want [max_threads]", right.Settings)
		}
	})

	t.Run("three_way_union_rightmost", func(t *testing.T) {
		tree := parseClickHouseSelect(t, "SELECT a FROM t UNION ALL SELECT b FROM u UNION ALL SELECT c FROM v SETTINGS max_threads = 4")
		var count int
		var last *ast.SelectStatement
		var walk func(st ast.Statement)
		walk = func(st ast.Statement) {
			switch n := st.(type) {
			case *ast.SetOperation:
				walk(n.Left)
				walk(n.Right)
			case *ast.SelectStatement:
				count += len(n.Settings)
				last = n
			}
		}
		walk(tree.Statements[0])
		if count != 1 {
			t.Fatalf("total settings = %d, want 1", count)
		}
		if last == nil || len(last.Settings) != 1 {
			t.Fatalf("rightmost select does not hold the setting")
		}
		if got, want := tree.SQL(), "SELECT a FROM t UNION ALL SELECT b FROM u UNION ALL SELECT c FROM v SETTINGS max_threads = 4"; got != want {
			t.Errorf("SQL() = %q, want %q", got, want)
		}
	})

	t.Run("format_suffix", func(t *testing.T) {
		tree := parseClickHouseSelect(t, "SELECT a FROM t SETTINGS max_threads = 4 FORMAT JSON")
		sel, ok := tree.Statements[0].(*ast.SelectStatement)
		if !ok {
			t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
		}
		if len(sel.Settings) != 1 {
			t.Fatalf("len(Settings) = %d, want 1", len(sel.Settings))
		}
	})

	t.Run("followed_by_statement", func(t *testing.T) {
		tree := parseClickHouseSelect(t, "SELECT a FROM t SETTINGS max_threads = 4; SELECT 1")
		if len(tree.Statements) != 2 {
			t.Fatalf("got %d statements, want 2", len(tree.Statements))
		}
		sel, ok := tree.Statements[0].(*ast.SelectStatement)
		if !ok {
			t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
		}
		if len(sel.Settings) != 1 {
			t.Fatalf("len(Settings) = %d, want 1", len(sel.Settings))
		}
	})
}

// TestClickHouseSelectSettings_Errors verifies that malformed SETTINGS lists,
// which the old skip loop silently accepted, are now syntax errors (#600).
func TestClickHouseSelectSettings_Errors(t *testing.T) {
	bad := []string{
		"SELECT a FROM t SETTINGS",
		"SELECT a FROM t SETTINGS max_threads",
		"SELECT a FROM t SETTINGS max_threads =",
		"SELECT a FROM t SETTINGS = 4",
		"SELECT a FROM t SETTINGS max_threads = 4,",
	}
	for _, sql := range bad {
		if _, err := gosqlx.ParseWithDialect(sql, keywords.DialectClickHouse); err == nil {
			t.Errorf("expected error for %q", sql)
		}
	}

	for _, d := range []keywords.SQLDialect{keywords.DialectGeneric, keywords.DialectPostgreSQL} {
		if _, err := gosqlx.ParseWithDialect("SELECT a FROM t", d); err != nil {
			t.Errorf("%s: SELECT a FROM t: %v", d, err)
		}
	}
}
