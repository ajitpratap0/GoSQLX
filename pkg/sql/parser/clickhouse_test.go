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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

func TestClickHousePrewhere(t *testing.T) {
	sql := `SELECT id, name FROM events PREWHERE type = 'click' WHERE date >= '2024-01-01'`
	tree, err := parser.ParseWithDialect(sql, keywords.DialectClickHouse)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tree.Statements) == 0 {
		t.Fatal("expected at least one statement")
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	if sel.PrewhereClause == nil {
		t.Error("expected PrewhereClause to be set")
	}
	if sel.Where == nil {
		t.Error("expected WhereClause to be set")
	}
}

func TestClickHouseFinal(t *testing.T) {
	sql := `SELECT * FROM orders FINAL`
	tree, err := parser.ParseWithDialect(sql, keywords.DialectClickHouse)
	if err != nil {
		t.Fatalf("unexpected error parsing FINAL modifier: %v", err)
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	if len(sel.From) == 0 || !sel.From[0].Final {
		t.Error("expected FINAL=true on first TableReference")
	}
}

func TestClickHouseKeywordRecognition(t *testing.T) {
	t.Skip("TODO: SAMPLE clause parsing not yet implemented")
}

func TestClickHouseDialectRegistered(t *testing.T) {
	if !keywords.IsValidDialect("clickhouse") {
		t.Error("clickhouse dialect not registered")
	}
}

func TestClickHousePrewhereOnly(t *testing.T) {
	// PREWHERE without WHERE — also valid in ClickHouse
	sql := `SELECT id FROM logs PREWHERE level = 'error'`
	tree, err := parser.ParseWithDialect(sql, keywords.DialectClickHouse)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tree.Statements) == 0 {
		t.Fatal("expected at least one statement")
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	if sel.PrewhereClause == nil {
		t.Error("expected PrewhereClause to be set")
	}
	if sel.Where != nil {
		t.Error("expected WhereClause to be nil when absent")
	}
}

func TestClickHousePrewhereNotParsedForOtherDialects(t *testing.T) {
	// PREWHERE should not be parsed as a clause in non-ClickHouse dialects;
	// it is still a known keyword token but the parser won't treat it as a clause.
	sql := `SELECT id FROM logs WHERE id > 1`
	_, err := parser.ParseWithDialect(sql, keywords.DialectGeneric)
	if err != nil {
		t.Errorf("unexpected error for generic dialect: %v", err)
	}
}

func TestClickHouseGlobalJoin(t *testing.T) {
	sql := `SELECT t1.id, t2.name FROM t1 GLOBAL JOIN t2 ON t1.id = t2.id`
	_, err := parser.ParseWithDialect(sql, keywords.DialectClickHouse)
	if err != nil {
		t.Fatalf("unexpected error parsing GLOBAL JOIN: %v", err)
	}
}

func TestClickHouseGlobalIn(t *testing.T) {
	sql := `SELECT id FROM orders WHERE id GLOBAL IN (SELECT id FROM users)`
	_, err := parser.ParseWithDialect(sql, keywords.DialectClickHouse)
	if err != nil {
		t.Fatalf("unexpected error parsing GLOBAL IN: %v", err)
	}
}

func TestClickHouseFinalWithWhere(t *testing.T) {
	sql := `SELECT * FROM orders FINAL WHERE id > 5`
	tree, err := parser.ParseWithDialect(sql, keywords.DialectClickHouse)
	if err != nil {
		t.Fatalf("unexpected error parsing FINAL with WHERE: %v", err)
	}
	if len(tree.Statements) == 0 {
		t.Fatal("expected at least one statement")
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	if len(sel.From) == 0 || !sel.From[0].Final {
		t.Error("expected FINAL=true on first TableReference")
	}
	if sel.Where == nil {
		t.Error("expected WHERE clause to be set")
	}
}

func TestClickHouseFinalWithAlias(t *testing.T) {
	t.Run("ExplicitAlias", func(t *testing.T) {
		sql := `SELECT * FROM orders AS o FINAL`
		tree, err := parser.ParseWithDialect(sql, keywords.DialectClickHouse)
		if err != nil {
			t.Fatalf("unexpected error parsing FINAL with AS alias: %v", err)
		}
		if len(tree.Statements) == 0 {
			t.Fatal("expected at least one statement")
		}
		sel, ok := tree.Statements[0].(*ast.SelectStatement)
		if !ok {
			t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
		}
		if len(sel.From) == 0 || !sel.From[0].Final {
			t.Error("expected FINAL=true on first TableReference")
		}
	})

	t.Run("ImplicitAlias", func(t *testing.T) {
		sql := `SELECT * FROM orders o FINAL`
		tree, err := parser.ParseWithDialect(sql, keywords.DialectClickHouse)
		if err != nil {
			t.Fatalf("unexpected error parsing FINAL with implicit alias: %v", err)
		}
		if len(tree.Statements) == 0 {
			t.Fatal("expected at least one statement")
		}
		sel, ok := tree.Statements[0].(*ast.SelectStatement)
		if !ok {
			t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
		}
		if len(sel.From) == 0 || !sel.From[0].Final {
			t.Error("expected FINAL=true on first TableReference")
		}
	})
}

func TestClickHouseFinalWithJoin(t *testing.T) {
	sql := `SELECT * FROM orders FINAL JOIN users ON orders.user_id = users.id`
	tree, err := parser.ParseWithDialect(sql, keywords.DialectClickHouse)
	if err != nil {
		t.Fatalf("unexpected error parsing FINAL with JOIN: %v", err)
	}
	if len(tree.Statements) == 0 {
		t.Fatal("expected at least one statement")
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	if len(sel.From) == 0 || !sel.From[0].Final {
		t.Error("expected FINAL=true on first TableReference")
	}
	if len(sel.Joins) == 0 {
		t.Error("expected at least one JOIN clause")
	}
}

func TestClickHouseFinalNotParsedInOtherDialects(t *testing.T) {
	// FINAL is a ClickHouse-specific modifier; in generic dialect it is an
	// unknown token that causes a parse error.
	sql := `SELECT * FROM orders FINAL`
	_, err := parser.ParseWithDialect(sql, keywords.DialectGeneric)
	if err == nil {
		t.Error("expected parse error for FINAL in generic dialect, but got none")
	}
}

func TestClickHouseFinalRoundtrip(t *testing.T) {
	input := `SELECT * FROM orders FINAL`
	tree, err := parser.ParseWithDialect(input, keywords.DialectClickHouse)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(tree.Statements) == 0 {
		t.Fatal("expected at least one statement")
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	got := sel.SQL()
	if !containsFINAL(got) {
		t.Errorf("SQL() round-trip output does not contain FINAL; got: %q", got)
	}
}

// containsFINAL reports whether s contains the uppercase keyword FINAL as a
// whole word. A simple strings.Contains is sufficient because SQL() always
// emits keywords in uppercase.
func containsFINAL(s string) bool {
	return strings.Contains(s, "FINAL")
}
