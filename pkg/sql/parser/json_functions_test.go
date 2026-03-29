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

// Package parser — json_functions_test.go
// Tests for JSON function parsing (JSON_OBJECT, JSON_ARRAY, JSON_EXTRACT, JSON_AGG, etc.)

package parser

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestParser_JSONObject_MySQL(t *testing.T) {
	sql := `SELECT JSON_OBJECT('name', u.name, 'age', u.age) AS profile FROM users u`
	tree := parseSQL(t, sql)

	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	if len(sel.Columns) == 0 {
		t.Fatal("expected columns")
	}
	// Column is AliasedExpression{Expr: FunctionCall, Alias: "profile"} due to AS alias.
	aliased, ok := sel.Columns[0].(*ast.AliasedExpression)
	if !ok {
		t.Fatalf("expected AliasedExpression, got %T", sel.Columns[0])
	}
	fn, ok := aliased.Expr.(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected FunctionCall, got %T", aliased.Expr)
	}
	if !strings.EqualFold(fn.Name, "JSON_OBJECT") {
		t.Errorf("function name: got %q want JSON_OBJECT", fn.Name)
	}
	if len(fn.Arguments) != 4 {
		t.Errorf("args: got %d want 4 (2 key-value pairs)", len(fn.Arguments))
	}
}

func TestParser_JSONBuildArray_Postgres(t *testing.T) {
	sql := `SELECT JSON_BUILD_ARRAY(1, 2, 3) AS arr`
	tree := parseSQL(t, sql)

	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	// Column is AliasedExpression{Expr: FunctionCall, Alias: "arr"} due to AS alias.
	aliased, ok := sel.Columns[0].(*ast.AliasedExpression)
	if !ok {
		t.Fatalf("expected AliasedExpression, got %T", sel.Columns[0])
	}
	fn, ok := aliased.Expr.(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected FunctionCall, got %T", aliased.Expr)
	}
	if !strings.EqualFold(fn.Name, "JSON_BUILD_ARRAY") {
		t.Errorf("function: got %q want JSON_BUILD_ARRAY", fn.Name)
	}
	if len(fn.Arguments) != 3 {
		t.Errorf("args: got %d want 3", len(fn.Arguments))
	}
}

func TestParser_JSONExtract_MySQL(t *testing.T) {
	sql := `SELECT JSON_EXTRACT(data, '$.name') FROM records`
	tree := parseSQL(t, sql)

	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	fn, ok := sel.Columns[0].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected FunctionCall, got %T", sel.Columns[0])
	}
	if !strings.EqualFold(fn.Name, "JSON_EXTRACT") {
		t.Errorf("function: got %q want JSON_EXTRACT", fn.Name)
	}
	if len(fn.Arguments) != 2 {
		t.Errorf("args: got %d want 2", len(fn.Arguments))
	}
}

func TestParser_JSONAgg_Postgres(t *testing.T) {
	sql := `SELECT JSON_AGG(id) FROM users`
	tree := parseSQL(t, sql)

	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	fn, ok := sel.Columns[0].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected FunctionCall, got %T", sel.Columns[0])
	}
	if !strings.EqualFold(fn.Name, "JSON_AGG") {
		t.Errorf("function: got %q want JSON_AGG", fn.Name)
	}
}

func TestParser_JSONBuildObject_Postgres(t *testing.T) {
	sql := `SELECT JSON_BUILD_OBJECT('id', id, 'name', name) FROM users`
	tree := parseSQL(t, sql)

	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	fn, ok := sel.Columns[0].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected FunctionCall, got %T", sel.Columns[0])
	}
	if !strings.EqualFold(fn.Name, "JSON_BUILD_OBJECT") {
		t.Errorf("function: got %q want JSON_BUILD_OBJECT", fn.Name)
	}
	if len(fn.Arguments) != 4 {
		t.Errorf("args: got %d want 4", len(fn.Arguments))
	}
}

func TestParser_JSONArrow_Postgres(t *testing.T) {
	// PostgreSQL JSON operators: -> and ->>
	sql := `SELECT data->>'name' AS name FROM records WHERE data->'age' > '18'`
	tree := parseSQL(t, sql)
	if len(tree.Statements) == 0 {
		t.Fatal("expected at least one statement")
	}
	// The important check: it parses without error
	if _, ok := tree.Statements[0].(*ast.SelectStatement); !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
}

func TestParser_JSONValue_Standard(t *testing.T) {
	sql := `SELECT JSON_VALUE(data, '$.name') FROM records`
	tree := parseSQL(t, sql)

	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	fn, ok := sel.Columns[0].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected FunctionCall, got %T", sel.Columns[0])
	}
	if !strings.EqualFold(fn.Name, "JSON_VALUE") {
		t.Errorf("function: got %q want JSON_VALUE", fn.Name)
	}
}

func TestParser_JSONContains_MySQL(t *testing.T) {
	sql := `SELECT id FROM products WHERE JSON_CONTAINS(tags, '"electronics"')`
	tree := parseSQL(t, sql)
	if len(tree.Statements) == 0 {
		t.Fatal("expected at least one statement")
	}
}

func TestParser_JSONSet_MySQL(t *testing.T) {
	sql := `UPDATE users SET data = JSON_SET(data, '$.score', 100) WHERE id = 1`
	tree := parseSQL(t, sql)
	if len(tree.Statements) == 0 {
		t.Fatal("expected at least one statement")
	}
}

func TestParser_JSONBAgg_Postgres(t *testing.T) {
	sql := `SELECT JSONB_AGG(row_to_json(t)) FROM (SELECT id, name FROM users) t`
	tree := parseSQL(t, sql)
	if len(tree.Statements) == 0 {
		t.Fatal("expected at least one statement")
	}
}

func TestParser_ToJSON_Postgres(t *testing.T) {
	sql := `SELECT TO_JSON(ARRAY[1,2,3]) AS arr`
	tree := parseSQL(t, sql)
	if len(tree.Statements) == 0 {
		t.Fatal("expected at least one statement")
	}
}

func TestParser_JSONArrayAgg_MySQL(t *testing.T) {
	sql := `SELECT JSON_ARRAYAGG(name) FROM users GROUP BY dept`
	tree := parseSQL(t, sql)

	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	fn, ok := sel.Columns[0].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected FunctionCall, got %T", sel.Columns[0])
	}
	if !strings.EqualFold(fn.Name, "JSON_ARRAYAGG") {
		t.Errorf("function: got %q want JSON_ARRAYAGG", fn.Name)
	}
}

func TestParser_JSONLength_MySQL(t *testing.T) {
	sql := `SELECT JSON_LENGTH(tags) FROM products WHERE JSON_LENGTH(tags) > 2`
	tree := parseSQL(t, sql)
	if len(tree.Statements) == 0 {
		t.Fatal("expected at least one statement")
	}
}
