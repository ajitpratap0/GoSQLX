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

// Package parser - oracle_bind_param_test.go
// Tests for Oracle bind variables (:1, :name) in parsed statements (issue #520).

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestParseWithDialect_OracleBindVariables(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		wantSQL string
	}{
		{"issue 520", "SELECT a, b FROM virtual_fund WHERE virtual_fund_id = :1", "SELECT a, b FROM virtual_fund WHERE virtual_fund_id = :1"},
		{"two positional", "SELECT * FROM t WHERE a = :1 AND b = :2", "SELECT * FROM t WHERE a = :1 AND b = :2"},
		{"named", "SELECT * FROM t WHERE name = :name", "SELECT * FROM t WHERE name = :name"},
		{"insert values", "INSERT INTO t (a, b) VALUES (:1, :b)", "INSERT INTO t (a, b) VALUES (:1, :b)"},
		{"update set", "UPDATE t SET a = :new_a WHERE id = :id", "UPDATE t SET a = :new_a WHERE id = :id"},
		{"delete", "DELETE FROM t WHERE id = :id", "DELETE FROM t WHERE id = :id"},
		{"no space", "SELECT * FROM t WHERE a=:1", "SELECT * FROM t WHERE a = :1"},
		{"in list", "SELECT * FROM t WHERE a IN (:1, :2, :3)", "SELECT * FROM t WHERE a IN (:1, :2, :3)"},
		{"between", "SELECT * FROM t WHERE a BETWEEN :lo AND :hi", "SELECT * FROM t WHERE a BETWEEN :lo AND :hi"},
		{"rownum", "SELECT * FROM t WHERE ROWNUM <= :n", "SELECT * FROM t WHERE ROWNUM <= :n"},
		{"function arg", "SELECT NVL(:p1, 0) FROM dual", "SELECT NVL(:p1, 0) FROM dual"},
		{"keyword-named", "SELECT * FROM t WHERE lvl = :level AND d = :date", "SELECT * FROM t WHERE lvl = :level AND d = :date"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := ParseWithDialect(tt.sql, keywords.DialectOracle)
			if err != nil {
				t.Fatalf("ParseWithDialect(%q) error = %v", tt.sql, err)
			}
			defer ast.ReleaseAST(tree)
			if len(tree.Statements) != 1 {
				t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
			}
			s, ok := tree.Statements[0].(interface{ SQL() string })
			if !ok {
				t.Fatalf("statement %T has no SQL() method", tree.Statements[0])
			}
			if got := s.SQL(); got != tt.wantSQL {
				t.Errorf("SQL() = %q, want %q", got, tt.wantSQL)
			}
		})
	}
}

func TestParseWithDialect_OracleBindASTShape(t *testing.T) {
	tree, err := ParseWithDialect("SELECT a, b FROM virtual_fund WHERE virtual_fund_id = :1", keywords.DialectOracle)
	if err != nil {
		t.Fatalf("ParseWithDialect error = %v", err)
	}
	defer ast.ReleaseAST(tree)

	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
	}
	bin, ok := sel.Where.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected *ast.BinaryExpression in WHERE, got %T", sel.Where)
	}
	lit, ok := bin.Right.(*ast.LiteralValue)
	if !ok {
		t.Fatalf("expected *ast.LiteralValue on the right, got %T", bin.Right)
	}
	if lit.Type != "placeholder" || lit.Value != ":1" {
		t.Errorf("got LiteralValue{Type:%q, Value:%v}, want placeholder :1", lit.Type, lit.Value)
	}
}

// Array slicing outside Oracle must keep using COLON.
func TestParseWithDialect_ColonSliceUnchangedOutsideOracle(t *testing.T) {
	for _, sql := range []string{
		"SELECT arr[1:n] FROM t",
		"SELECT arr[:n] FROM t",
	} {
		t.Run(sql, func(t *testing.T) {
			tree, err := ParseWithDialect(sql, keywords.DialectPostgreSQL)
			if err != nil {
				t.Fatalf("ParseWithDialect(%q) error = %v", sql, err)
			}
			defer ast.ReleaseAST(tree)
			s, ok := tree.Statements[0].(interface{ SQL() string })
			if !ok {
				t.Fatalf("statement %T has no SQL() method", tree.Statements[0])
			}
			if got := s.SQL(); got != sql {
				t.Errorf("SQL() = %q, want %q", got, sql)
			}
		})
	}
}
