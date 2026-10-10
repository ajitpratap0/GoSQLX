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

// TestParseWithDialect_QuestionMarkPlaceholder verifies that a bare `?` parses
// as a placeholder literal end-to-end for MySQL, MariaDB, and SQLite.
func TestParseWithDialect_QuestionMarkPlaceholder(t *testing.T) {
	dialects := []keywords.SQLDialect{
		keywords.DialectMySQL,
		keywords.DialectMariaDB,
		keywords.DialectSQLite,
	}

	for _, dialect := range dialects {
		t.Run(string(dialect), func(t *testing.T) {
			tree, err := ParseWithDialect("SELECT * FROM users WHERE id = ?", dialect)
			if err != nil {
				t.Fatalf("ParseWithDialect(%q) error = %v", dialect, err)
			}
			defer ast.ReleaseAST(tree)

			stmt, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
			}

			where, ok := stmt.Where.(*ast.BinaryExpression)
			if !ok {
				t.Fatalf("expected WHERE to be *ast.BinaryExpression, got %T", stmt.Where)
			}

			lit, ok := where.Right.(*ast.LiteralValue)
			if !ok {
				t.Fatalf("expected right side to be *ast.LiteralValue, got %T", where.Right)
			}
			if lit.Type != "placeholder" {
				t.Errorf("expected placeholder type, got %q", lit.Type)
			}
			if lit.Value != "?" {
				t.Errorf("expected placeholder value %q, got %q", "?", lit.Value)
			}
		})
	}
}
