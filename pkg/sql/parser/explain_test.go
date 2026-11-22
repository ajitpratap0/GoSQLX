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
	"fmt"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// EXPLAIN <stmt> must keep the explained statement and its options instead of
// collapsing to DESCRIBE "SELECT" or splitting into two statements.
func TestParser_ExplainStatement(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		keyword string
		options string
		inner   string // %T of the explained statement
	}{
		{keywords.DialectPostgreSQL, "EXPLAIN SELECT * FROM users WHERE id = 1", "EXPLAIN", "", "*ast.SelectStatement"},
		{keywords.DialectPostgreSQL, "EXPLAIN ANALYZE UPDATE t SET x = 1", "EXPLAIN", "ANALYZE", "*ast.UpdateStatement"},
		{keywords.DialectPostgreSQL, "explain (analyze, format json) select 1", "EXPLAIN", "(ANALYZE, FORMAT JSON)", "*ast.SelectStatement"},
		{keywords.DialectPostgreSQL, "EXPLAIN WITH c AS (SELECT 1) SELECT * FROM c", "EXPLAIN", "", "*ast.SelectStatement"},
		{keywords.DialectSQLite, "EXPLAIN QUERY PLAN SELECT * FROM t WHERE a = 2", "EXPLAIN", "QUERY PLAN", "*ast.SelectStatement"},
		{keywords.DialectMySQL, "EXPLAIN FORMAT=JSON DELETE FROM t WHERE id = 1", "EXPLAIN", "FORMAT = JSON", "*ast.DeleteStatement"},
		{keywords.DialectMySQL, "DESCRIBE ANALYZE SELECT * FROM users", "DESCRIBE", "ANALYZE", "*ast.SelectStatement"},
		{keywords.DialectClickHouse, "DESCRIBE PIPELINE SELECT count() FROM events", "DESCRIBE", "PIPELINE", "*ast.SelectStatement"},
		{keywords.DialectOracle, "EXPLAIN PLAN FOR SELECT * FROM emp", "EXPLAIN", "PLAN FOR", "*ast.SelectStatement"},
	}
	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			tree, err := ParseWithDialect(tt.sql, tt.dialect)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(tree.Statements) != 1 {
				t.Fatalf("got %d statements, want 1", len(tree.Statements))
			}
			ex, ok := tree.Statements[0].(*ast.ExplainStatement)
			if !ok {
				t.Fatalf("got %T, want *ast.ExplainStatement", tree.Statements[0])
			}
			if ex.Keyword != tt.keyword || ex.Options != tt.options {
				t.Errorf("keyword/options = %q/%q, want %q/%q", ex.Keyword, ex.Options, tt.keyword, tt.options)
			}
			if got := typeName(ex.Statement); got != tt.inner {
				t.Errorf("inner statement %s, want %s", got, tt.inner)
			}
		})
	}
}

// DESCRIBE of a table name stays a DescribeStatement.
func TestParser_DescribeTableStillDescribe(t *testing.T) {
	for _, sql := range []string{"DESCRIBE users", "DESC orders", "EXPLAIN users", "DESCRIBE TABLE db.users"} {
		tree, err := ParseWithDialect(sql, keywords.DialectMySQL)
		if err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		if _, ok := tree.Statements[0].(*ast.DescribeStatement); !ok {
			t.Errorf("%s: got %T, want *ast.DescribeStatement", sql, tree.Statements[0])
		}
	}
}

func typeName(v any) string {
	if v == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%T", v)
}
