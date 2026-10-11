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

// Package gosqlx - tests that Oracle bind variables (:1, :name) round-trip
// through ParseWithDialect and the AST-based formatter (issue #520).
package gosqlx_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestOracleBindVariables_FormatRoundTrip(t *testing.T) {
	inputs := []string{
		"SELECT a, b FROM virtual_fund WHERE virtual_fund_id = :1",
		"SELECT * FROM t WHERE name = :name",
		"INSERT INTO t (a, b) VALUES (:1, :b)",
		"UPDATE t SET a = :new_a WHERE id = :id",
	}
	for _, sql := range inputs {
		t.Run(sql, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectOracle)
			if err != nil {
				t.Fatalf("ParseWithDialect(%q) error = %v", sql, err)
			}
			defer ast.ReleaseAST(tree)
			out := formatter.FormatAST(tree, ast.CompactStyle())
			if out != sql {
				t.Fatalf("FormatAST = %q, want %q", out, sql)
			}

			tree2, err := gosqlx.ParseWithDialect(out, keywords.DialectOracle)
			if err != nil {
				t.Fatalf("re-parse of %q error = %v", out, err)
			}
			defer ast.ReleaseAST(tree2)
			if out2 := formatter.FormatAST(tree2, ast.CompactStyle()); out2 != out {
				t.Errorf("not idempotent: %q then %q", out, out2)
			}
		})
	}
}
