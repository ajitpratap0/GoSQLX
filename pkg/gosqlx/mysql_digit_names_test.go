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
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestMySQLDigitLeadingNamesUseBackticks checks that bare digit-leading
// MySQL names are delimited with backticks wherever they appear: "1col" would
// be a string literal in MySQL's default mode.
func TestMySQLDigitLeadingNamesUseBackticks(t *testing.T) {
	for _, tc := range []struct{ sql, want string }{
		{"SELECT 1col FROM t", "SELECT `1col` FROM t"},
		{"SELECT t.1col FROM t", "SELECT t.`1col` FROM t"},
		{"SELECT db.t.1col FROM db.t", "SELECT db.t.`1col` FROM db.t"},
		{"SELECT a FROM 1tbl", "SELECT a FROM `1tbl`"},
		{"SELECT a FROM db.1tbl t", "SELECT a FROM db.`1tbl` t"},
		{"UPDATE t SET t.1col = 1", "UPDATE t SET t.`1col` = 1"},
	} {
		t.Run(tc.sql, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, keywords.DialectMySQL)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			defer ast.ReleaseAST(tree)
			if got := tree.SQL(); got != tc.want {
				t.Errorf("SQL() = %q, want %q", got, tc.want)
			}
		})
	}
}
