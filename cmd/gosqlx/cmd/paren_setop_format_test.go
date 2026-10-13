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

package cmd

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// TestParenSetOpFormat_Issue612 checks that `gosqlx format` output keeps
// set-operation operand parentheses and set-operation derived tables (#612),
// and that readable and compact output parse again to the same SQL().
func TestParenSetOpFormat_Issue612(t *testing.T) {
	cases := []struct{ sql, wantSQL, wantContains string }{
		{"SELECT * FROM (SELECT 1 UNION SELECT 2) t",
			"SELECT * FROM (SELECT 1 UNION SELECT 2) t", "UNION"},
		{"SELECT * FROM ((SELECT 1) UNION (SELECT 2)) t",
			"SELECT * FROM ((SELECT 1) UNION (SELECT 2)) t", "((SELECT"},
		{"(SELECT 1) UNION (SELECT 2)",
			"(SELECT 1) UNION (SELECT 2)", "(SELECT"},
		{"SELECT a FROM t EXCEPT (SELECT a FROM u UNION SELECT a FROM v)",
			"SELECT a FROM t EXCEPT (SELECT a FROM u UNION SELECT a FROM v)", "(SELECT"},
		{"SELECT * FROM t1 JOIN (SELECT 1 UNION SELECT 2) t ON t1.a = t.a",
			"SELECT * FROM t1 INNER JOIN (SELECT 1 UNION SELECT 2) t ON t1.a = t.a", "UNION"},
	}
	for _, tc := range cases {
		for _, compact := range []bool{false, true} {
			tree, err := parser.ParseWithDialect(tc.sql, "postgresql")
			if err != nil {
				t.Fatalf("%q: parse: %v", tc.sql, err)
			}
			f := NewSQLFormatter(FormatterOptions{Compact: compact, UppercaseKw: true})
			out, err := f.Format(tree)
			ast.ReleaseAST(tree)
			if err != nil {
				t.Fatalf("%q (compact=%v): format: %v", tc.sql, compact, err)
			}
			if !strings.Contains(out, tc.wantContains) {
				t.Errorf("%q (compact=%v): output %q does not contain %q", tc.sql, compact, out, tc.wantContains)
			}
			tree2, err := parser.ParseWithDialect(out, "postgresql")
			if err != nil {
				t.Errorf("%q (compact=%v): output %q does not re-parse: %v", tc.sql, compact, out, err)
				continue
			}
			if got := tree2.SQL(); got != tc.wantSQL {
				t.Errorf("%q (compact=%v): output %q re-parses to %q, want %q", tc.sql, compact, out, got, tc.wantSQL)
			}
			ast.ReleaseAST(tree2)
		}
	}
}
