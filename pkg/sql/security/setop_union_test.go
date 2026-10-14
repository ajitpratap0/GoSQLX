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

package security

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// countUnionSystemTableFindings counts CRITICAL UNION-based system-table findings.
func countUnionSystemTableFindings(res *ScanResult) int {
	n := 0
	for _, f := range res.Findings {
		if f.Pattern == PatternUnionBased && f.Severity == SeverityCritical {
			n++
		}
	}
	return n
}

// Regression for the #612 follow-up: parenthesized set-operation operands are
// parsed into right-nested SetOperation trees. The UNION check must inspect
// every SELECT on the right-hand side of a UNION, including the leftmost
// SELECT of a parenthesized group, and must not report the same operand twice.
func TestScan_UnionInjectionInNestedSetOperations(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want int
	}{
		{
			name: "left-associative chain (baseline)",
			sql:  "SELECT a, b FROM t WHERE id = 1 UNION SELECT NULL, NULL FROM pg_user UNION SELECT 1, 2",
			want: 1,
		},
		{
			name: "parenthesized right group, system table leftmost",
			sql:  "SELECT a, b FROM t WHERE id = 1 UNION (SELECT NULL, NULL FROM pg_user UNION SELECT 1, 2)",
			want: 1,
		},
		{
			name: "parenthesized right group, system table rightmost",
			sql:  "SELECT a FROM t UNION (SELECT 1 FROM t2 UNION SELECT a FROM pg_shadow)",
			want: 1,
		},
		{
			name: "parenthesized right group, both operands system tables",
			sql:  "SELECT a FROM t UNION (SELECT a FROM pg_user UNION SELECT a FROM pg_shadow)",
			want: 2,
		},
		{
			name: "doubly nested parenthesized UNIONs",
			sql:  "SELECT a FROM t UNION (SELECT 1 FROM t2 UNION (SELECT a FROM pg_user UNION SELECT 2 FROM t3))",
			want: 1,
		},
		{
			name: "EXCEPT inside UNION right operand",
			sql:  "SELECT a FROM t UNION ALL (SELECT a FROM pg_user EXCEPT SELECT a FROM t2)",
			want: 1,
		},
		{
			name: "INTERSECT inside UNION right operand, system table rightmost",
			sql:  "SELECT a FROM t UNION (SELECT a FROM t2 INTERSECT SELECT a FROM pg_shadow)",
			want: 1,
		},
		{
			name: "system table only in the original (leftmost) query",
			sql:  "SELECT a FROM pg_user UNION (SELECT a FROM t UNION SELECT a FROM t2)",
			want: 0,
		},
		{
			name: "parenthesized left group is not a UNION operand",
			sql:  "(SELECT a FROM pg_user EXCEPT SELECT a FROM t) UNION SELECT a FROM t2",
			want: 0,
		},
		{
			name: "parenthesized left group containing a UNION",
			sql:  "(SELECT a FROM t UNION SELECT a FROM pg_shadow) EXCEPT SELECT a FROM t2",
			want: 1,
		},
		{
			name: "no UNION anywhere",
			sql:  "SELECT a FROM t EXCEPT (SELECT a FROM pg_user INTERSECT SELECT a FROM t2)",
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := parseForScan(t, tt.sql)
			defer ast.ReleaseAST(tree)
			res := NewScanner().Scan(tree)
			if got := countUnionSystemTableFindings(res); got != tt.want {
				t.Fatalf("UNION system-table findings = %d, want %d; findings: %+v", got, tt.want, res.Findings)
			}
		})
	}
}
