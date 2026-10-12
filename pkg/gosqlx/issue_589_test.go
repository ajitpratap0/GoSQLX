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

// Package gosqlx - issue_589_test.go
// End-to-end regression tests for GitHub issue #589: the numeric offset of a
// window-frame bound (ROWS/RANGE ... <n> PRECEDING/FOLLOWING) must survive both
// the ast.SQL() serializer and the formatter. Before the fix the offset was
// dropped, producing invalid SQL (e.g. "ROWS BETWEEN PRECEDING AND ...").

package gosqlx

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
)

func TestIssue589_NumericWindowFrameBoundsRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want string
	}{
		{
			name: "BETWEEN 1 PRECEDING AND CURRENT ROW",
			sql:  "SELECT SUM(x) OVER (ORDER BY y ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM t",
			want: "ROWS BETWEEN 1 PRECEDING AND CURRENT ROW",
		},
		{
			name: "BETWEEN UNBOUNDED PRECEDING AND 2 FOLLOWING",
			sql:  "SELECT SUM(x) OVER (ORDER BY y ROWS BETWEEN UNBOUNDED PRECEDING AND 2 FOLLOWING) FROM t",
			want: "ROWS BETWEEN UNBOUNDED PRECEDING AND 2 FOLLOWING",
		},
		{
			name: "BETWEEN 2 PRECEDING AND 3 FOLLOWING",
			sql:  "SELECT SUM(x) OVER (ORDER BY y ROWS BETWEEN 2 PRECEDING AND 3 FOLLOWING) FROM t",
			want: "ROWS BETWEEN 2 PRECEDING AND 3 FOLLOWING",
		},
		{
			name: "single numeric bound 3 PRECEDING",
			sql:  "SELECT SUM(x) OVER (ORDER BY y ROWS 3 PRECEDING) FROM t",
			want: "ROWS 3 PRECEDING",
		},
		{
			name: "RANGE with numeric bound",
			sql:  "SELECT SUM(x) OVER (ORDER BY y RANGE BETWEEN 5 PRECEDING AND CURRENT ROW) FROM t",
			want: "RANGE BETWEEN 5 PRECEDING AND CURRENT ROW",
		},
		{
			name: "expression offset (1+1) PRECEDING",
			sql:  "SELECT SUM(x) OVER (ORDER BY y ROWS (1+1) PRECEDING) FROM t",
			want: "ROWS (1 + 1) PRECEDING",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := Parse(tc.sql)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tc.sql, err)
			}
			got := tree.SQL()
			if !strings.Contains(got, tc.want) {
				t.Errorf("tree.SQL() =\n  %s\nwant to contain: %s", got, tc.want)
			}

			// #589 asks that SQL() output re-parse to the same SQL (idempotent).
			reparsed, err := Parse(got)
			if err != nil {
				t.Fatalf("re-Parse(tree.SQL() = %q) error: %v", got, err)
			}
			if reparsed.SQL() != got {
				t.Errorf("tree.SQL() is not idempotent:\n first: %s\nsecond: %s", got, reparsed.SQL())
			}

			out, err := formatter.FormatString(tc.sql)
			if err != nil {
				t.Fatalf("FormatString(%q) error: %v", tc.sql, err)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("FormatString() =\n  %s\nwant to contain: %s", out, tc.want)
			}

			// Formatting is idempotent too: formatting the output again is a
			// no-op.
			out2, err := formatter.FormatString(out)
			if err != nil {
				t.Fatalf("FormatString(FormatString()) error: %v", err)
			}
			if out2 != out {
				t.Errorf("FormatString() is not idempotent:\n first: %s\nsecond: %s", out, out2)
			}
		})
	}
}
