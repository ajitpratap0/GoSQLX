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

package formatter_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestFormatAST_ClickHouseParametricAggregates locks in that the library
// formatter keeps the params group of ClickHouse parametric aggregates
// (issue #531): quantile(0.5)(x) must not render as quantile(x).
func TestFormatAST_ClickHouseParametricAggregates(t *testing.T) {
	cases := []struct {
		sql  string
		call string // fn(params)(args) substring that must survive
	}{
		{"SELECT quantileTDigest(0.95)(value) FROM events", "quantileTDigest(0.95)(value)"},
		{"SELECT topK(10)(name) FROM users", "topK(10)(name)"},
		{"SELECT quantiles(0.5, 0.9, 0.99)(latency_ms) FROM requests", "quantiles(0.5, 0.9, 0.99)(latency_ms)"},
		{"SELECT category, quantileTDigest(0.99)(price) FROM products GROUP BY category", "quantileTDigest(0.99)(price)"},
		{"SELECT quantileIf(0.5)(x, y > 0) FROM t", "quantileIf(0.5)(x, y > 0)"},
		{"SELECT quantile(0.5)(x) AS p50 FROM t WHERE a = 1", "quantile(0.5)(x)"},
		{"SELECT sequenceMatch('(?1)(?2)')(ts, e = 1, e = 2) FROM t", "sequenceMatch('(?1)(?2)')(ts, e = 1, e = 2)"},
		{"SELECT quantile(0.9)(x) OVER (PARTITION BY k) FROM t", "quantile(0.9)(x) OVER (PARTITION BY k)"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.call, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, keywords.DialectClickHouse)
			if err != nil {
				t.Fatalf("ParseWithDialect(%q) failed: %v", tc.sql, err)
			}

			compact := formatter.FormatAST(tree, ast.CompactStyle())
			if compact != tc.sql {
				t.Fatalf("FormatAST(CompactStyle) mismatch\n got: %q\nwant: %q", compact, tc.sql)
			}

			readable := formatter.FormatAST(tree, ast.ReadableStyle())
			if !strings.Contains(readable, tc.call) {
				t.Fatalf("FormatAST(ReadableStyle) lost %q:\n%s", tc.call, readable)
			}

			// Round trip: formatter output -> parse -> SQL() returns the input.
			reparsed, err := gosqlx.ParseWithDialect(compact, keywords.DialectClickHouse)
			if err != nil {
				t.Fatalf("re-parse of %q failed: %v", compact, err)
			}
			if got := reparsed.SQL(); got != tc.sql {
				t.Fatalf("SQL() round trip mismatch\n got: %q\nwant: %q", got, tc.sql)
			}
		})
	}
}
