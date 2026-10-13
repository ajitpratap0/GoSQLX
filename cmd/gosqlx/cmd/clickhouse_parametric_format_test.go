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
	"bytes"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// findFunctionCall walks the tree and returns the first FunctionCall whose
// name equals name, or nil if none exists.
func findFunctionCall(tree *ast.AST, name string) *ast.FunctionCall {
	var found *ast.FunctionCall
	var walk func(n ast.Node)
	walk = func(n ast.Node) {
		if n == nil || found != nil {
			return
		}
		if fc, ok := n.(*ast.FunctionCall); ok && fc != nil && fc.Name == name {
			found = fc
			return
		}
		for _, child := range n.Children() {
			walk(child)
		}
	}
	for _, stmt := range tree.Statements {
		walk(stmt)
	}
	return found
}

// TestFormatCommand_ClickHouseParametricAggregates is a regression test for
// issue #531: the `gosqlx format` CLI renderer dropped the params group of
// ClickHouse parametric aggregates, turning quantile(0.5)(x) into quantile(x).
func TestFormatCommand_ClickHouseParametricAggregates(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		want       string // exact compact uppercase output
		fn         string
		wantParams int
	}{
		{
			name:       "quantileTDigest",
			in:         "SELECT quantileTDigest(0.95)(value) FROM events",
			want:       "SELECT quantileTDigest(0.95)(value) FROM events",
			fn:         "quantileTDigest",
			wantParams: 1,
		},
		{
			name:       "topK",
			in:         "SELECT topK(10)(name) FROM users",
			want:       "SELECT topK(10)(name) FROM users",
			fn:         "topK",
			wantParams: 1,
		},
		{
			name:       "quantiles multiple params",
			in:         "SELECT quantiles(0.5, 0.9, 0.99)(latency_ms) FROM requests",
			want:       "SELECT quantiles(0.5, 0.9, 0.99)(latency_ms) FROM requests",
			fn:         "quantiles",
			wantParams: 3,
		},
		{
			name:       "group by",
			in:         "SELECT category, quantileTDigest(0.99)(price) FROM products GROUP BY category",
			want:       "SELECT category, quantileTDigest(0.99)(price) FROM products GROUP BY category",
			fn:         "quantileTDigest",
			wantParams: 1,
		},
		{
			name:       "combinator with multiple args",
			in:         "SELECT quantileIf(0.5)(x, y > 0) FROM t",
			want:       "SELECT quantileIf(0.5)(x, y > 0) FROM t",
			fn:         "quantileIf",
			wantParams: 1,
		},
		{
			name:       "alias and where",
			in:         "SELECT quantile(0.5)(x) AS p50 FROM t WHERE a = 1",
			want:       "SELECT quantile(0.5)(x) AS p50 FROM t WHERE a = 1",
			fn:         "quantile",
			wantParams: 1,
		},
		{
			name:       "string param",
			in:         "SELECT sequenceMatch('(?1)(?2)')(ts, e = 1, e = 2) FROM t",
			want:       "SELECT sequenceMatch('(?1)(?2)')(ts, e = 1, e = 2) FROM t",
			fn:         "sequenceMatch",
			wantParams: 1,
		},
		{
			name:       "window",
			in:         "SELECT quantile(0.9)(x) OVER (PARTITION BY k) FROM t",
			want:       "SELECT quantile(0.9)(x) OVER (PARTITION BY k) FROM t",
			fn:         "quantile",
			wantParams: 1,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			f := NewFormatter(&out, &errBuf, CLIFormatterOptions{Compact: true, Uppercase: true, Dialect: "clickhouse"})

			got, err := f.formatSQL(tc.in)
			if err != nil {
				t.Fatalf("formatSQL(%q) failed: %v", tc.in, err)
			}
			got = strings.TrimSpace(got)
			if got != tc.want {
				t.Fatalf("formatSQL mismatch\n got: %q\nwant: %q", got, tc.want)
			}

			// Idempotency: formatting the output again must not change it.
			again, err := f.formatSQL(got)
			if err != nil {
				t.Fatalf("formatSQL(%q) (second pass) failed: %v", got, err)
			}
			if strings.TrimSpace(again) != got {
				t.Fatalf("formatting is not idempotent\nfirst:  %q\nsecond: %q", got, strings.TrimSpace(again))
			}

			// The output must re-parse under ClickHouse with params intact.
			tree, err := gosqlx.ParseWithDialect(got, keywords.DialectClickHouse)
			if err != nil {
				t.Fatalf("re-parse of %q failed: %v", got, err)
			}
			fc := findFunctionCall(tree, tc.fn)
			if fc == nil {
				t.Fatalf("re-parsed AST has no FunctionCall named %q", tc.fn)
			}
			if len(fc.Parameters) != tc.wantParams {
				t.Fatalf("re-parsed %s has %d parameters, want %d", tc.fn, len(fc.Parameters), tc.wantParams)
			}
		})
	}

	t.Run("readable mode", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		f := NewFormatter(&out, &errBuf, CLIFormatterOptions{IndentSize: 2, Uppercase: true, Dialect: "clickhouse"})
		got, err := f.formatSQL("SELECT quantileTDigest(0.95)(value) FROM events")
		if err != nil {
			t.Fatalf("formatSQL failed: %v", err)
		}
		if !strings.Contains(got, "quantileTDigest(0.95)(value)") {
			t.Fatalf("readable output lost the params group:\n%s", got)
		}
	})

	t.Run("ordinary functions unchanged", func(t *testing.T) {
		const in = "SELECT count(DISTINCT x), uniqExact(x) FROM t"
		for _, dialect := range []string{"", "clickhouse"} {
			var out, errBuf bytes.Buffer
			f := NewFormatter(&out, &errBuf, CLIFormatterOptions{Compact: true, Uppercase: true, Dialect: dialect})
			got, err := f.formatSQL(in)
			if err != nil {
				t.Fatalf("dialect %q: formatSQL failed: %v", dialect, err)
			}
			if strings.TrimSpace(got) != in {
				t.Fatalf("dialect %q: got %q, want %q", dialect, strings.TrimSpace(got), in)
			}
		}
	})
}
