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

package transform_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/transform"
)

var transformSink string

func portableQueries(tb testing.TB) []benchcorpus.Query {
	tb.Helper()
	set, err := benchcorpus.Default()
	if err != nil {
		tb.Fatalf("load benchmark corpus: %v", err)
	}
	qs := set.Portable()
	if len(qs) == 0 {
		tb.Fatal("benchmark corpus has no portable queries")
	}
	return qs
}

// BenchmarkTransformParse measures transform.ParseSQL (parse plus release)
// over the portable queries.
func BenchmarkTransformParse(b *testing.B) {
	for _, q := range portableQueries(b) {
		b.Run(q.ID, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				tree, err := transform.ParseSQL(q.SQL)
				if err != nil {
					b.Fatal(err)
				}
				ast.ReleaseAST(tree)
			}
		})
	}
}

// roundTripCase is one parse, rewrite, render cycle. The same table drives
// the benchmark and the test that pins what each case produces.
type roundTripCase struct {
	name  string
	sql   string
	rules func() []transform.Rule
	// want lists fragments the rewritten SQL must contain; absent lists
	// fragments it must not.
	want, absent []string
}

var roundTripCases = []roundTripCase{
	{
		name: "addwhere",
		sql:  "SELECT id, name FROM users WHERE active = 1",
		rules: func() []transform.Rule {
			cond := &ast.BinaryExpression{
				Left:     &ast.Identifier{Name: "tenant_id"},
				Operator: "=",
				Right:    &ast.LiteralValue{Value: "42", Type: "int"},
			}
			return []transform.Rule{transform.AddWhere(cond)}
		},
		want: []string{"active = 1", "tenant_id = 42", "AND"},
	},
	{
		name: "addwhere_fromsql",
		sql:  "SELECT id, name FROM users WHERE active = 1",
		rules: func() []transform.Rule {
			return []transform.Rule{transform.AddWhereFromSQL("tenant_id = 42")}
		},
		want: []string{"active = 1", "tenant_id = 42", "AND"},
	},
	{
		name:  "limit",
		sql:   "SELECT id, name FROM users ORDER BY name",
		rules: func() []transform.Rule { return []transform.Rule{transform.SetLimit(10)} },
		want:  []string{"ORDER BY name", "10"},
	},
	{
		name: "rename",
		sql:  "SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id",
		rules: func() []transform.Rule {
			return []transform.Rule{transform.ReplaceTable("users", "accounts")}
		},
		want:   []string{"accounts"},
		absent: []string{"users"},
	},
}

func roundTrip(tb testing.TB, c roundTripCase, dialect keywords.SQLDialect) string {
	tb.Helper()
	tree, err := transform.ParseSQLWithDialect(c.sql, dialect)
	if err != nil {
		tb.Fatalf("%s: parse: %v", c.name, err)
	}
	defer ast.ReleaseAST(tree)
	if err := transform.Apply(tree.Statements[0], c.rules()...); err != nil {
		tb.Fatalf("%s: apply: %v", c.name, err)
	}
	var out string
	if dialect == "" {
		out = transform.FormatSQL(tree.Statements[0])
	} else {
		out = transform.FormatSQLWithDialect(tree.Statements[0], dialect)
	}
	if out == "" {
		tb.Fatalf("%s: rendered empty SQL", c.name)
	}
	return out
}

// BenchmarkTransformRoundTrip measures the full rewrite cycle a caller pays:
// parse, apply one rule, render, release.
func BenchmarkTransformRoundTrip(b *testing.B) {
	for _, c := range roundTripCases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				transformSink = roundTrip(b, c, "")
			}
		})
	}
}

// BenchmarkTransformRoundTripSQLServer is BenchmarkTransformRoundTrip parsed
// and rendered for SQL Server, which adds the dialect conversion on render.
func BenchmarkTransformRoundTripSQLServer(b *testing.B) {
	for _, c := range roundTripCases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				transformSink = roundTrip(b, c, keywords.DialectSQLServer)
			}
		})
	}
}

// TestRoundTripCasesRewrite pins that each benchmarked rewrite really changes
// the SQL as named, for both the generic and the SQL Server path.
func TestRoundTripCasesRewrite(t *testing.T) {
	for _, dialect := range []keywords.SQLDialect{"", keywords.DialectSQLServer} {
		for _, c := range roundTripCases {
			out := roundTrip(t, c, dialect)
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("%s [%q]: %q missing %q", c.name, dialect, out, w)
				}
			}
			for _, a := range c.absent {
				if strings.Contains(out, a) {
					t.Errorf("%s [%q]: %q still contains %q", c.name, dialect, out, a)
				}
			}
		}
	}
}

// TestRoundTripLimitDialects pins the one place the dialects must differ: a
// SQL Server render of SetLimit over an ORDER BY uses OFFSET/FETCH, the
// generic render uses LIMIT.
func TestRoundTripLimitDialects(t *testing.T) {
	var limit roundTripCase
	for _, c := range roundTripCases {
		if c.name == "limit" {
			limit = c
		}
	}
	if got := roundTrip(t, limit, ""); !strings.Contains(got, "LIMIT 10") {
		t.Errorf("generic: %q lacks LIMIT 10", got)
	}
	if got := roundTrip(t, limit, keywords.DialectSQLServer); strings.Contains(got, "LIMIT") || !strings.Contains(got, "FETCH NEXT 10 ROWS ONLY") {
		t.Errorf("sqlserver: %q should use FETCH NEXT 10 ROWS ONLY, not LIMIT", got)
	}
}

// TestTransformParseInputsParse guards BenchmarkTransformParse: each portable
// query parses to exactly one statement.
func TestTransformParseInputsParse(t *testing.T) {
	for _, q := range portableQueries(t) {
		tree, err := transform.ParseSQL(q.SQL)
		if err != nil {
			t.Errorf("%s: %v", q.ID, err)
			continue
		}
		if len(tree.Statements) != 1 {
			t.Errorf("%s: %d statements, want 1", q.ID, len(tree.Statements))
		}
		ast.ReleaseAST(tree)
	}
}
