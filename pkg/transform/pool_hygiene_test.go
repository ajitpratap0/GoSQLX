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

package transform

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/metrics"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// Pool counters are process-global: use deltas, never reset, never t.Parallel.

func poolDelta(before, after map[string]metrics.PoolStat, name string) (gets, puts int64) {
	return after[name].Gets - before[name].Gets, after[name].Puts - before[name].Puts
}

func TestParseHelpers_ParserPoolBalanced(t *testing.T) {
	const n = 50
	selStmt := mustParse(t, "SELECT id FROM t")
	updStmt := mustParse(t, "UPDATE t SET a = 1")

	tests := []struct {
		name        string
		run         func() error
		callerOwned bool // true: each call hands one *ast.AST to the caller
	}{
		{"ParseSQL", func() error { _, err := ParseSQL("SELECT id FROM t"); return err }, true},
		{"ParseSQLWithDialect", func() error {
			_, err := ParseSQLWithDialect("SELECT TOP 10 * FROM users", keywords.DialectSQLServer)
			return err
		}, true},
		{"AddWhereFromSQL", func() error { return Apply(selStmt, AddWhereFromSQL("id = 1")) }, false},
		{"AddJoinFromSQL", func() error { return Apply(selStmt, AddJoinFromSQL("JOIN o ON o.id = t.id")) }, false},
		{"SetClause", func() error { return Apply(updStmt, SetClause("name", "'x'")) }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := metrics.GetPoolStats()
			for i := 0; i < n; i++ {
				if err := tt.run(); err != nil {
					t.Fatalf("run: %v", err)
				}
			}
			after := metrics.GetPoolStats()
			if g, p := poolDelta(before, after, "parser"); g != p || g < n {
				t.Errorf("parser pool: gets=%d puts=%d, want equal and >= %d", g, p, n)
			}
			g, p := poolDelta(before, after, "ast")
			want := int64(0)
			if tt.callerOwned {
				want = n
			}
			if g-p != want {
				t.Errorf("outstanding ASTs = %d, want %d", g-p, want)
			}
		})
	}
}

func TestParseSQL_NodesSurviveContainerRelease(t *testing.T) {
	stmt := mustParse(t, "SELECT id, name FROM users")
	if err := Apply(stmt, AddWhereFromSQL("id = 1 AND name = 'x'")); err != nil {
		t.Fatalf("AddWhereFromSQL: %v", err)
	}

	other := mustParse(t, "SELECT a FROM b")
	for i := 0; i < 200; i++ {
		tree, err := ParseSQL("SELECT 1")
		if err != nil {
			t.Fatalf("ParseSQL: %v", err)
		}
		ast.ReleaseAST(tree)
		if err := Apply(other, AddWhereFromSQL("z > 3"), RemoveWhere()); err != nil {
			t.Fatalf("Apply: %v", err)
		}
	}

	got := FormatSQL(stmt)
	if !strings.Contains(got, "id = 1 AND name = 'x'") {
		t.Errorf("Where subtree clobbered by pool reuse: %q", got)
	}
}

func TestParseSQLWithDialect_NoDialectCarryover(t *testing.T) {
	const sql = "SELECT TOP 10 * FROM users"
	for i := 0; i < 20; i++ {
		tree, err := ParseSQLWithDialect(sql, keywords.DialectSQLServer)
		if err != nil {
			t.Fatalf("iteration %d: SQL Server parse failed: %v", i, err)
		}
		ast.ReleaseAST(tree)

		if tree, err := ParseSQL(sql); err == nil {
			ast.ReleaseAST(tree)
			t.Fatalf("iteration %d: generic ParseSQL accepted TOP; dialect leaked through parser pool", i)
		}
	}

	p := parser.GetParser()
	defer parser.PutParser(p)
	if p.Dialect() != "postgresql" || p.DialectTyped() != dialect.Unknown {
		t.Errorf("pooled parser carries dialect: Dialect()=%q DialectTyped()=%v", p.Dialect(), p.DialectTyped())
	}
}
