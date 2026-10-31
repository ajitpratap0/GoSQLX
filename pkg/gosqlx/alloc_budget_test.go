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

package gosqlx_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// Allocation budgets (PLAN W0-04). Each budget is the allocs/op measured on
// the commit that introduced it. A change that adds allocations fails here; a
// change that removes them must lower the budget in the same PR (the test
// logs when a budget has slack). Budgets are skipped under -race, where
// instrumentation and randomised sync.Pool eviction change the counts.

// parseAllocBudget is allocs/op of Parse+ReleaseAST for the 11 portable queries.
var parseAllocBudget = map[string]float64{
	"simple_select": 5,
	"select_where":  18,
	"join":          17,
	"aggregate":     18,
	"subquery":      14,
	"cte":           21,
	"window":        11,
	"complex":       50,
	"insert":        17,
	"update":        13,
	"delete":        5,
}

// dialectAllocBudget is allocs/op of ParseWithDialect+ReleaseAST for the first
// medium real-world statement of each dialect corpus.
var dialectAllocBudget = map[string]float64{
	"postgresql": 37,
	"mysql":      50,
	"mariadb":    61,
	"sqlserver":  36,
	"oracle":     68,
	"sqlite":     48,
	"snowflake":  71,
	"clickhouse": 82,
}

const allocRuns = 200

func measureAllocs(t *testing.T, fn func() error) float64 {
	t.Helper()
	if err := fn(); err != nil {
		t.Fatalf("warm-up parse failed: %v", err)
	}
	return testing.AllocsPerRun(allocRuns, func() {
		if err := fn(); err != nil {
			t.Fatalf("parse failed: %v", err)
		}
	})
}

func checkBudget(t *testing.T, name string, budget map[string]float64, got float64) {
	t.Helper()
	want, ok := budget[name]
	switch {
	case !ok:
		t.Errorf("no allocation budget for %s (measured %.0f allocs/op); add it to the budget table", name, got)
	case got > want:
		t.Errorf("%s: %.0f allocs/op exceeds budget %.0f", name, got, want)
	case got < want:
		t.Logf("%s: %.0f allocs/op is under budget %.0f; lower the budget to lock in the gain", name, got, want)
	}
}

func skipAllocBudgets(t *testing.T) {
	t.Helper()
	if raceEnabled {
		t.Skip("allocation budgets are not meaningful under the race detector")
	}
}

func TestParseAllocBudget(t *testing.T) {
	skipAllocBudgets(t)
	set, err := benchcorpus.Default()
	if err != nil {
		t.Fatalf("load benchmark corpus: %v", err)
	}
	queries := set.Portable()
	if len(queries) != 11 {
		t.Fatalf("portable corpus has %d queries, want 11", len(queries))
	}
	for _, q := range queries {
		t.Run(q.ID, func(t *testing.T) {
			got := measureAllocs(t, func() error {
				tree, err := gosqlx.Parse(q.SQL)
				if err != nil {
					return err
				}
				ast.ReleaseAST(tree)
				return nil
			})
			checkBudget(t, q.ID, parseAllocBudget, got)
		})
	}
}

func TestParseWithDialectAllocBudget(t *testing.T) {
	skipAllocBudgets(t)
	set, err := benchcorpus.Default()
	if err != nil {
		t.Fatalf("load benchmark corpus: %v", err)
	}
	tested := 0
	for _, d := range benchcorpus.Dialects() {
		mediums := benchcorpus.InBucket(set.RealWorld(d), benchcorpus.Medium)
		if len(mediums) == 0 {
			continue
		}
		dialect := keywords.SQLDialect(d)
		var sql string
		for _, st := range mediums {
			if tree, err := gosqlx.ParseWithDialect(st.SQL, dialect); err == nil {
				ast.ReleaseAST(tree)
				sql = st.SQL
				break
			}
		}
		if sql == "" {
			t.Errorf("%s: no medium statement parses with its own dialect", d)
			continue
		}
		tested++
		t.Run(d, func(t *testing.T) {
			got := measureAllocs(t, func() error {
				tree, err := gosqlx.ParseWithDialect(sql, dialect)
				if err != nil {
					return err
				}
				ast.ReleaseAST(tree)
				return nil
			})
			checkBudget(t, d, dialectAllocBudget, got)
		})
	}
	if tested == 0 {
		t.Fatal("no dialect has a medium real-world statement")
	}
}
