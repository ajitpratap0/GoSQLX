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
	"sort"
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
// instrumentation and randomised sync.Pool eviction change the counts, so CI
// runs them in a dedicated non-race step (.github/workflows/test.yml, build
// job). Counts were measured on go1.26.9 (the CI toolchain); they can differ
// by a few allocations on other patch levels, hence the upper-bound rule.

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

// dialectAllocStatement pins each dialect to one medium real-world corpus
// statement by benchcorpus Statement.Key(), so a corpus or parser change cannot
// silently swap the measured statement.
var dialectAllocStatement = map[string]string{
	"postgresql": "realworld/postgresql/02_reporting.sql#0",
	"mysql":      "realworld/mysql/03_ddl_migrations.sql#0",
	"mariadb":    "realworld/mariadb/03_ddl_migrations.sql#1",
	"sqlserver":  "realworld/sqlserver/02_reporting.sql#0",
	"oracle":     "realworld/oracle/02_reporting.sql#5",
	"sqlite":     "realworld/sqlite/01_app_crud.sql#0",
	"snowflake":  "realworld/snowflake/02_reporting.sql#7",
	"clickhouse": "realworld/clickhouse/03_ddl_migrations.sql#2",
}

// dialectAllocBudget is allocs/op of ParseWithDialect+ReleaseAST for the
// statement pinned in dialectAllocStatement.
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
	dialects := make([]string, 0, len(dialectAllocStatement))
	for d := range dialectAllocStatement {
		dialects = append(dialects, d)
	}
	sort.Strings(dialects)
	for _, d := range dialects {
		key := dialectAllocStatement[d]
		dialect := keywords.SQLDialect(d)
		var sql string
		for _, st := range set.RealWorld(d) {
			if st.Key() == key {
				sql = st.SQL
				break
			}
		}
		if sql == "" {
			t.Errorf("%s: pinned statement %s not found in the corpus", d, key)
			continue
		}
		if tree, err := gosqlx.ParseWithDialect(sql, dialect); err != nil {
			t.Errorf("%s: pinned statement %s no longer parses: %v", d, key, err)
			continue
		} else {
			ast.ReleaseAST(tree)
		}
		tested++
		t.Run(d, func(t *testing.T) {
			t.Logf("measuring %s", key)
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
	if tested != len(dialectAllocStatement) {
		t.Fatalf("measured %d dialects, want %d", tested, len(dialectAllocStatement))
	}
}
