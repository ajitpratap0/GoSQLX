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

package transpiler_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/metrics"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler"
)

// Pool counters are process-global: use deltas, never reset, never t.Parallel.

func TestTranspile_ASTPoolBalanced(t *testing.T) {
	const n = 50
	tests := []struct {
		name     string
		sql      string
		from, to keywords.SQLDialect
		wantErr  bool
		contains string
	}{
		{"mysql_to_pg_autoincrement", "CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY)", keywords.DialectMySQL, keywords.DialectPostgreSQL, false, "SERIAL"},
		{"pg_to_mysql_ilike", "SELECT * FROM t WHERE name ILIKE 'a%'", keywords.DialectPostgreSQL, keywords.DialectMySQL, false, ""},
		{"generic_passthrough", "SELECT id FROM t", keywords.DialectGeneric, keywords.DialectGeneric, false, ""},
		{"invalid_sql", "SELECT FROM WHERE", keywords.DialectMySQL, keywords.DialectPostgreSQL, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := metrics.GetPoolStats()
			var out string
			for i := 0; i < n; i++ {
				var err error
				out, err = transpiler.Transpile(tt.sql, tt.from, tt.to)
				if (err != nil) != tt.wantErr {
					t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
				}
			}
			after := metrics.GetPoolStats()
			g := after["ast"].Gets - before["ast"].Gets
			p := after["ast"].Puts - before["ast"].Puts
			if g != p {
				t.Errorf("ast pool unbalanced: gets=%d puts=%d", g, p)
			}
			if tt.wantErr {
				return
			}
			if g < n {
				t.Errorf("ast gets = %d, want >= %d", g, n)
			}
			// The output string must be independent of pooled nodes.
			for i := 0; i < 100; i++ {
				tree, err := gosqlx.Parse("SELECT x, y FROM z WHERE x = 1")
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				ast.ReleaseAST(tree)
			}
			if tt.contains != "" && !strings.Contains(out, tt.contains) {
				t.Errorf("output %q does not contain %q", out, tt.contains)
			}
		})
	}
}

func TestTranspile_ConcurrentRace(t *testing.T) {
	const sql = "CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY)"
	want, err := transpiler.Transpile(sql, keywords.DialectMySQL, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("Transpile: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan string, 8)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				got, err := transpiler.Transpile(sql, keywords.DialectMySQL, keywords.DialectPostgreSQL)
				if err != nil || got != want {
					errs <- "mismatch or error: " + got
					return
				}
				tree, err := gosqlx.Parse("SELECT a FROM b WHERE a = 1")
				if err != nil {
					errs <- "parse: " + err.Error()
					return
				}
				ast.ReleaseAST(tree)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
