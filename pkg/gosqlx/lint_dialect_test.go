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

package gosqlx

import (
	"sync"
	"testing"

	sqlkeywords "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func hasRule(res *LintResult, id string) bool {
	for _, v := range res.Violations {
		if v.Rule == id {
			return true
		}
	}
	return false
}

func TestLintWithDialect(t *testing.T) {
	const sql = "SELECT TOP 10 * FROM [users]"

	tests := []struct {
		name    string
		dialect sqlkeywords.SQLDialect
		wantAST bool
	}{
		{name: "sqlserver runs AST rules on dialect syntax", dialect: sqlkeywords.DialectSQLServer, wantAST: true},
		{name: "empty dialect matches Lint", dialect: "", wantAST: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := LintWithDialect(sql, tt.dialect)
			if err != nil {
				t.Fatalf("LintWithDialect: %v", err)
			}
			if got := hasRule(res, "L016"); got != tt.wantAST {
				t.Fatalf("L016 fired = %v, want %v (violations: %+v)", got, tt.wantAST, res.Violations)
			}
		})
	}

	// The shared default linter must stay on the default dialect.
	res, err := Lint(sql)
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	if hasRule(res, "L016") {
		t.Fatal("Lint picked up the SQL Server dialect from LintWithDialect")
	}
}

func TestLintWithDialect_Concurrent(t *testing.T) {
	dialects := []sqlkeywords.SQLDialect{sqlkeywords.DialectSQLServer, sqlkeywords.DialectMySQL, sqlkeywords.DialectPostgreSQL, ""}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		d := dialects[i%len(dialects)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := LintWithDialect("SELECT * FROM users", d); err != nil {
				t.Errorf("LintWithDialect(%q): %v", d, err)
			}
		}()
	}
	wg.Wait()
}
