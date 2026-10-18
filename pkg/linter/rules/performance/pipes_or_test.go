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

package performance_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/performance"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestOrInsteadOfIn_MySQLPipes_Issue781 checks that L021 treats a MySQL ||
// chain exactly like an OR chain, and does not fire on PostgreSQL ||
// (concatenation).
func TestOrInsteadOfIn_MySQLPipes_Issue781(t *testing.T) {
	const sql = "SELECT id FROM users WHERE status = 1 || status = 2 || status = 3"
	cases := []struct {
		dialect keywords.SQLDialect
		want    bool
	}{
		{keywords.DialectMySQL, true},
		{keywords.DialectMariaDB, true},
		{keywords.DialectPostgreSQL, false},
	}
	for _, tc := range cases {
		t.Run(string(tc.dialect), func(t *testing.T) {
			l := linter.New(performance.NewOrInsteadOfInRule())
			l.SetDialect(tc.dialect)
			res := l.LintString(sql, "test.sql")
			got := false
			for _, v := range res.Violations {
				if v.Rule == "L021" {
					got = true
				}
			}
			if got != tc.want {
				t.Fatalf("L021 fired = %v, want %v (violations %+v, err %v)", got, tc.want, res.Violations, res.Error)
			}
		})
	}
}
