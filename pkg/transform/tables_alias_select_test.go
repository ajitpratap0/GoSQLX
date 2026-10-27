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

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestAddTableAliasSelectQualifiers(t *testing.T) {
	tests := []struct {
		name, sql    string
		want, reject []string
	}{
		{"where", "SELECT users.id FROM users WHERE users.id = 1", []string{"SELECT u.id", "FROM users u", "WHERE u.id = 1"}, []string{"users.id"}},
		{"previous alias", "SELECT old.id FROM users old WHERE old.id = 1", []string{"u.id", "FROM users u"}, []string{"old.id"}},
		{"shadowed subquery", "SELECT users.id FROM users WHERE EXISTS (SELECT users.id FROM users WHERE users.id = 2)", []string{"SELECT u.id FROM users u", "SELECT users.id FROM users WHERE users.id = 2"}, nil},
		{"correlated subquery", "SELECT users.id FROM users WHERE EXISTS (SELECT 1 FROM orders WHERE orders.user_id = users.id)", []string{"orders.user_id = u.id"}, []string{"users.id"}},
		{"join", "SELECT users.id FROM orders JOIN users ON users.id = orders.user_id", []string{"JOIN users u ON u.id = orders.user_id"}, []string{"users.id"}},
		{"group having", "SELECT users.id FROM users GROUP BY users.id HAVING users.id > 0 ORDER BY users.id", []string{"GROUP BY u.id", "HAVING u.id", "ORDER BY u.id"}, []string{"users.id"}},
		{"window", "SELECT SUM(users.id) OVER (PARTITION BY users.id ORDER BY users.id) FROM users", []string{"SUM(u.id) OVER (PARTITION BY u.id ORDER BY u.id)"}, []string{"users.id"}},
		{"named window", "SELECT SUM(users.id) OVER w FROM users WINDOW w AS (PARTITION BY users.id ORDER BY users.id)", []string{"PARTITION BY u.id ORDER BY u.id"}, []string{"users.id"}},
		{"partial shadow", "SELECT old.id FROM users old WHERE EXISTS (SELECT 1 FROM users WHERE users.id = old.id)", []string{"users.id = u.id"}, []string{"old.id"}},
		{"lateral join", "SELECT users.id FROM users JOIN LATERAL (SELECT users.id) x ON true", []string{"LATERAL (SELECT u.id)"}, []string{"users.id"}},
		{"lateral from", "SELECT users.id FROM users, LATERAL (SELECT users.id) x", []string{"LATERAL (SELECT u.id)"}, []string{"users.id"}},
		{"lateral shadow", "SELECT users.id FROM users JOIN LATERAL (SELECT users.id FROM users) x ON true", []string{"LATERAL (SELECT users.id FROM users)"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := ParseSQL(tt.sql)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			stmt := tree.Statements[0]
			if err := Apply(stmt, AddTableAlias("users", "u")); err != nil {
				t.Fatal(err)
			}
			out := selectSQL(t, stmt)
			for _, s := range tt.want {
				if !strings.Contains(out, s) {
					t.Errorf("want %q in %q", s, out)
				}
			}
			for _, s := range tt.reject {
				if strings.Contains(out, s) {
					t.Errorf("unexpected %q in %q", s, out)
				}
			}
		})
	}
}

func TestAddTableAliasSelectRejectsSelfJoin(t *testing.T) {
	tree, err := ParseSQL("SELECT a.id FROM users a JOIN users b ON a.id = b.id")
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	stmt := tree.Statements[0]
	before := selectSQL(t, stmt)
	if err := Apply(stmt, AddTableAlias("users", "u")); err == nil {
		t.Fatal("expected ambiguous alias error")
	}
	if got := selectSQL(t, stmt); got != before {
		t.Errorf("error mutated statement: %s", got)
	}
}

func TestAddTableAliasDMLPartialShadow(t *testing.T) {
	for _, sql := range []string{
		"UPDATE users old SET id = 1 WHERE EXISTS (SELECT 1 FROM users WHERE users.id = old.id)",
		"DELETE FROM users old WHERE EXISTS (SELECT 1 FROM users WHERE users.id = old.id)",
	} {
		t.Run(sql, func(t *testing.T) {
			tree, err := ParseSQL(sql)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			if err := Apply(tree.Statements[0], AddTableAlias("users", "u")); err != nil {
				t.Fatal(err)
			}
			out := FormatSQL(tree.Statements[0])
			if !strings.Contains(out, "users.id = u.id") || strings.Contains(out, "old.id") {
				t.Errorf("incorrect scoped alias: %s", out)
			}
		})
	}
}

func TestAddTableAliasRejectsCorrelatedCapture(t *testing.T) {
	for _, sql := range []string{
		"SELECT users.id FROM users WHERE EXISTS (SELECT 1 FROM orders u WHERE u.user_id = users.id)",
		"SELECT users.id FROM users JOIN LATERAL (SELECT users.id FROM orders u) x ON true",
		"UPDATE users SET id = 1 WHERE EXISTS (SELECT 1 FROM orders u WHERE u.user_id = users.id)",
		"DELETE FROM users WHERE EXISTS (SELECT 1 FROM orders u WHERE u.user_id = users.id)",
	} {
		t.Run(sql, func(t *testing.T) {
			tree, err := ParseSQL(sql)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			before := tree.SQL()
			if err := Apply(tree.Statements[0], AddTableAlias("users", "u")); err == nil {
				t.Fatal("expected correlated qualifier capture error")
			}
			if got := tree.SQL(); got != before {
				t.Errorf("error mutated statement: %s", got)
			}
		})
	}
}

func TestAddTableAliasAllowsIndependentNestedAlias(t *testing.T) {
	for _, sql := range []string{
		"SELECT users.id FROM users WHERE EXISTS (SELECT 1 FROM orders u WHERE u.user_id = 1)",
		"SELECT users.id FROM users WHERE EXISTS (SELECT users.id FROM users JOIN orders u ON users.id = u.user_id)",
	} {
		t.Run(sql, func(t *testing.T) {
			tree, err := ParseSQL(sql)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			if err := Apply(tree.Statements[0], AddTableAlias("users", "u")); err != nil {
				t.Fatal(err)
			}
			if got := tree.SQL(); !strings.Contains(got, "SELECT u.id FROM users u") {
				t.Errorf("outer qualifier was not renamed: %s", got)
			}
		})
	}
}
