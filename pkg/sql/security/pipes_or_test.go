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

package security

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

func hasTautology(r *ScanResult, descPrefix string) bool {
	for _, f := range r.Findings {
		if f.Pattern == PatternTautology && strings.HasPrefix(f.Description, descPrefix) {
			return true
		}
	}
	return false
}

// TestScanner_PipesOrTautology_Issue781 checks that the AST scanner sees a
// MySQL/MariaDB || tautology as an OR tautology, exactly like the OR keyword.
func TestScanner_PipesOrTautology_Issue781(t *testing.T) {
	cases := []string{
		"SELECT * FROM users WHERE name = 'x' || 1 = 1",
		"SELECT * FROM users WHERE name = 'x' || 'a' = 'a'",
		"SELECT * FROM users WHERE 1 = 1 || name = 'x'",
	}
	for _, d := range []keywords.SQLDialect{keywords.DialectMySQL, keywords.DialectMariaDB} {
		for _, sql := range cases {
			t.Run(string(d)+"/"+sql, func(t *testing.T) {
				tree, err := parser.ParseWithDialect(sql, d)
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				defer ast.ReleaseAST(tree)
				res := NewScanner().Scan(tree)
				if !hasTautology(res, "OR condition with tautology") {
					t.Fatalf("no OR-tautology finding for %q: %+v", sql, res.Findings)
				}
			})
		}
	}
}

// TestScanSQL_PipesOrTautology_Issue781 checks the dialect-agnostic raw-SQL
// scan for || tautologies, and that plain concatenation is not flagged.
func TestScanSQL_PipesOrTautology_Issue781(t *testing.T) {
	s := NewScanner()
	for _, sql := range []string{
		"SELECT * FROM users WHERE id = 1 || TRUE",
		"SELECT * FROM users WHERE id = 1 ||true --",
		"SELECT * FROM users WHERE name = '' || 1=1 --",
	} {
		if res := s.ScanSQL(sql); !hasTautology(res, "") {
			t.Errorf("ScanSQL(%q): tautology not detected", sql)
		}
	}
	for _, sql := range []string{
		"SELECT first_name || ' ' || last_name FROM users",
		"SELECT * FROM users WHERE code = 'a' || 'b'",
	} {
		if res := s.ScanSQL(sql); hasTautology(res, "") {
			t.Errorf("ScanSQL(%q): unexpected tautology: %+v", sql, res.Findings)
		}
	}
}
