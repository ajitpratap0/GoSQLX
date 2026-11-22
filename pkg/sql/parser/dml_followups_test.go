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

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// SQL Server MERGE ... OUTPUT ... INTO target keeps the INTO part.
func TestParser_MergeOutputInto(t *testing.T) {
	tests := []struct {
		name       string
		sql        string
		wantTarget string
		wantCols   int
		wantOutput int
	}{
		{"table variable",
			"MERGE INTO t USING s ON t.id = s.id WHEN NOT MATCHED BY TARGET THEN INSERT (id) VALUES (s.id) WHEN NOT MATCHED BY SOURCE THEN DELETE OUTPUT $action, INSERTED.id INTO @t",
			"@t", 0, 2},
		{"table with column list",
			"MERGE t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET a = 1 OUTPUT inserted.id, deleted.a INTO dbo.log (id, a)",
			"dbo.log", 2, 2},
		{"output without into",
			"MERGE t USING s ON t.id = s.id WHEN MATCHED THEN DELETE OUTPUT deleted.id",
			"", 0, 1},
		{"derived source",
			"MERGE t USING (SELECT 1 AS id) AS s ON t.id = s.id WHEN MATCHED THEN DELETE OUTPUT deleted.id AS old_id INTO @x",
			"@x", 0, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmt, tree := parseDMLShape(t, tc.sql, keywords.DialectSQLServer)
			defer ast.ReleaseAST(tree)
			m, ok := stmt.(*ast.MergeStatement)
			if !ok {
				t.Fatalf("expected *ast.MergeStatement, got %T", stmt)
			}
			if len(m.Output) != tc.wantOutput {
				t.Errorf("len(Output) = %d, want %d", len(m.Output), tc.wantOutput)
			}
			if tc.wantTarget == "" {
				if m.OutputInto != nil {
					t.Errorf("OutputInto = %+v, want nil", m.OutputInto)
				}
				return
			}
			if m.OutputInto == nil {
				t.Fatalf("OutputInto is nil, want target %q", tc.wantTarget)
			}
			if m.OutputInto.Target != tc.wantTarget || len(m.OutputInto.Columns) != tc.wantCols {
				t.Errorf("OutputInto = %q with %d columns, want %q with %d", m.OutputInto.Target, len(m.OutputInto.Columns), tc.wantTarget, tc.wantCols)
			}
			// The rendered SQL re-parses to the same OUTPUT INTO.
			out := m.SQL()
			stmt2, tree2 := parseDMLShape(t, out, keywords.DialectSQLServer)
			defer ast.ReleaseAST(tree2)
			m2, ok := stmt2.(*ast.MergeStatement)
			if !ok || m2.OutputInto == nil || m2.OutputInto.Target != tc.wantTarget {
				t.Errorf("reparsing %q lost OUTPUT INTO: %+v", out, stmt2)
			}
		})
	}
}

// OUTPUT is SQL Server only: elsewhere MERGE keeps ending at the last WHEN.
func TestParser_MergeOutputGated(t *testing.T) {
	const sql = "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE OUTPUT deleted.id INTO @t"
	for _, d := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectOracle, keywords.DialectSnowflake} {
		t.Run(string(d), func(t *testing.T) {
			if _, err := ParseWithDialect(sql, d); err == nil {
				t.Errorf("MERGE ... OUTPUT parsed in %s, want an error", d)
			}
		})
	}
}

// MySQL and MariaDB reject DELETE forms that only Oracle and SQL Server
// accept; the parser must not normalize them into valid-looking SQL.
func TestParser_MySQLDeleteRejectedForms(t *testing.T) {
	rejected := []string{
		"DELETE t WHERE a = 1",
		"DELETE t",
		"DELETE FROM t1, t2 WHERE a = 1",
		"DELETE FROM t1, t2",
		"DELETE FROM t1 AS a, t2 AS b WHERE a.id = b.id",
	}
	accepted := []string{
		"DELETE FROM t WHERE a = 1",
		"DELETE LOW_PRIORITY QUICK IGNORE FROM t WHERE a = 1 ORDER BY id LIMIT 3",
		"DELETE t1 FROM t1 JOIN t2 ON t1.id = t2.id WHERE t2.x = 1",
		"DELETE t1, t2 FROM t1 JOIN t2 ON t1.id = t2.id",
		"DELETE FROM t1, t2 USING t1 JOIN t2 ON t1.id = t2.id WHERE t2.x = 1",
		"DELETE FROM t1 USING t1 JOIN t2 ON t1.id = t2.id",
	}
	for _, d := range []keywords.SQLDialect{keywords.DialectMySQL, keywords.DialectMariaDB} {
		for _, sql := range rejected {
			t.Run(string(d)+"/reject/"+sql, func(t *testing.T) {
				if tree, err := ParseWithDialect(sql, d); err == nil {
					t.Errorf("parse %q (%s) succeeded as %s, want an error", sql, d, tree.Statements[0].(interface{ SQL() string }).SQL())
				}
			})
		}
		for _, sql := range accepted {
			t.Run(string(d)+"/accept/"+sql, func(t *testing.T) {
				if _, err := ParseWithDialect(sql, d); err != nil {
					t.Errorf("parse %q (%s): %v", sql, d, err)
				}
			})
		}
	}
}

// Dialects that allow DELETE without FROM, and PostgreSQL's single-target
// forms, are unaffected by the MySQL rejection.
func TestParser_DeleteWithoutFromOtherDialects(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectOracle, "DELETE t WHERE a = 1"},
		{keywords.DialectSQLServer, "DELETE t WHERE a = 1"},
		{keywords.DialectSQLServer, "DELETE t1 FROM t1 JOIN t2 ON t1.id = t2.id"},
		{keywords.DialectPostgreSQL, "DELETE FROM t USING u WHERE t.id = u.id"},
	}
	for _, tc := range tests {
		t.Run(string(tc.dialect)+"/"+tc.sql, func(t *testing.T) {
			if _, err := ParseWithDialect(tc.sql, tc.dialect); err != nil {
				t.Errorf("parse %q (%s): %v", tc.sql, tc.dialect, err)
			}
		})
	}
}
