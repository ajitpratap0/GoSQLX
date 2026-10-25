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
	"reflect"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseDMLShape parses sql in dialect and returns its only statement. The
// returned AST must be released by the caller.
func parseDMLShape(t *testing.T, sql string, dialect keywords.SQLDialect) (ast.Statement, *ast.AST) {
	t.Helper()
	tree, err := ParseWithDialect(sql, dialect)
	if err != nil {
		t.Fatalf("ParseWithDialect(%q, %s): %v", sql, dialect, err)
	}
	if len(tree.Statements) != 1 {
		ast.ReleaseAST(tree)
		t.Fatalf("expected 1 statement for %q, got %d", sql, len(tree.Statements))
	}
	return tree.Statements[0], tree
}

func TestDMLShape_Update(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		check   func(t *testing.T, u *ast.UpdateStatement)
	}{
		{"limit is stored", keywords.DialectMySQL, "UPDATE t SET a = 1 WHERE b = 2 ORDER BY id LIMIT 5",
			func(t *testing.T, u *ast.UpdateStatement) {
				lit, ok := u.Limit.(*ast.LiteralValue)
				if !ok {
					t.Fatalf("Limit: expected *ast.LiteralValue, got %T", u.Limit)
				}
				if lit.Value != "5" {
					t.Errorf("Limit = %v, want 5", lit.Value)
				}
				if len(u.OrderBy) != 1 {
					t.Errorf("OrderBy: got %d items, want 1", len(u.OrderBy))
				}
			}},
		{"alias", keywords.DialectPostgreSQL, "UPDATE t AS x SET a = 1",
			func(t *testing.T, u *ast.UpdateStatement) {
				if u.TableName != "t" || u.Alias != "x" {
					t.Errorf("target = %q %q, want t x", u.TableName, u.Alias)
				}
				if len(u.Tables) != 0 {
					t.Errorf("Tables should be empty for a single plain target, got %d", len(u.Tables))
				}
			}},
		{"modifiers", keywords.DialectMySQL, "UPDATE LOW_PRIORITY IGNORE t SET x = 1",
			func(t *testing.T, u *ast.UpdateStatement) {
				if !reflect.DeepEqual(u.Modifiers, []string{"LOW_PRIORITY", "IGNORE"}) {
					t.Errorf("Modifiers = %v", u.Modifiers)
				}
			}},
		{"sqlite or modifier", keywords.DialectSQLite, "UPDATE OR IGNORE t SET a = 1",
			func(t *testing.T, u *ast.UpdateStatement) {
				if !reflect.DeepEqual(u.Modifiers, []string{"OR IGNORE"}) {
					t.Errorf("Modifiers = %v", u.Modifiers)
				}
			}},
		{"joins", keywords.DialectMySQL, "UPDATE t JOIN u ON t.id = u.id SET t.a = 1",
			func(t *testing.T, u *ast.UpdateStatement) {
				if len(u.Joins) != 1 || u.Joins[0].Right.Name != "u" {
					t.Fatalf("Joins = %+v", u.Joins)
				}
				col, ok := u.Assignments[0].Column.(*ast.Identifier)
				if !ok {
					t.Fatalf("Column: expected *ast.Identifier, got %T", u.Assignments[0].Column)
				}
				if col.Table != "t" || col.Name != "a" {
					t.Errorf("Column = %s.%s, want t.a", col.Table, col.Name)
				}
			}},
		{"comma targets", keywords.DialectMySQL, "UPDATE t1, t2 x SET t1.a = x.b",
			func(t *testing.T, u *ast.UpdateStatement) {
				if u.TableName != "t1" || len(u.Tables) != 1 || u.Tables[0].Name != "t2" || u.Tables[0].Alias != "x" {
					t.Errorf("targets = %q + %+v", u.TableName, u.Tables)
				}
			}},
		{"derived target", keywords.DialectOracle, "UPDATE (SELECT a FROM t) SET a = 1",
			func(t *testing.T, u *ast.UpdateStatement) {
				if u.TableName != "" || len(u.Tables) != 1 || u.Tables[0].Subquery == nil {
					t.Errorf("derived target not stored in Tables: %q %+v", u.TableName, u.Tables)
				}
			}},
		{"top and only", keywords.DialectSQLServer, "UPDATE TOP (5) t SET a = 1",
			func(t *testing.T, u *ast.UpdateStatement) {
				if u.Top == nil || u.Top.Count == nil {
					t.Fatal("Top not stored")
				}
			}},
		{"only", keywords.DialectPostgreSQL, "UPDATE ONLY t SET a = 1",
			func(t *testing.T, u *ast.UpdateStatement) {
				if !u.Only || u.TableName != "t" {
					t.Errorf("Only = %v, TableName = %q", u.Only, u.TableName)
				}
			}},
		{"tuple target and default", keywords.DialectPostgreSQL, "UPDATE t SET (a, b) = (1, 2), c = DEFAULT",
			func(t *testing.T, u *ast.UpdateStatement) {
				tuple, ok := u.Assignments[0].Column.(*ast.TupleExpression)
				if !ok {
					t.Fatalf("Column: expected *ast.TupleExpression, got %T", u.Assignments[0].Column)
				}
				if len(tuple.Expressions) != 2 {
					t.Errorf("tuple has %d columns, want 2", len(tuple.Expressions))
				}
				if _, ok := u.Assignments[1].Value.(*ast.DefaultExpr); !ok {
					t.Errorf("Value: expected *ast.DefaultExpr, got %T", u.Assignments[1].Value)
				}
			}},
		{"output into", keywords.DialectSQLServer, "UPDATE t SET a = 1 OUTPUT inserted.a AS na INTO @v (a) WHERE b = 1",
			func(t *testing.T, u *ast.UpdateStatement) {
				if len(u.Output) != 1 {
					t.Fatalf("Output = %v", u.Output)
				}
				if _, ok := u.Output[0].(*ast.AliasedExpression); !ok {
					t.Errorf("Output[0]: expected *ast.AliasedExpression, got %T", u.Output[0])
				}
				if u.OutputInto == nil || u.OutputInto.Target != "@v" || len(u.OutputInto.Columns) != 1 {
					t.Errorf("OutputInto = %+v", u.OutputInto)
				}
				if u.Where == nil {
					t.Error("Where lost after OUTPUT")
				}
			}},
		{"returning into", keywords.DialectOracle, "UPDATE t SET a = 1 RETURNING a INTO :x",
			func(t *testing.T, u *ast.UpdateStatement) {
				if len(u.Returning) != 1 || len(u.ReturningInto) != 1 {
					t.Errorf("Returning = %v, ReturningInto = %v", u.Returning, u.ReturningInto)
				}
			}},
		{"from with joins", keywords.DialectSQLServer, "UPDATE t SET a = 1 FROM t JOIN u ON u.id = t.id",
			func(t *testing.T, u *ast.UpdateStatement) {
				if len(u.From) != 1 || len(u.Joins) != 1 {
					t.Errorf("From = %d, Joins = %d; want 1, 1", len(u.From), len(u.Joins))
				}
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmt, tree := parseDMLShape(t, tc.sql, tc.dialect)
			defer ast.ReleaseAST(tree)
			u, ok := stmt.(*ast.UpdateStatement)
			if !ok {
				t.Fatalf("expected *ast.UpdateStatement, got %T", stmt)
			}
			tc.check(t, u)
		})
	}
}

func TestDMLShape_Delete(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		check   func(t *testing.T, d *ast.DeleteStatement)
	}{
		{"limit", keywords.DialectMySQL, "DELETE FROM t WHERE a = 1 LIMIT 10",
			func(t *testing.T, d *ast.DeleteStatement) {
				if d.Limit == nil {
					t.Error("Limit not stored")
				}
			}},
		{"using", keywords.DialectPostgreSQL, "DELETE FROM a USING b, c WHERE a.id = b.id",
			func(t *testing.T, d *ast.DeleteStatement) {
				if len(d.Using) != 2 || d.Using[0].Name != "b" {
					t.Errorf("Using = %+v", d.Using)
				}
			}},
		{"mysql multi-table", keywords.DialectMySQL, "DELETE a, b FROM a JOIN b ON a.id = b.id",
			func(t *testing.T, d *ast.DeleteStatement) {
				if d.TableName != "a" || len(d.Tables) != 1 || d.Tables[0].Name != "b" {
					t.Errorf("targets = %q + %+v", d.TableName, d.Tables)
				}
				if len(d.From) != 1 || d.From[0].Name != "a" || len(d.Joins) != 1 {
					t.Errorf("From = %+v, Joins = %d", d.From, len(d.Joins))
				}
			}},
		{"modifiers", keywords.DialectMySQL, "DELETE LOW_PRIORITY QUICK IGNORE FROM t",
			func(t *testing.T, d *ast.DeleteStatement) {
				if !reflect.DeepEqual(d.Modifiers, []string{"LOW_PRIORITY", "QUICK", "IGNORE"}) {
					t.Errorf("Modifiers = %v", d.Modifiers)
				}
			}},
		{"top output", keywords.DialectSQLServer, "DELETE TOP (3) FROM t OUTPUT deleted.id WHERE a = 1",
			func(t *testing.T, d *ast.DeleteStatement) {
				if d.Top == nil || len(d.Output) != 1 || d.Where == nil {
					t.Errorf("Top = %v, Output = %v, Where = %v", d.Top, d.Output, d.Where)
				}
			}},
		{"oracle without from", keywords.DialectOracle, "DELETE t x WHERE x.a = 1",
			func(t *testing.T, d *ast.DeleteStatement) {
				if d.TableName != "t" || d.Alias != "x" || len(d.From) != 0 {
					t.Errorf("target = %q %q, From = %v", d.TableName, d.Alias, d.From)
				}
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmt, tree := parseDMLShape(t, tc.sql, tc.dialect)
			defer ast.ReleaseAST(tree)
			d, ok := stmt.(*ast.DeleteStatement)
			if !ok {
				t.Fatalf("expected *ast.DeleteStatement, got %T", stmt)
			}
			tc.check(t, d)
		})
	}
}

func TestDMLShape_Insert(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		check   func(t *testing.T, i *ast.InsertStatement)
	}{
		{"modifiers", keywords.DialectMySQL, "INSERT IGNORE INTO t (a) VALUES (1)",
			func(t *testing.T, i *ast.InsertStatement) {
				if !reflect.DeepEqual(i.DialectExtras().Modifiers, []string{"IGNORE"}) || i.TableName != "t" {
					t.Errorf("Modifiers = %v, TableName = %q", i.DialectExtras().Modifiers, i.TableName)
				}
			}},
		{"sqlite or replace", keywords.DialectSQLite, "INSERT OR REPLACE INTO t (a) VALUES (1)",
			func(t *testing.T, i *ast.InsertStatement) {
				if !reflect.DeepEqual(i.DialectExtras().Modifiers, []string{"OR REPLACE"}) {
					t.Errorf("Modifiers = %v", i.DialectExtras().Modifiers)
				}
			}},
		{"default values items", keywords.DialectPostgreSQL, "INSERT INTO t (a, b) VALUES (DEFAULT, 1)",
			func(t *testing.T, i *ast.InsertStatement) {
				if _, ok := i.Values[0][0].(*ast.DefaultExpr); !ok {
					t.Errorf("Values[0][0]: expected *ast.DefaultExpr, got %T", i.Values[0][0])
				}
			}},
		{"empty row", keywords.DialectMySQL, "INSERT INTO t VALUES ()",
			func(t *testing.T, i *ast.InsertStatement) {
				if len(i.Values) != 1 || len(i.Values[0]) != 0 {
					t.Errorf("Values = %v, want one empty row", i.Values)
				}
			}},
		{"row alias", keywords.DialectMySQL, "INSERT INTO t (a) VALUES (1) AS n (x) ON DUPLICATE KEY UPDATE a = n.x",
			func(t *testing.T, i *ast.InsertStatement) {
				if i.DialectExtras().RowAlias != "n" || !reflect.DeepEqual(i.DialectExtras().RowAliasColumns, []string{"x"}) || i.OnDuplicateKey == nil {
					t.Errorf("RowAlias = %q %v, OnDuplicateKey = %v", i.DialectExtras().RowAlias, i.DialectExtras().RowAliasColumns, i.OnDuplicateKey)
				}
			}},
		{"on conflict target where", keywords.DialectPostgreSQL, "INSERT INTO t (a) VALUES (1) ON CONFLICT (lower(a)) WHERE b > 0 DO NOTHING",
			func(t *testing.T, i *ast.InsertStatement) {
				if i.OnConflict == nil || i.OnConflict.TargetWhere == nil || !i.OnConflict.Action.DoNothing {
					t.Fatalf("OnConflict = %+v", i.OnConflict)
				}
				if _, ok := i.OnConflict.Target[0].(*ast.FunctionCall); !ok {
					t.Errorf("Target[0]: expected *ast.FunctionCall, got %T", i.OnConflict.Target[0])
				}
			}},
		{"overriding", keywords.DialectPostgreSQL, "INSERT INTO t (a) OVERRIDING SYSTEM VALUE VALUES (1)",
			func(t *testing.T, i *ast.InsertStatement) {
				if i.DialectExtras().Overriding != "SYSTEM" {
					t.Errorf("Overriding = %q", i.DialectExtras().Overriding)
				}
			}},
		{"returning alias into", keywords.DialectOracle, "INSERT INTO t (a) VALUES (1) RETURNING a AS x INTO :v",
			func(t *testing.T, i *ast.InsertStatement) {
				if len(i.Returning) != 1 || len(i.DialectExtras().ReturningInto) != 1 {
					t.Fatalf("Returning = %v, ReturningInto = %v", i.Returning, i.DialectExtras().ReturningInto)
				}
				if _, ok := i.Returning[0].(*ast.AliasedExpression); !ok {
					t.Errorf("Returning[0]: expected *ast.AliasedExpression, got %T", i.Returning[0])
				}
			}},
		{"output into", keywords.DialectSQLServer, "INSERT INTO t (a) OUTPUT inserted.id INTO @ids (id) VALUES (1)",
			func(t *testing.T, i *ast.InsertStatement) {
				if len(i.Output) != 1 || i.DialectExtras().OutputInto == nil || i.DialectExtras().OutputInto.Target != "@ids" {
					t.Errorf("Output = %v, OutputInto = %+v", i.Output, i.DialectExtras().OutputInto)
				}
			}},
		{"clickhouse settings function format", keywords.DialectClickHouse, "INSERT INTO FUNCTION s3('x') SETTINGS a = 1 FORMAT CSV",
			func(t *testing.T, i *ast.InsertStatement) {
				if i.DialectExtras().TableFunction == nil || i.TableName != "" {
					t.Errorf("TableFunction = %v, TableName = %q", i.DialectExtras().TableFunction, i.TableName)
				}
				if len(i.DialectExtras().Settings) != 1 || i.DialectExtras().Settings[0].Name != "a" {
					t.Errorf("Settings = %+v", i.DialectExtras().Settings)
				}
				if i.DialectExtras().DataFormat != "CSV" {
					t.Errorf("DataFormat = %q", i.DialectExtras().DataFormat)
				}
			}},
		{"oracle insert first", keywords.DialectOracle, "INSERT FIRST WHEN a > 1 THEN INTO x VALUES (a) INTO y (b) VALUES (a) ELSE INTO z SELECT a FROM s",
			func(t *testing.T, i *ast.InsertStatement) {
				m := i.DialectExtras().MultiTable
				if m == nil || !m.First || len(m.Branches) != 2 {
					t.Fatalf("MultiTable = %+v", m)
				}
				if m.Branches[0].When == nil || len(m.Branches[0].Into) != 2 {
					t.Errorf("first branch = %+v", m.Branches[0])
				}
				if !m.Branches[1].Else || m.Branches[1].Into[0].Values != nil {
					t.Errorf("ELSE branch = %+v", m.Branches[1])
				}
				if i.Query == nil {
					t.Error("Query not stored")
				}
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmt, tree := parseDMLShape(t, tc.sql, tc.dialect)
			defer ast.ReleaseAST(tree)
			i, ok := stmt.(*ast.InsertStatement)
			if !ok {
				t.Fatalf("expected *ast.InsertStatement, got %T", stmt)
			}
			tc.check(t, i)
		})
	}
}

func TestDMLShape_MergeAndReplace(t *testing.T) {
	t.Run("merge derived source and oracle predicates", func(t *testing.T) {
		stmt, tree := parseDMLShape(t,
			"MERGE INTO t USING (SELECT a, b FROM s) src ON (t.a = src.a) WHEN MATCHED THEN UPDATE SET t.b = src.b WHERE t.b <> src.b DELETE WHERE src.b IS NULL",
			keywords.DialectOracle)
		defer ast.ReleaseAST(tree)
		m, ok := stmt.(*ast.MergeStatement)
		if !ok {
			t.Fatalf("expected *ast.MergeStatement, got %T", stmt)
		}
		if m.SourceTable.Subquery == nil || m.SourceAlias != "src" || m.SourceTable.Alias != "" {
			t.Errorf("source = %+v alias %q", m.SourceTable, m.SourceAlias)
		}
		a := m.WhenClauses[0].Action
		if a.Where == nil || a.DeleteWhere == nil {
			t.Errorf("Where = %v, DeleteWhere = %v", a.Where, a.DeleteWhere)
		}
	})
	t.Run("merge do nothing, by target, returning", func(t *testing.T) {
		stmt, tree := parseDMLShape(t,
			"MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DO NOTHING WHEN NOT MATCHED BY TARGET THEN INSERT (id) VALUES (s.id) RETURNING t.id",
			keywords.DialectPostgreSQL)
		defer ast.ReleaseAST(tree)
		m, ok := stmt.(*ast.MergeStatement)
		if !ok {
			t.Fatalf("expected *ast.MergeStatement, got %T", stmt)
		}
		if m.WhenClauses[0].Action.ActionType != "DO NOTHING" {
			t.Errorf("ActionType = %q", m.WhenClauses[0].Action.ActionType)
		}
		if m.WhenClauses[1].Type != "NOT_MATCHED_BY_TARGET" {
			t.Errorf("Type = %q", m.WhenClauses[1].Type)
		}
		if len(m.Returning) != 1 {
			t.Errorf("Returning = %v", m.Returning)
		}
	})
	replaceTests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		check   func(t *testing.T, r *ast.ReplaceStatement)
	}{
		{"select", keywords.DialectMySQL, "REPLACE INTO t (a) SELECT a FROM u",
			func(t *testing.T, r *ast.ReplaceStatement) {
				if r.Query == nil || len(r.Values) != 0 {
					t.Errorf("Query = %v, Values = %v", r.Query, r.Values)
				}
			}},
		{"set", keywords.DialectMySQL, "REPLACE t SET a = 1",
			func(t *testing.T, r *ast.ReplaceStatement) {
				if !r.SetSyntax || len(r.Columns) != 1 || len(r.Values) != 1 {
					t.Errorf("SetSyntax = %v, Columns = %v, Values = %v", r.SetSyntax, r.Columns, r.Values)
				}
			}},
		{"returning", keywords.DialectMariaDB, "REPLACE INTO t (a) VALUES (1) RETURNING a",
			func(t *testing.T, r *ast.ReplaceStatement) {
				if len(r.Returning) != 1 {
					t.Errorf("Returning = %v", r.Returning)
				}
			}},
	}
	for _, tc := range replaceTests {
		t.Run("replace "+tc.name, func(t *testing.T) {
			stmt, tree := parseDMLShape(t, tc.sql, tc.dialect)
			defer ast.ReleaseAST(tree)
			r, ok := stmt.(*ast.ReplaceStatement)
			if !ok {
				t.Fatalf("expected *ast.ReplaceStatement, got %T", stmt)
			}
			tc.check(t, r)
		})
	}
}
