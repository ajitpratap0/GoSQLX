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
	"fmt"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// A T-SQL utility statement ends at the word that starts the next statement,
// so a batch written without semicolons keeps the statements after it
// visible to the linter, scanner and analyzer.
func TestParser_UtilityStatementEndsAtNextStatement(t *testing.T) {
	const (
		set  = "*ast.SetStatement"
		sel  = "*ast.SelectStatement"
		upd  = "*ast.UpdateStatement"
		del  = "*ast.DeleteStatement"
		ins  = "*ast.InsertStatement"
		tx   = "*ast.TransactionStatement"
		use  = "*ast.UseStatement"
		util = "*ast.UtilityStatement"
	)
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    []string
	}{
		{"set then select", keywords.DialectSQLServer, "SET NOCOUNT ON\nSELECT * FROM t", []string{set, sel}},
		{"set then set then dml", keywords.DialectSQLServer,
			"SET NOCOUNT ON SET XACT_ABORT ON DELETE FROM t WHERE a = 1", []string{set, set, del}},
		{"set variable subquery stays whole", keywords.DialectSQLServer,
			"SET @x = (SELECT MAX(id) FROM t) SELECT @x", []string{set, sel}},
		{"set variable case", keywords.DialectSQLServer,
			"SET @x = CASE WHEN @y > 1 THEN 1 ELSE 2 END UPDATE t SET a = @x", []string{set, upd}},
		{"set transaction isolation", keywords.DialectSQLServer,
			"SET TRANSACTION ISOLATION LEVEL READ COMMITTED SELECT 1", []string{set, sel}},
		{"begin tran then update", keywords.DialectSQLServer,
			"BEGIN TRANSACTION\nUPDATE t SET a = 1", []string{tx, upd}},
		{"begin tran with mark keeps option", keywords.DialectSQLServer,
			"BEGIN TRANSACTION t1 WITH MARK 'x' UPDATE t SET a = 1", []string{tx, upd}},
		{"commit then select", keywords.DialectSQLServer, "COMMIT TRAN SELECT 1", []string{tx, sel}},
		{"commit delayed durability option", keywords.DialectSQLServer,
			"COMMIT TRANSACTION WITH (DELAYED_DURABILITY = ON) SELECT 1", []string{tx, sel}},
		{"rollback then insert", keywords.DialectSQLServer,
			"ROLLBACK TRAN INSERT INTO t (a) VALUES (1)", []string{tx, ins}},
		{"use then select", keywords.DialectSQLServer, "USE mydb SELECT 1", []string{use, sel}},
		{"declare then set then select", keywords.DialectSQLServer,
			"DECLARE @n INT = 5 SET @n = @n + 1 SELECT @n", []string{util, set, sel}},
		{"declare cursor keeps its select", keywords.DialectSQLServer,
			"DECLARE c CURSOR FOR SELECT a FROM t", []string{util}},
		{"declare cursor for update", keywords.DialectSQLServer,
			"DECLARE c CURSOR FOR SELECT a FROM t FOR UPDATE OF a", []string{util}},
		{"exec with recompile option", keywords.DialectSQLServer,
			"EXEC sp_x 1, 2 WITH RECOMPILE SELECT 1", []string{util, sel}},
		{"exec then cte", keywords.DialectSQLServer,
			"EXEC sp_x 1 WITH c AS (SELECT 1 a) SELECT * FROM c", []string{util, sel}},
		{"print then select", keywords.DialectSQLServer, "PRINT 'hello' SELECT 1", []string{util, sel}},
		{"raiserror with nowait", keywords.DialectSQLServer,
			"RAISERROR ('x', 10, 1) WITH NOWAIT SELECT 1", []string{util, sel}},
		{"bracketed word is a name", keywords.DialectSQLServer,
			"SET @x = [update] SELECT 1", []string{set, sel}},
		{"semicolons still separate", keywords.DialectSQLServer,
			"SET NOCOUNT ON; SELECT 1;", []string{set, sel}},
		// Statements that own a nested body keep running to the semicolon.
		{"if keeps its body", keywords.DialectSQLServer,
			"IF @x = 1 SELECT 1 ELSE SELECT 2", []string{util}},
		{"grant keeps select privilege", keywords.DialectSQLServer,
			"GRANT SELECT, INSERT ON t TO u", []string{util}},
		// Other dialects need a semicolon: a SELECT after a SET without one is
		// part of the SET, as before.
		{"mysql set subquery", keywords.DialectMySQL, "SET @x = (SELECT MAX(id) FROM t)", []string{set}},
		{"mysql set global", keywords.DialectMySQL, "SET GLOBAL max_connections = 100", []string{set}},
		{"mysql set then select with semicolon", keywords.DialectMySQL,
			"SET @x = 1; SELECT @x", []string{set, sel}},
		{"mysql set names", keywords.DialectMySQL, "SET NAMES utf8mb4", []string{set}},
		{"mysql grant select", keywords.DialectMySQL, "GRANT SELECT, INSERT ON db.* TO 'u'@'h'", []string{util}},
		{"mysql does not split without semicolon", keywords.DialectMySQL,
			"SET @x = 1 SELECT @x", []string{set}},
		{"postgres set search_path", keywords.DialectPostgreSQL,
			"SET search_path TO public, other", []string{set}},
		{"postgres begin then commit", keywords.DialectPostgreSQL, "BEGIN; COMMIT", []string{tx, tx}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatalf("parse %q (%s): %v", tc.sql, tc.dialect, err)
			}
			got := make([]string, len(tree.Statements))
			for i, s := range tree.Statements {
				got[i] = fmt.Sprintf("%T", s)
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("statements = %v, want %v", got, tc.want)
			}
		})
	}
}

// The Set / Transaction text of a statement that ended implicitly holds only
// its own tokens.
func TestParser_UtilityStatementImplicitEndText(t *testing.T) {
	tree, err := ParseWithDialect("SET NOCOUNT ON\nBEGIN TRAN t1\nSELECT 1", keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(tree.Statements) != 3 {
		t.Fatalf("got %d statements, want 3", len(tree.Statements))
	}
	set, ok := tree.Statements[0].(*ast.SetStatement)
	if !ok {
		t.Fatalf("statement 0 is %T, want *ast.SetStatement", tree.Statements[0])
	}
	if set.Text != "SET NOCOUNT ON" || set.Name != "NOCOUNT" {
		t.Errorf("set = %q name %q, want %q name NOCOUNT", set.Text, set.Name, "SET NOCOUNT ON")
	}
	tx, ok := tree.Statements[1].(*ast.TransactionStatement)
	if !ok {
		t.Fatalf("statement 1 is %T, want *ast.TransactionStatement", tree.Statements[1])
	}
	if tx.Text != "BEGIN TRAN t1" {
		t.Errorf("transaction text = %q, want %q", tx.Text, "BEGIN TRAN t1")
	}
}

// A parser reused for a second parse must not carry the implicit-boundary
// mark of the first one.
func TestParser_ImplicitEndResetsBetweenParses(t *testing.T) {
	p := NewParser(WithDialect(string(keywords.DialectSQLServer)))
	defer p.Release()
	for i := 0; i < 2; i++ {
		tree, err := parseWith(t, p, "SET NOCOUNT ON SELECT 1")
		if err != nil {
			t.Fatalf("parse %d: %v", i, err)
		}
		if len(tree.Statements) != 2 {
			t.Fatalf("parse %d: got %d statements, want 2", i, len(tree.Statements))
		}
	}
}
