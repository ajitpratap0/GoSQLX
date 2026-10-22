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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseAlterTable parses sql in dialect and returns its only statement, which
// must be an ALTER TABLE. The caller must release the returned AST.
func parseAlterTable(t *testing.T, sql string, dialect keywords.SQLDialect) (*ast.AlterStatement, *ast.AST) {
	t.Helper()
	tree, err := ParseWithDialect(sql, dialect)
	if err != nil {
		t.Fatalf("ParseWithDialect(%q, %s): %v", sql, dialect, err)
	}
	if len(tree.Statements) != 1 {
		ast.ReleaseAST(tree)
		t.Fatalf("expected 1 statement for %q, got %d", sql, len(tree.Statements))
	}
	stmt, ok := tree.Statements[0].(*ast.AlterStatement)
	if !ok {
		ast.ReleaseAST(tree)
		t.Fatalf("expected *ast.AlterStatement for %q, got %T", sql, tree.Statements[0])
	}
	if stmt.Type != ast.AlterTypeTable {
		ast.ReleaseAST(tree)
		t.Fatalf("Type = %v, want AlterTypeTable", stmt.Type)
	}
	return stmt, tree
}

// alterOpAt returns operation i of stmt as an *ast.AlterTableOperation.
func alterOpAt(t *testing.T, stmt *ast.AlterStatement, i int) *ast.AlterTableOperation {
	t.Helper()
	if i >= len(stmt.Operations) {
		t.Fatalf("operation %d: statement has %d operations", i, len(stmt.Operations))
	}
	op, ok := stmt.Operations[i].(*ast.AlterTableOperation)
	if !ok {
		t.Fatalf("operation %d: expected *ast.AlterTableOperation, got %T", i, stmt.Operations[i])
	}
	return op
}

func TestAlterTable_Header(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		check   func(t *testing.T, s *ast.AlterStatement)
	}{
		{"schema qualified (SQL Server)", keywords.DialectSQLServer, "ALTER TABLE dbo.t ADD c INT",
			func(t *testing.T, s *ast.AlterStatement) {
				if s.Name != "dbo.t" {
					t.Errorf("Name = %q, want dbo.t", s.Name)
				}
			}},
		{"three part (Snowflake)", keywords.DialectSnowflake, "ALTER TABLE db.sch.t DROP COLUMN c",
			func(t *testing.T, s *ast.AlterStatement) {
				if s.Name != "db.sch.t" {
					t.Errorf("Name = %q, want db.sch.t", s.Name)
				}
			}},
		{"IF EXISTS and ONLY (PostgreSQL)", keywords.DialectPostgreSQL, "ALTER TABLE IF EXISTS ONLY public.t DROP COLUMN c",
			func(t *testing.T, s *ast.AlterStatement) {
				if !s.IfExists || !s.Only || s.Name != "public.t" {
					t.Errorf("IfExists=%v Only=%v Name=%q", s.IfExists, s.Only, s.Name)
				}
			}},
		{"ON CLUSTER (ClickHouse)", keywords.DialectClickHouse, "ALTER TABLE db.t ON CLUSTER my_cluster ADD COLUMN x UInt8",
			func(t *testing.T, s *ast.AlterStatement) {
				if s.OnCluster != "my_cluster" || s.Name != "db.t" {
					t.Errorf("OnCluster=%q Name=%q", s.OnCluster, s.Name)
				}
			}},
		{"ON CLUSTER string (ClickHouse)", keywords.DialectClickHouse, "ALTER TABLE t ON CLUSTER '{cluster}' DROP COLUMN x",
			func(t *testing.T, s *ast.AlterStatement) {
				if s.OnCluster != "'{cluster}'" {
					t.Errorf("OnCluster = %q, want '{cluster}'", s.OnCluster)
				}
			}},
		{"ONLINE modifier (MariaDB)", keywords.DialectMariaDB, "ALTER ONLINE TABLE t ADD COLUMN c INT",
			func(t *testing.T, s *ast.AlterStatement) {
				if len(s.Modifiers) != 1 || s.Modifiers[0] != "ONLINE" {
					t.Errorf("Modifiers = %v, want [ONLINE]", s.Modifiers)
				}
			}},
		{"IGNORE modifier (MySQL)", keywords.DialectMySQL, "ALTER IGNORE TABLE t ADD COLUMN c INT",
			func(t *testing.T, s *ast.AlterStatement) {
				if len(s.Modifiers) != 1 || s.Modifiers[0] != "IGNORE" {
					t.Errorf("Modifiers = %v, want [IGNORE]", s.Modifiers)
				}
			}},
		{"multiple actions", keywords.DialectPostgreSQL, "ALTER TABLE t ADD COLUMN a int, DROP COLUMN b, RENAME COLUMN c TO d",
			func(t *testing.T, s *ast.AlterStatement) {
				if len(s.Operations) != 3 {
					t.Fatalf("got %d operations, want 3", len(s.Operations))
				}
				if s.Operation != s.Operations[0] {
					t.Errorf("Operation is not Operations[0]")
				}
				want := []ast.AlterTableOpType{ast.AddColumn, ast.DropColumn, ast.RenameColumn}
				for i, w := range want {
					if got := alterOpAt(t, s, i).Type; got != w {
						t.Errorf("operation %d: Type = %v, want %v", i, got, w)
					}
				}
				if got := len(s.Children()); got != 3 {
					t.Errorf("Children() = %d nodes, want 3", got)
				}
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmt, tree := parseAlterTable(t, tc.sql, tc.dialect)
			defer ast.ReleaseAST(tree)
			tc.check(t, stmt)
		})
	}
}

func TestAlterTable_AddColumn(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		check   func(t *testing.T, op *ast.AlterTableOperation)
	}{
		{"IF NOT EXISTS", keywords.DialectPostgreSQL, "ALTER TABLE t ADD COLUMN IF NOT EXISTS phone VARCHAR(32)",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.AddColumn || !op.IfNotExists || op.NoColumnKeyword || op.ColumnDef == nil || op.ColumnDef.Name != "phone" {
					t.Errorf("op = %+v", op)
				}
			}},
		{"without COLUMN (SQL Server)", keywords.DialectSQLServer, "ALTER TABLE t ADD c INT NULL",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.AddColumn || !op.NoColumnKeyword || op.ColumnDef == nil || op.ColumnDef.Name != "c" {
					t.Errorf("op = %+v", op)
				}
			}},
		{"SQL Server column list", keywords.DialectSQLServer, "ALTER TABLE t ADD a INT NULL, b INT NOT NULL",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if len(op.ColumnDefs) != 2 || op.ColumnDefs[0] != op.ColumnDef || op.ColumnDefs[1].Name != "b" || op.Parenthesized {
					t.Errorf("ColumnDefs = %v, Parenthesized = %v", op.ColumnDefs, op.Parenthesized)
				}
			}},
		{"Oracle parenthesized list", keywords.DialectOracle, "ALTER TABLE t ADD (a NUMBER, b VARCHAR2(10) DEFAULT 'x')",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if !op.Parenthesized || len(op.ColumnDefs) != 2 || !op.NoColumnKeyword {
					t.Errorf("Parenthesized=%v ColumnDefs=%d NoColumnKeyword=%v", op.Parenthesized, len(op.ColumnDefs), op.NoColumnKeyword)
				}
			}},
		{"AFTER column (MySQL)", keywords.DialectMySQL, "ALTER TABLE t ADD COLUMN c INT NULL AFTER b",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.ColumnPosition == nil || op.ColumnPosition.First || op.ColumnPosition.After == nil || op.ColumnPosition.After.Name != "b" {
					t.Errorf("ColumnPosition = %+v", op.ColumnPosition)
				}
			}},
		{"FIRST (MySQL)", keywords.DialectMySQL, "ALTER TABLE t ADD COLUMN c INT FIRST",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.ColumnPosition == nil || !op.ColumnPosition.First {
					t.Errorf("ColumnPosition = %+v", op.ColumnPosition)
				}
			}},
		{"AFTER column (ClickHouse)", keywords.DialectClickHouse, "ALTER TABLE t ADD COLUMN c UInt8 AFTER b",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.ColumnPosition == nil || op.ColumnPosition.After == nil || op.ColumnPosition.After.Name != "b" {
					t.Errorf("ColumnPosition = %+v", op.ColumnPosition)
				}
			}},
		{"IF NOT EXISTS without COLUMN (MariaDB)", keywords.DialectMariaDB, "ALTER TABLE t ADD IF NOT EXISTS c INT",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if !op.IfNotExists || !op.NoColumnKeyword {
					t.Errorf("IfNotExists=%v NoColumnKeyword=%v", op.IfNotExists, op.NoColumnKeyword)
				}
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmt, tree := parseAlterTable(t, tc.sql, tc.dialect)
			defer ast.ReleaseAST(tree)
			tc.check(t, alterOpAt(t, stmt, 0))
		})
	}
}

func TestAlterTable_Constraints(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		check   func(t *testing.T, op *ast.AlterTableOperation)
	}{
		{"ADD PRIMARY KEY is bare", keywords.DialectPostgreSQL, "ALTER TABLE t ADD PRIMARY KEY (a)",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.AddConstraint || !op.BareConstraint || op.Constraint == nil || op.Constraint.Type != "PRIMARY KEY" {
					t.Errorf("op = %+v", op)
				}
			}},
		{"ADD CONSTRAINT keeps the keyword", keywords.DialectPostgreSQL, "ALTER TABLE t ADD CONSTRAINT c CHECK (a > 0) NOT VALID",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.BareConstraint || op.Constraint == nil || op.Constraint.Name != "c" || op.ConstraintSuffix != "NOT VALID" {
					t.Errorf("BareConstraint=%v Constraint=%+v Suffix=%q", op.BareConstraint, op.Constraint, op.ConstraintSuffix)
				}
			}},
		{"foreign key with deferrable clause", keywords.DialectPostgreSQL, "ALTER TABLE t ADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES u (id) DEFERRABLE INITIALLY DEFERRED",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Constraint == nil || op.Constraint.Type != "FOREIGN KEY" ||
					op.Constraint.Deferrable != "DEFERRABLE INITIALLY DEFERRED" || op.ConstraintSuffix != "" {
					t.Errorf("Constraint=%+v Suffix=%q", op.Constraint, op.ConstraintSuffix)
				}
			}},
		{"NONCLUSTERED (SQL Server)", keywords.DialectSQLServer, "ALTER TABLE t ADD CONSTRAINT uq UNIQUE NONCLUSTERED (a, b)",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Clustering != "NONCLUSTERED" || op.Constraint == nil || op.Constraint.Type != "UNIQUE" || len(op.Constraint.Columns) != 2 {
					t.Errorf("Clustering=%q Constraint=%+v", op.Clustering, op.Constraint)
				}
			}},
		{"WITH NOCHECK modifier (SQL Server)", keywords.DialectSQLServer, "ALTER TABLE t WITH NOCHECK ADD CONSTRAINT c CHECK (a > 0)",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Modifier != "WITH NOCHECK" || op.Type != ast.AddConstraint {
					t.Errorf("Modifier=%q Type=%v", op.Modifier, op.Type)
				}
			}},
		{"DROP CONSTRAINT IF EXISTS", keywords.DialectPostgreSQL, "ALTER TABLE t DROP CONSTRAINT IF EXISTS c CASCADE",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.DropConstraint || !op.IfExists || !op.CascadeDrops || op.ConstraintName == nil || op.ConstraintName.Name != "c" || op.ConstraintKind != "" {
					t.Errorf("op = %+v", op)
				}
			}},
		{"DROP CONSTRAINT RESTRICT", keywords.DialectPostgreSQL, "ALTER TABLE t DROP CONSTRAINT c RESTRICT",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if !op.Restrict || op.CascadeDrops {
					t.Errorf("Restrict=%v CascadeDrops=%v", op.Restrict, op.CascadeDrops)
				}
			}},
		{"DROP PRIMARY KEY (MySQL)", keywords.DialectMySQL, "ALTER TABLE t DROP PRIMARY KEY",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.DropConstraint || op.ConstraintKind != "PRIMARY KEY" {
					t.Errorf("op = %+v", op)
				}
			}},
		{"DROP FOREIGN KEY (MySQL)", keywords.DialectMySQL, "ALTER TABLE t DROP FOREIGN KEY fk",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.ConstraintKind != "FOREIGN KEY" || op.ConstraintName == nil || op.ConstraintName.Name != "fk" {
					t.Errorf("op = %+v", op)
				}
			}},
		{"DROP CHECK (MySQL)", keywords.DialectMySQL, "ALTER TABLE t DROP CHECK chk",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.ConstraintKind != "CHECK" || op.ConstraintName == nil || op.ConstraintName.Name != "chk" {
					t.Errorf("op = %+v", op)
				}
			}},
		{"RENAME CONSTRAINT", keywords.DialectPostgreSQL, "ALTER TABLE t RENAME CONSTRAINT a TO b",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.RenameConstraint || op.OldName == nil || op.NewName == nil || op.OldName.Name != "a" || op.NewName.Name != "b" {
					t.Errorf("op = %+v", op)
				}
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmt, tree := parseAlterTable(t, tc.sql, tc.dialect)
			defer ast.ReleaseAST(tree)
			tc.check(t, alterOpAt(t, stmt, 0))
		})
	}
}

func TestAlterTable_Indexes(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		check   func(t *testing.T, op *ast.AlterTableOperation)
	}{
		{"ADD INDEX", keywords.DialectMySQL, "ALTER TABLE t ADD INDEX ix (a, b(10))",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.AddIndex || op.IndexKeyword != "INDEX" || op.IndexName != "ix" || op.Text != "(a, b(10))" || op.IndexKind != "" {
					t.Errorf("op = %+v", op)
				}
			}},
		{"ADD UNIQUE KEY", keywords.DialectMySQL, "ALTER TABLE t ADD UNIQUE KEY ux (a)",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.IndexKind != "UNIQUE" || op.IndexKeyword != "KEY" || op.IndexName != "ux" {
					t.Errorf("op = %+v", op)
				}
			}},
		{"ADD UNIQUE is an index in MySQL", keywords.DialectMySQL, "ALTER TABLE t ADD UNIQUE (a)",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.AddIndex || op.IndexKind != "UNIQUE" || op.IndexName != "" {
					t.Errorf("op = %+v", op)
				}
			}},
		{"ADD UNIQUE is a constraint in PostgreSQL", keywords.DialectPostgreSQL, "ALTER TABLE t ADD UNIQUE (a)",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.AddConstraint || op.Constraint == nil || op.Constraint.Type != "UNIQUE" {
					t.Errorf("op = %+v", op)
				}
			}},
		{"ADD FULLTEXT INDEX", keywords.DialectMySQL, "ALTER TABLE t ADD FULLTEXT INDEX ft (title)",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.IndexKind != "FULLTEXT" || op.IndexName != "ft" {
					t.Errorf("op = %+v", op)
				}
			}},
		{"ADD INDEX IF NOT EXISTS (MariaDB)", keywords.DialectMariaDB, "ALTER TABLE t ADD INDEX IF NOT EXISTS ix (a)",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if !op.IfNotExists || op.IndexName != "ix" {
					t.Errorf("op = %+v", op)
				}
			}},
		{"ADD INDEX (ClickHouse)", keywords.DialectClickHouse, "ALTER TABLE t ADD INDEX i a TYPE bloom_filter GRANULARITY 3",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.IndexName != "i" || op.Text != "a TYPE bloom_filter GRANULARITY 3" {
					t.Errorf("IndexName=%q Text=%q", op.IndexName, op.Text)
				}
			}},
		{"DROP INDEX IF EXISTS", keywords.DialectMariaDB, "ALTER TABLE t DROP INDEX IF EXISTS ix",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.DropIndex || !op.IfExists || op.IndexName != "ix" || op.IndexKeyword != "INDEX" {
					t.Errorf("op = %+v", op)
				}
			}},
		{"DROP KEY", keywords.DialectMySQL, "ALTER TABLE t DROP KEY ix",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.DropIndex || op.IndexKeyword != "KEY" {
					t.Errorf("op = %+v", op)
				}
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmt, tree := parseAlterTable(t, tc.sql, tc.dialect)
			defer ast.ReleaseAST(tree)
			tc.check(t, alterOpAt(t, stmt, 0))
		})
	}
}

func TestAlterTable_DropRenameModify(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		check   func(t *testing.T, op *ast.AlterTableOperation)
	}{
		{"DROP COLUMN IF EXISTS", keywords.DialectPostgreSQL, "ALTER TABLE t DROP COLUMN IF EXISTS a",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.DropColumn || !op.IfExists || op.NoColumnKeyword || op.ColumnName == nil || op.ColumnName.Name != "a" {
					t.Errorf("op = %+v", op)
				}
			}},
		{"DROP without COLUMN (MySQL)", keywords.DialectMySQL, "ALTER TABLE t DROP c",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.DropColumn || !op.NoColumnKeyword || op.ColumnName == nil || op.ColumnName.Name != "c" {
					t.Errorf("op = %+v", op)
				}
			}},
		{"DROP COLUMN list (SQL Server)", keywords.DialectSQLServer, "ALTER TABLE t DROP COLUMN a, b",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.ColumnName == nil || op.ColumnName.Name != "a" || len(op.ExtraNames) != 1 || op.ExtraNames[0].Name != "b" {
					t.Errorf("op = %+v", op)
				}
			}},
		{"RENAME TO qualified", keywords.DialectPostgreSQL, "ALTER TABLE t RENAME TO s.u",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.RenameTable || op.NewTableName.Name != "s.u" {
					t.Errorf("op = %+v", op)
				}
			}},
		{"RENAME without TO (MySQL)", keywords.DialectMySQL, "ALTER TABLE t RENAME u",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.RenameTable || op.NewTableName.Name != "u" {
					t.Errorf("op = %+v", op)
				}
			}},
		{"RENAME column without COLUMN (PostgreSQL)", keywords.DialectPostgreSQL, "ALTER TABLE t RENAME a TO b",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.RenameColumn || !op.NoColumnKeyword || op.ColumnName == nil || op.NewColumnName == nil {
					t.Errorf("op = %+v", op)
				}
			}},
		{"MODIFY COLUMN (MySQL)", keywords.DialectMySQL, "ALTER TABLE t MODIFY COLUMN c INT NOT NULL AFTER b",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.ModifyColumn || op.ColumnDef == nil || op.ColumnDef.Name != "c" || op.ColumnPosition == nil {
					t.Errorf("op = %+v", op)
				}
			}},
		{"MODIFY list (Oracle)", keywords.DialectOracle, "ALTER TABLE t MODIFY (a VARCHAR2(20) NOT NULL, b NUMBER)",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.ModifyColumn || !op.Parenthesized || len(op.ColumnDefs) != 2 {
					t.Errorf("op = %+v", op)
				}
			}},
		{"CHANGE COLUMN (MySQL)", keywords.DialectMySQL, "ALTER TABLE t CHANGE COLUMN a b INT FIRST",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.ChangeColumn || op.ColumnName == nil || op.ColumnName.Name != "a" || op.ColumnDef == nil || op.ColumnDef.Name != "b" || op.ColumnPosition == nil || !op.ColumnPosition.First {
					t.Errorf("op = %+v", op)
				}
			}},
		{"MODIFY COLUMN SET MASKING POLICY (Snowflake)", keywords.DialectSnowflake, "ALTER TABLE t MODIFY COLUMN email SET MASKING POLICY email_mask",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.ModifyColumn || op.AlterColumnOp == nil || *op.AlterColumnOp != ast.AlterColumnOther ||
					op.Keyword != "SET" || op.Text != "MASKING POLICY email_mask" || op.ColumnName == nil || op.ColumnName.Name != "email" {
					t.Errorf("op = %+v", op)
				}
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmt, tree := parseAlterTable(t, tc.sql, tc.dialect)
			defer ast.ReleaseAST(tree)
			tc.check(t, alterOpAt(t, stmt, 0))
		})
	}
}

func TestAlterTable_AlterColumn(t *testing.T) {
	colOp := func(t *testing.T, op *ast.AlterTableOperation, want ast.AlterColumnOperation) {
		t.Helper()
		if op.Type != ast.AlterColumn {
			t.Fatalf("Type = %v, want AlterColumn", op.Type)
		}
		if op.AlterColumnOp == nil {
			t.Fatalf("AlterColumnOp is nil")
		}
		if *op.AlterColumnOp != want {
			t.Fatalf("AlterColumnOp = %v, want %v", *op.AlterColumnOp, want)
		}
	}
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		check   func(t *testing.T, op *ast.AlterTableOperation)
	}{
		{"SET DEFAULT literal", keywords.DialectPostgreSQL, "ALTER TABLE t ALTER COLUMN a SET DEFAULT 5",
			func(t *testing.T, op *ast.AlterTableOperation) {
				colOp(t, op, ast.AlterColumnSetDefault)
				if _, ok := op.DefaultValue.(*ast.LiteralValue); !ok {
					t.Errorf("DefaultValue: expected *ast.LiteralValue, got %T", op.DefaultValue)
				}
			}},
		{"SET DEFAULT expression", keywords.DialectPostgreSQL, "ALTER TABLE t ALTER COLUMN a SET DEFAULT now() + interval '1 day'",
			func(t *testing.T, op *ast.AlterTableOperation) {
				colOp(t, op, ast.AlterColumnSetDefault)
				if op.DefaultValue == nil {
					t.Errorf("DefaultValue is nil")
				}
			}},
		{"DROP DEFAULT is not a data type", keywords.DialectMySQL, "ALTER TABLE t ALTER COLUMN a DROP DEFAULT",
			func(t *testing.T, op *ast.AlterTableOperation) {
				colOp(t, op, ast.AlterColumnDropDefault)
				if op.ColumnDef != nil {
					t.Errorf("ColumnDef = %+v, want nil", op.ColumnDef)
				}
			}},
		{"SET NOT NULL without COLUMN", keywords.DialectPostgreSQL, "ALTER TABLE t ALTER a SET NOT NULL",
			func(t *testing.T, op *ast.AlterTableOperation) {
				colOp(t, op, ast.AlterColumnSetNotNull)
				if !op.NoColumnKeyword {
					t.Errorf("NoColumnKeyword = false")
				}
			}},
		{"DROP NOT NULL", keywords.DialectPostgreSQL, "ALTER TABLE t ALTER COLUMN a DROP NOT NULL",
			func(t *testing.T, op *ast.AlterTableOperation) { colOp(t, op, ast.AlterColumnDropNotNull) }},
		{"TYPE USING", keywords.DialectPostgreSQL, "ALTER TABLE t ALTER COLUMN a TYPE bigint USING a::bigint",
			func(t *testing.T, op *ast.AlterTableOperation) {
				colOp(t, op, ast.AlterColumnSetDataType)
				if op.Keyword != "TYPE" || op.DataType != "bigint" || op.Using == nil {
					t.Errorf("Keyword=%q DataType=%q Using=%v", op.Keyword, op.DataType, op.Using)
				}
			}},
		{"SET DATA TYPE", keywords.DialectSnowflake, "ALTER TABLE t ALTER COLUMN a SET DATA TYPE VARCHAR(10)",
			func(t *testing.T, op *ast.AlterTableOperation) {
				colOp(t, op, ast.AlterColumnSetDataType)
				if op.Keyword != "SET DATA TYPE" || op.DataType != "VARCHAR(10)" || op.Using != nil {
					t.Errorf("Keyword=%q DataType=%q Using=%v", op.Keyword, op.DataType, op.Using)
				}
			}},
		{"other sub-action", keywords.DialectPostgreSQL, "ALTER TABLE t ALTER COLUMN a SET STATISTICS 100",
			func(t *testing.T, op *ast.AlterTableOperation) {
				colOp(t, op, ast.AlterColumnOther)
				if op.Keyword != "SET" || op.Text != "STATISTICS 100" {
					t.Errorf("Keyword=%q Text=%q", op.Keyword, op.Text)
				}
			}},
		{"full definition (SQL Server)", keywords.DialectSQLServer, "ALTER TABLE t ALTER COLUMN Name NVARCHAR(400) NOT NULL",
			func(t *testing.T, op *ast.AlterTableOperation) {
				if op.Type != ast.AlterColumn || op.AlterColumnOp != nil || op.ColumnDef == nil ||
					op.ColumnDef.Name != "Name" || op.ColumnDef.Type != "NVARCHAR(400)" {
					t.Errorf("op = %+v", op)
				}
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmt, tree := parseAlterTable(t, tc.sql, tc.dialect)
			defer ast.ReleaseAST(tree)
			tc.check(t, alterOpAt(t, stmt, 0))
		})
	}
}

func TestAlterTable_OtherActions(t *testing.T) {
	tests := []struct {
		name        string
		dialect     keywords.SQLDialect
		sql         string
		wantActions int
		keyword     string
		text        string
	}{
		{"enable row level security", keywords.DialectPostgreSQL, "ALTER TABLE t ENABLE ROW LEVEL SECURITY", 1, "ENABLE ROW LEVEL SECURITY", ""},
		{"validate constraint", keywords.DialectPostgreSQL, "ALTER TABLE t VALIDATE CONSTRAINT c", 1, "VALIDATE CONSTRAINT", "c"},
		{"owner to", keywords.DialectPostgreSQL, "ALTER TABLE t OWNER TO bob", 1, "OWNER TO", "bob"},
		{"set storage parameters", keywords.DialectPostgreSQL, "ALTER TABLE t SET (fillfactor = 70, autovacuum_enabled = false)", 1, "SET", "(fillfactor = 70, autovacuum_enabled = false)"},
		{"attach partition", keywords.DialectPostgreSQL, "ALTER TABLE t ATTACH PARTITION p FOR VALUES IN ('a')", 1, "ATTACH PARTITION", "p FOR VALUES IN ('a')"},
		{"engine option", keywords.DialectMySQL, "ALTER TABLE t ENGINE=InnoDB", 1, "", "ENGINE=InnoDB"},
		{"options are separate actions", keywords.DialectMySQL, "ALTER TABLE t ENGINE=InnoDB, ALGORITHM=INPLACE, LOCK=NONE", 3, "", "ENGINE=InnoDB"},
		{"default charset", keywords.DialectMySQL, "ALTER TABLE t DEFAULT CHARSET=utf8mb4", 1, "DEFAULT", "CHARSET=utf8mb4"},
		{"convert to character set", keywords.DialectMySQL, "ALTER TABLE t CONVERT TO CHARACTER SET utf8mb4", 1, "CONVERT TO CHARACTER SET", "utf8mb4"},
		{"drop partition list", keywords.DialectMySQL, "ALTER TABLE t DROP PARTITION p1, p2", 1, "DROP PARTITION", "p1, p2"},
		{"order by", keywords.DialectMySQL, "ALTER TABLE t ORDER BY a, b DESC", 1, "ORDER BY", "a, b DESC"},
		{"rename index", keywords.DialectMySQL, "ALTER TABLE t RENAME INDEX a TO b", 1, "RENAME INDEX", "a TO b"},
		{"disable keys", keywords.DialectMySQL, "ALTER TABLE t DISABLE KEYS", 1, "DISABLE KEYS", ""},
		{"add system versioning", keywords.DialectMariaDB, "ALTER TABLE t ADD SYSTEM VERSIONING", 1, "ADD SYSTEM VERSIONING", ""},
		{"disable constraint", keywords.DialectOracle, "ALTER TABLE t DISABLE CONSTRAINT c", 1, "DISABLE CONSTRAINT", "c"},
		{"enable novalidate", keywords.DialectOracle, "ALTER TABLE t ENABLE NOVALIDATE CONSTRAINT c", 1, "ENABLE NOVALIDATE CONSTRAINT", "c"},
		{"move tablespace", keywords.DialectOracle, "ALTER TABLE t MOVE TABLESPACE users2", 1, "MOVE TABLESPACE", "users2"},
		{"add partition", keywords.DialectOracle, "ALTER TABLE t ADD PARTITION p VALUES LESS THAN (10)", 1, "ADD PARTITION", "p VALUES LESS THAN (10)"},
		{"nocheck constraint", keywords.DialectSQLServer, "ALTER TABLE t NOCHECK CONSTRAINT fk", 1, "NOCHECK CONSTRAINT", "fk"},
		{"cluster by", keywords.DialectSnowflake, "ALTER TABLE t CLUSTER BY (a, b)", 1, "CLUSTER BY", "(a, b)"},
		{"swap with", keywords.DialectSnowflake, "ALTER TABLE a.b SWAP WITH a.c", 1, "SWAP WITH", "a.c"},
		{"set properties keep their commas", keywords.DialectSnowflake, "ALTER TABLE t SET DATA_RETENTION_TIME_IN_DAYS = 7, COMMENT = 'x'", 1, "SET", "DATA_RETENTION_TIME_IN_DAYS = 7, COMMENT = 'x'"},
		{"add row access policy", keywords.DialectSnowflake, "ALTER TABLE t ADD ROW ACCESS POLICY rap ON (region)", 1, "ADD ROW ACCESS POLICY", "rap ON (region)"},
		{"modify ttl", keywords.DialectClickHouse, "ALTER TABLE t MODIFY TTL ts + INTERVAL 6 MONTH", 1, "MODIFY TTL", "ts + INTERVAL 6 MONTH"},
		{"modify setting keeps commas", keywords.DialectClickHouse, "ALTER TABLE t MODIFY SETTING a = 1, b = 2", 1, "MODIFY SETTING", "a = 1, b = 2"},
		{"drop partition id", keywords.DialectClickHouse, "ALTER TABLE t DROP PARTITION ID '20240101'", 1, "DROP PARTITION ID", "'20240101'"},
		{"move partition", keywords.DialectClickHouse, "ALTER TABLE t MOVE PARTITION '202401' TO TABLE e", 1, "MOVE PARTITION", "'202401' TO TABLE e"},
		{"materialize index", keywords.DialectClickHouse, "ALTER TABLE t MATERIALIZE INDEX i", 1, "MATERIALIZE INDEX", "i"},
		{"clear column in partition", keywords.DialectClickHouse, "ALTER TABLE t CLEAR COLUMN a IN PARTITION '202401'", 1, "CLEAR COLUMN", "a IN PARTITION '202401'"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmt, tree := parseAlterTable(t, tc.sql, tc.dialect)
			defer ast.ReleaseAST(tree)
			if len(stmt.Operations) != tc.wantActions {
				t.Fatalf("got %d actions, want %d", len(stmt.Operations), tc.wantActions)
			}
			op := alterOpAt(t, stmt, 0)
			if op.Type != ast.AlterTableOther {
				t.Fatalf("Type = %v, want AlterTableOther", op.Type)
			}
			if op.Keyword != tc.keyword || op.Text != tc.text {
				t.Errorf("Keyword = %q, Text = %q; want %q, %q", op.Keyword, op.Text, tc.keyword, tc.text)
			}
		})
	}
}

func TestAlterTable_ClickHouseMutations(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		typ         ast.AlterTableOpType
		assignments int
		partition   bool
	}{
		{"update", "ALTER TABLE t UPDATE a = 1 WHERE b = 2", ast.UpdateMutation, 1, false},
		{"update several columns", "ALTER TABLE t UPDATE a = 1, b = now() WHERE c < 3", ast.UpdateMutation, 2, false},
		{"update in partition", "ALTER TABLE t UPDATE a = 'x' IN PARTITION '202401' WHERE id = 1", ast.UpdateMutation, 1, true},
		{"update value with IN list", "ALTER TABLE t UPDATE a = if(c IN (1, 2), 1, 0) WHERE id = 1", ast.UpdateMutation, 1, false},
		{"delete", "ALTER TABLE t DELETE WHERE b = 2", ast.DeleteMutation, 0, false},
		{"delete in partition", "ALTER TABLE t DELETE IN PARTITION '202401' WHERE ts < '2024-01-05'", ast.DeleteMutation, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmt, tree := parseAlterTable(t, tc.sql, keywords.DialectClickHouse)
			defer ast.ReleaseAST(tree)
			op := alterOpAt(t, stmt, 0)
			if op.Type != tc.typ {
				t.Fatalf("Type = %v, want %v", op.Type, tc.typ)
			}
			if len(op.Assignments) != tc.assignments {
				t.Errorf("got %d assignments, want %d", len(op.Assignments), tc.assignments)
			}
			if (op.PartitionExpr != nil) != tc.partition {
				t.Errorf("PartitionExpr set = %v, want %v", op.PartitionExpr != nil, tc.partition)
			}
			if op.Where == nil {
				t.Errorf("Where is nil")
			}
		})
	}
}

// TestAlterObjects checks that ALTER <object> statements other than TABLE are
// kept as written in a UtilityStatement of the matching kind.
func TestAlterObjects(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		kind    string
	}{
		{keywords.DialectPostgreSQL, "ALTER INDEX i RENAME TO j", "ALTER INDEX"},
		{keywords.DialectSQLServer, "ALTER INDEX IX_Orders ON dbo.Orders REORGANIZE", "ALTER INDEX"},
		{keywords.DialectSQLServer, "ALTER INDEX ALL ON dbo.Orders REBUILD WITH (ONLINE = ON)", "ALTER INDEX"},
		{keywords.DialectOracle, "ALTER INDEX idx REBUILD", "ALTER INDEX"},
		{keywords.DialectOracle, "ALTER SESSION SET NLS_LANGUAGE = 'AMERICAN' NLS_TERRITORY = 'AMERICA'", "ALTER SESSION"},
		{keywords.DialectSnowflake, "ALTER SESSION SET TIMEZONE = 'UTC'", "ALTER SESSION"},
		{keywords.DialectOracle, "ALTER SYSTEM SET open_cursors = 500 SCOPE = BOTH", "ALTER SYSTEM"},
		{keywords.DialectMySQL, "ALTER USER 'app'@'%' IDENTIFIED BY 'new'", "ALTER USER"},
		{keywords.DialectSnowflake, "ALTER USER jdoe SET DISABLED = TRUE", "ALTER USER"},
		{keywords.DialectMySQL, "ALTER DATABASE app CHARACTER SET utf8mb4", "ALTER DATABASE"},
		{keywords.DialectSQLServer, "ALTER DATABASE CURRENT SET RECOVERY SIMPLE", "ALTER DATABASE"},
		{keywords.DialectSnowflake, "ALTER WAREHOUSE w SUSPEND", "ALTER WAREHOUSE"},
		{keywords.DialectSnowflake, "ALTER TASK refresh_summary RESUME", "ALTER TASK"},
		{keywords.DialectSnowflake, "ALTER ACCOUNT SET TIMEZONE = 'UTC'", "ALTER ACCOUNT"},
		{keywords.DialectOracle, "ALTER SEQUENCE s INCREMENT BY 10", "ALTER SEQUENCE"},
		{keywords.DialectPostgreSQL, "ALTER MATERIALIZED VIEW v RENAME TO w", "ALTER MATERIALIZED"},
		{keywords.DialectPostgreSQL, "ALTER SCHEMA s RENAME TO t", "ALTER SCHEMA"},
		{keywords.DialectPostgreSQL, "ALTER VIEW v OWNER TO bob", "ALTER VIEW"},
		{keywords.DialectPostgreSQL, "ALTER ROLE r WITH LOGIN PASSWORD 'x'", "ALTER ROLE"},
		{keywords.DialectMySQL, "ALTER ROLE r IDENTIFIED BY 'x'", "ALTER ROLE"},
		{keywords.DialectOracle, "ALTER ROLE r NOT IDENTIFIED", "ALTER ROLE"},
	}
	for _, tc := range tests {
		t.Run(string(tc.dialect)+"/"+tc.sql, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatalf("ParseWithDialect(%q): %v", tc.sql, err)
			}
			defer ast.ReleaseAST(tree)
			if len(tree.Statements) != 1 {
				t.Fatalf("got %d statements, want 1", len(tree.Statements))
			}
			u, ok := tree.Statements[0].(*ast.UtilityStatement)
			if !ok {
				t.Fatalf("expected *ast.UtilityStatement, got %T", tree.Statements[0])
			}
			if u.Kind != tc.kind {
				t.Errorf("Kind = %q, want %q", u.Kind, tc.kind)
			}
			if !strings.HasPrefix(strings.ToUpper(u.Text), "ALTER ") {
				t.Errorf("Text = %q, want it to start with ALTER", u.Text)
			}
			if strings.ReplaceAll(u.Text, " ", "") != strings.ReplaceAll(strings.TrimSuffix(tc.sql, ";"), " ", "") {
				t.Errorf("Text = %q, want %q", u.Text, tc.sql)
			}
		})
	}
}

// TestAlterDialectGates checks that dialect-specific actions are refused in
// dialects that do not have them, and accepted when no dialect is set.
func TestAlterDialectGates(t *testing.T) {
	rejected := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectPostgreSQL, "ALTER TABLE t ENGINE=InnoDB"},
		{keywords.DialectPostgreSQL, "ALTER TABLE t MODIFY c INT"},
		{keywords.DialectPostgreSQL, "ALTER TABLE t CHANGE a b INT"},
		{keywords.DialectPostgreSQL, "ALTER TABLE t ADD COLUMN c INT AFTER b"},
		{keywords.DialectPostgreSQL, "ALTER TABLE t UPDATE a = 1 WHERE b = 2"},
		{keywords.DialectSQLServer, "ALTER TABLE t ADD COLUMN IF NOT EXISTS c INT AFTER b"},
		{keywords.DialectSQLite, "ALTER TABLE t ENABLE ROW LEVEL SECURITY"},
		{keywords.DialectMySQL, "ALTER TABLE t OWNER TO bob"},
		{keywords.DialectMySQL, "ALTER TABLE t VALIDATE CONSTRAINT c"},
		{keywords.DialectMySQL, "ALTER SESSION SET x = 1"},
		{keywords.DialectPostgreSQL, "ALTER WAREHOUSE w SUSPEND"},
		{keywords.DialectClickHouse, "ALTER TABLE t SWAP WITH u"},
		{keywords.DialectPostgreSQL, "ALTER TABLE t ADD COLUMN a int GARBAGE here"},
		{keywords.DialectPostgreSQL, "ALTER TABLE t FOO bar"},
		{keywords.DialectPostgreSQL, "ALTER TABLE t"},
		{keywords.DialectPostgreSQL, "ALTER TABLE t ADD COLUMN a int,"},
		{keywords.DialectPostgreSQL, "ALTER INDEX"},
		{keywords.DialectOracle, "ALTER FOO bar"},
	}
	for _, tc := range rejected {
		t.Run("rejected/"+string(tc.dialect)+"/"+tc.sql, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, tc.dialect)
			if err == nil {
				ast.ReleaseAST(tree)
				t.Fatalf("ParseWithDialect(%q, %s) succeeded, want an error", tc.sql, tc.dialect)
			}
		})
	}

	accepted := []string{
		"ALTER TABLE t ENGINE=InnoDB",
		"ALTER TABLE t MODIFY c INT",
		"ALTER TABLE t ADD COLUMN c INT AFTER b",
		"ALTER TABLE t ADD INDEX ix (a)",
		"ALTER TABLE t OWNER TO bob",
		"ALTER SESSION SET x = 1",
	}
	for _, sql := range accepted {
		t.Run("generic/"+sql, func(t *testing.T) {
			tree, err := ParseWithDialect(sql, keywords.DialectGeneric)
			if err != nil {
				t.Fatalf("ParseWithDialect(%q, generic): %v", sql, err)
			}
			ast.ReleaseAST(tree)
		})
	}
}

// TestAlterTable_Prefixes checks that every prefix of every statement the
// tests above use either parses or fails with an error: no panic, no hang.
func TestAlterTable_Prefixes(t *testing.T) {
	stmts := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectPostgreSQL, "ALTER TABLE IF EXISTS ONLY s.t ADD COLUMN IF NOT EXISTS a int NOT NULL DEFAULT 1, ALTER COLUMN b TYPE bigint USING b::bigint, DROP CONSTRAINT IF EXISTS c CASCADE"},
		{keywords.DialectMySQL, "ALTER TABLE t ADD UNIQUE KEY ux (a), MODIFY COLUMN c INT NOT NULL AFTER b, CHANGE a z INT FIRST, DROP FOREIGN KEY fk, ENGINE=InnoDB"},
		{keywords.DialectSQLServer, "ALTER TABLE dbo.t WITH NOCHECK ADD CONSTRAINT uq UNIQUE NONCLUSTERED (a, b)"},
		{keywords.DialectSQLServer, "ALTER TABLE dbo.t ADD a INT NULL, b INT NOT NULL"},
		{keywords.DialectOracle, "ALTER TABLE t ADD (a NUMBER, b VARCHAR2(10)) "},
		{keywords.DialectSnowflake, "ALTER TABLE a.b.c SET DATA_RETENTION_TIME_IN_DAYS = 7, COMMENT = 'x'"},
		{keywords.DialectClickHouse, "ALTER TABLE t ON CLUSTER c UPDATE a = 1, b = 2 IN PARTITION '1' WHERE c = 3"},
		{keywords.DialectClickHouse, "ALTER TABLE t DELETE IN PARTITION '1' WHERE c IN (1, 2)"},
		{keywords.DialectOracle, "ALTER SESSION SET CURRENT_SCHEMA = hr"},
	}
	for _, s := range stmts {
		words := strings.Fields(s.sql)
		for n := 1; n <= len(words); n++ {
			prefix := strings.Join(words[:n], " ")
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("ParseWithDialect(%q, %s) panicked: %v", prefix, s.dialect, r)
					}
				}()
				tree, err := ParseWithDialect(prefix, s.dialect)
				if err == nil {
					ast.ReleaseAST(tree)
				}
			}()
		}
	}
}

// TestAlterPolicy_Table checks that ALTER POLICY keeps the table it is on.
func TestAlterPolicy_Table(t *testing.T) {
	tree, err := ParseWithDialect("ALTER POLICY p ON s.t RENAME TO q", keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("ParseWithDialect: %v", err)
	}
	defer ast.ReleaseAST(tree)
	if len(tree.Statements) != 1 {
		t.Fatalf("got %d statements, want 1", len(tree.Statements))
	}
	stmt, ok := tree.Statements[0].(*ast.AlterStatement)
	if !ok {
		t.Fatalf("expected *ast.AlterStatement, got %T", tree.Statements[0])
	}
	op, ok := stmt.Operation.(*ast.AlterPolicyOperation)
	if !ok {
		t.Fatalf("expected *ast.AlterPolicyOperation, got %T", stmt.Operation)
	}
	if stmt.Name != "p" || op.Table != "s.t" || op.NewName != "q" || op.Type != ast.RenamePolicy {
		t.Errorf("Name=%q Table=%q NewName=%q Type=%v", stmt.Name, op.Table, op.NewName, op.Type)
	}
}

// TestAlterConnector_OwnerWords checks that SET OWNER USER / ROLE are read by
// their words, which the tokenizer does not always give keyword types.
func TestAlterConnector_OwnerWords(t *testing.T) {
	for _, tc := range []struct {
		sql    string
		isUser bool
	}{
		{"ALTER CONNECTOR c SET OWNER USER bob", true},
		{"ALTER CONNECTOR c SET OWNER ROLE admins", false},
	} {
		tree, err := ParseWithDialect(tc.sql, keywords.DialectGeneric)
		if err != nil {
			t.Fatalf("ParseWithDialect(%q): %v", tc.sql, err)
		}
		stmt, ok := tree.Statements[0].(*ast.AlterStatement)
		if !ok {
			ast.ReleaseAST(tree)
			t.Fatalf("expected *ast.AlterStatement, got %T", tree.Statements[0])
		}
		op, ok := stmt.Operation.(*ast.AlterConnectorOperation)
		if !ok || op.Owner == nil {
			ast.ReleaseAST(tree)
			t.Fatalf("expected an owner operation, got %T", stmt.Operation)
		}
		if op.Owner.IsUser != tc.isUser {
			t.Errorf("%q: IsUser = %v, want %v", tc.sql, op.Owner.IsUser, tc.isUser)
		}
		ast.ReleaseAST(tree)
	}
}

// TestAlterTable_NextStatementWithoutSemicolon checks that an ALTER TABLE
// followed by another statement without a ';' (common in T-SQL scripts) is
// two statements, as it was before ALTER TABLE accepted action lists, and
// that trailing junk is still an error.
func TestAlterTable_NextStatementWithoutSemicolon(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    int // statement count; 0 means a parse error
	}{
		{"sqlserver add then update", keywords.DialectSQLServer, "ALTER TABLE t ADD c INT UPDATE t SET c = 1", 2},
		{"sqlserver two alters", keywords.DialectSQLServer, "ALTER TABLE t ADD c INT\nALTER TABLE t ADD d INT", 2},
		{"postgresql drop then select", keywords.DialectPostgreSQL, "ALTER TABLE t DROP COLUMN c SELECT 1", 2},
		{"postgresql rename then select", keywords.DialectPostgreSQL, "ALTER TABLE t RENAME TO u SELECT 1", 2},
		{"trailing junk", keywords.DialectPostgreSQL, "ALTER TABLE t DROP COLUMN c junk", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, tc.dialect)
			if tc.want == 0 {
				if err == nil {
					ast.ReleaseAST(tree)
					t.Fatalf("ParseWithDialect(%q) succeeded, want an error", tc.sql)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseWithDialect(%q): %v", tc.sql, err)
			}
			defer ast.ReleaseAST(tree)
			if got := len(tree.Statements); got != tc.want {
				t.Fatalf("got %d statements, want %d", got, tc.want)
			}
			if _, ok := tree.Statements[0].(*ast.AlterStatement); !ok {
				t.Fatalf("statement 0 is %T, want *ast.AlterStatement", tree.Statements[0])
			}
		})
	}
}
