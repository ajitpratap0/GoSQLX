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

package ast

import (
	"testing"
)

// ============================================================
// CreateTableStatement pool tests
// ============================================================

func TestCreateTableStatementPool(t *testing.T) {
	t.Run("Get returns non-nil", func(t *testing.T) {
		stmt := GetCreateTableStatement()
		if stmt == nil {
			t.Fatal("GetCreateTableStatement() returned nil")
		}
		PutCreateTableStatement(stmt)
	})

	t.Run("Put nil is safe", func(t *testing.T) {
		PutCreateTableStatement(nil) // must not panic
	})

	t.Run("Fields zeroed after Put", func(t *testing.T) {
		stmt := GetCreateTableStatement()
		stmt.Name = "users"
		stmt.IfNotExists = true
		stmt.Temporary = true
		stmt.Columns = append(stmt.Columns, ColumnDef{
			Name: "id",
			Type: "INT",
			Constraints: []ColumnConstraint{
				{
					Type:    "NOT NULL",
					Default: &LiteralValue{Value: "0"},
					Check:   &BinaryExpression{Left: &Identifier{Name: "id"}, Operator: ">", Right: &LiteralValue{Value: "0"}},
				},
			},
		})
		stmt.Constraints = append(stmt.Constraints, TableConstraint{
			Name:  "pk",
			Type:  "PRIMARY KEY",
			Check: &BinaryExpression{Left: &Identifier{Name: "x"}, Operator: "=", Right: &LiteralValue{Value: "1"}},
		})
		stmt.PartitionBy = &PartitionBy{
			Type:    "RANGE",
			Columns: []string{"created_at"},
			Boundary: []Expression{
				&LiteralValue{Value: "2024-01-01"},
			},
		}
		stmt.Partitions = append(stmt.Partitions, PartitionDefinition{
			Name:     "p0",
			LessThan: &LiteralValue{Value: "2024-01-01"},
			From:     &LiteralValue{Value: "2024-01-01"},
			To:       &LiteralValue{Value: "2025-01-01"},
			InValues: []Expression{&LiteralValue{Value: "a"}},
		})
		stmt.Inherits = append(stmt.Inherits, "parent_table")
		stmt.Options = append(stmt.Options, TableOption{Name: "ENGINE", Value: "InnoDB"})

		PutCreateTableStatement(stmt)

		if stmt.Name != "" {
			t.Errorf("Name not cleared, got %q", stmt.Name)
		}
		if stmt.IfNotExists {
			t.Error("IfNotExists not cleared")
		}
		if stmt.Temporary {
			t.Error("Temporary not cleared")
		}
		if len(stmt.Columns) != 0 {
			t.Errorf("Columns not cleared, len=%d", len(stmt.Columns))
		}
		if len(stmt.Constraints) != 0 {
			t.Errorf("Constraints not cleared, len=%d", len(stmt.Constraints))
		}
		if stmt.PartitionBy != nil {
			t.Error("PartitionBy not cleared")
		}
		if len(stmt.Partitions) != 0 {
			t.Errorf("Partitions not cleared, len=%d", len(stmt.Partitions))
		}
		if len(stmt.Inherits) != 0 {
			t.Errorf("Inherits not cleared, len=%d", len(stmt.Inherits))
		}
		if len(stmt.Options) != 0 {
			t.Errorf("Options not cleared, len=%d", len(stmt.Options))
		}
	})

	t.Run("Pool roundtrip reuse", func(t *testing.T) {
		stmt1 := GetCreateTableStatement()
		stmt1.Name = "orders"
		PutCreateTableStatement(stmt1)

		stmt2 := GetCreateTableStatement()
		if stmt2.Name != "" {
			t.Errorf("Reused statement not clean, Name=%q", stmt2.Name)
		}
		PutCreateTableStatement(stmt2)
	})
}

// ============================================================
// AlterTableStatement pool tests
// ============================================================

func TestAlterTableStatementPool(t *testing.T) {
	t.Run("Get returns non-nil", func(t *testing.T) {
		stmt := GetAlterTableStatement()
		if stmt == nil {
			t.Fatal("GetAlterTableStatement() returned nil")
		}
		PutAlterTableStatement(stmt)
	})

	t.Run("Put nil is safe", func(t *testing.T) {
		PutAlterTableStatement(nil)
	})

	t.Run("Fields zeroed after Put", func(t *testing.T) {
		stmt := GetAlterTableStatement()
		stmt.Table = "users"
		stmt.Actions = append(stmt.Actions, AlterTableAction{
			Type:       "ADD COLUMN",
			ColumnName: "email",
			ColumnDef: &ColumnDef{
				Name: "email",
				Type: "VARCHAR(255)",
				Constraints: []ColumnConstraint{
					{
						Type:    "DEFAULT",
						Default: &LiteralValue{Value: "''"},
						Check:   &BinaryExpression{Left: &Identifier{Name: "email"}, Operator: "IS NOT", Right: &LiteralValue{Value: "NULL"}},
					},
				},
			},
			Constraint: &TableConstraint{
				Type:  "UNIQUE",
				Check: &BinaryExpression{Left: &Identifier{Name: "email"}, Operator: "!=", Right: &LiteralValue{Value: "''"}},
			},
		})

		PutAlterTableStatement(stmt)

		if stmt.Table != "" {
			t.Errorf("Table not cleared, got %q", stmt.Table)
		}
		if len(stmt.Actions) != 0 {
			t.Errorf("Actions not cleared, len=%d", len(stmt.Actions))
		}
	})

	t.Run("Pool roundtrip reuse", func(t *testing.T) {
		stmt1 := GetAlterTableStatement()
		stmt1.Table = "products"
		PutAlterTableStatement(stmt1)

		stmt2 := GetAlterTableStatement()
		if stmt2.Table != "" {
			t.Errorf("Reused statement not clean, Table=%q", stmt2.Table)
		}
		PutAlterTableStatement(stmt2)
	})
}

// ============================================================
// CreateIndexStatement pool tests
// ============================================================

func TestCreateIndexStatementPool(t *testing.T) {
	t.Run("Get returns non-nil", func(t *testing.T) {
		stmt := GetCreateIndexStatement()
		if stmt == nil {
			t.Fatal("GetCreateIndexStatement() returned nil")
		}
		PutCreateIndexStatement(stmt)
	})

	t.Run("Put nil is safe", func(t *testing.T) {
		PutCreateIndexStatement(nil)
	})

	t.Run("Fields zeroed after Put", func(t *testing.T) {
		stmt := GetCreateIndexStatement()
		stmt.Name = "idx_users_email"
		stmt.Table = "users"
		stmt.Unique = true
		stmt.IfNotExists = true
		stmt.Using = "BTREE"
		stmt.Columns = append(stmt.Columns, IndexColumn{Column: "email", Direction: "ASC"})
		stmt.Where = &BinaryExpression{
			Left:     &Identifier{Name: "active"},
			Operator: "=",
			Right:    &LiteralValue{Value: "true"},
		}

		PutCreateIndexStatement(stmt)

		if stmt.Name != "" {
			t.Errorf("Name not cleared, got %q", stmt.Name)
		}
		if stmt.Table != "" {
			t.Errorf("Table not cleared, got %q", stmt.Table)
		}
		if stmt.Unique {
			t.Error("Unique not cleared")
		}
		if stmt.IfNotExists {
			t.Error("IfNotExists not cleared")
		}
		if stmt.Using != "" {
			t.Errorf("Using not cleared, got %q", stmt.Using)
		}
		if len(stmt.Columns) != 0 {
			t.Errorf("Columns not cleared, len=%d", len(stmt.Columns))
		}
		if stmt.Where != nil {
			t.Error("Where not cleared")
		}
	})

	t.Run("Pool roundtrip reuse", func(t *testing.T) {
		stmt1 := GetCreateIndexStatement()
		stmt1.Name = "idx_foo"
		PutCreateIndexStatement(stmt1)

		stmt2 := GetCreateIndexStatement()
		if stmt2.Name != "" {
			t.Errorf("Reused statement not clean, Name=%q", stmt2.Name)
		}
		PutCreateIndexStatement(stmt2)
	})
}

// ============================================================
// MergeStatement pool tests
// ============================================================

func TestMergeStatementPool(t *testing.T) {
	t.Run("Get returns non-nil", func(t *testing.T) {
		stmt := GetMergeStatement()
		if stmt == nil {
			t.Fatal("GetMergeStatement() returned nil")
		}
		PutMergeStatement(stmt)
	})

	t.Run("Put nil is safe", func(t *testing.T) {
		PutMergeStatement(nil)
	})

	t.Run("Fields zeroed after Put", func(t *testing.T) {
		stmt := GetMergeStatement()
		stmt.TargetTable = TableReference{Name: "target"}
		stmt.TargetAlias = "t"
		stmt.SourceTable = TableReference{Name: "source"}
		stmt.SourceAlias = "s"
		stmt.OnCondition = &BinaryExpression{
			Left:     &Identifier{Name: "t.id"},
			Operator: "=",
			Right:    &Identifier{Name: "s.id"},
		}
		stmt.WhenClauses = append(stmt.WhenClauses, &MergeWhenClause{
			Type:      "MATCHED",
			Condition: &BinaryExpression{Left: &Identifier{Name: "x"}, Operator: "=", Right: &LiteralValue{Value: "1"}},
			Action: &MergeAction{
				ActionType: "UPDATE",
				SetClauses: []SetClause{
					{Column: "name", Value: &LiteralValue{Value: "new_name"}},
				},
				Values: []Expression{&LiteralValue{Value: "v1"}},
			},
		})
		stmt.Output = append(stmt.Output, &Identifier{Name: "inserted.id"})

		PutMergeStatement(stmt)

		if stmt.TargetAlias != "" {
			t.Errorf("TargetAlias not cleared, got %q", stmt.TargetAlias)
		}
		if stmt.SourceAlias != "" {
			t.Errorf("SourceAlias not cleared, got %q", stmt.SourceAlias)
		}
		if stmt.OnCondition != nil {
			t.Error("OnCondition not cleared")
		}
		if len(stmt.WhenClauses) != 0 {
			t.Errorf("WhenClauses not cleared, len=%d", len(stmt.WhenClauses))
		}
		if len(stmt.Output) != 0 {
			t.Errorf("Output not cleared, len=%d", len(stmt.Output))
		}
		if stmt.TargetTable.Name != "" {
			t.Errorf("TargetTable not cleared, Name=%q", stmt.TargetTable.Name)
		}
		if stmt.SourceTable.Name != "" {
			t.Errorf("SourceTable not cleared, Name=%q", stmt.SourceTable.Name)
		}
	})

	t.Run("Pool roundtrip reuse", func(t *testing.T) {
		stmt1 := GetMergeStatement()
		stmt1.TargetAlias = "t"
		PutMergeStatement(stmt1)

		stmt2 := GetMergeStatement()
		if stmt2.TargetAlias != "" {
			t.Errorf("Reused statement not clean, TargetAlias=%q", stmt2.TargetAlias)
		}
		PutMergeStatement(stmt2)
	})
}

// ============================================================
// CreateViewStatement pool tests
// ============================================================

func TestCreateViewStatementPool(t *testing.T) {
	t.Run("Get returns non-nil", func(t *testing.T) {
		stmt := GetCreateViewStatement()
		if stmt == nil {
			t.Fatal("GetCreateViewStatement() returned nil")
		}
		PutCreateViewStatement(stmt)
	})

	t.Run("Put nil is safe", func(t *testing.T) {
		PutCreateViewStatement(nil)
	})

	t.Run("Fields zeroed after Put", func(t *testing.T) {
		inner := GetSelectStatement()
		inner.TableName = "users"

		stmt := GetCreateViewStatement()
		stmt.Name = "active_users"
		stmt.OrReplace = true
		stmt.Temporary = true
		stmt.IfNotExists = true
		stmt.Columns = append(stmt.Columns, "id", "name")
		stmt.Query = inner
		stmt.WithOption = "CASCADED"

		PutCreateViewStatement(stmt)

		if stmt.Name != "" {
			t.Errorf("Name not cleared, got %q", stmt.Name)
		}
		if stmt.OrReplace {
			t.Error("OrReplace not cleared")
		}
		if stmt.Temporary {
			t.Error("Temporary not cleared")
		}
		if stmt.IfNotExists {
			t.Error("IfNotExists not cleared")
		}
		if len(stmt.Columns) != 0 {
			t.Errorf("Columns not cleared, len=%d", len(stmt.Columns))
		}
		if stmt.Query != nil {
			t.Error("Query not cleared")
		}
		if stmt.WithOption != "" {
			t.Errorf("WithOption not cleared, got %q", stmt.WithOption)
		}
	})

	t.Run("Pool roundtrip reuse", func(t *testing.T) {
		stmt1 := GetCreateViewStatement()
		stmt1.Name = "my_view"
		PutCreateViewStatement(stmt1)

		stmt2 := GetCreateViewStatement()
		if stmt2.Name != "" {
			t.Errorf("Reused statement not clean, Name=%q", stmt2.Name)
		}
		PutCreateViewStatement(stmt2)
	})
}

// ============================================================
// CreateMaterializedViewStatement pool tests
// ============================================================

func TestCreateMaterializedViewStatementPool(t *testing.T) {
	t.Run("Get returns non-nil", func(t *testing.T) {
		stmt := GetCreateMaterializedViewStatement()
		if stmt == nil {
			t.Fatal("GetCreateMaterializedViewStatement() returned nil")
		}
		PutCreateMaterializedViewStatement(stmt)
	})

	t.Run("Put nil is safe", func(t *testing.T) {
		PutCreateMaterializedViewStatement(nil)
	})

	t.Run("Fields zeroed after Put", func(t *testing.T) {
		withData := true
		inner := GetSelectStatement()
		inner.TableName = "events"

		stmt := GetCreateMaterializedViewStatement()
		stmt.Name = "mv_events"
		stmt.IfNotExists = true
		stmt.Columns = append(stmt.Columns, "id", "ts")
		stmt.Query = inner
		stmt.WithData = &withData
		stmt.Tablespace = "pg_default"

		PutCreateMaterializedViewStatement(stmt)

		if stmt.Name != "" {
			t.Errorf("Name not cleared, got %q", stmt.Name)
		}
		if stmt.IfNotExists {
			t.Error("IfNotExists not cleared")
		}
		if len(stmt.Columns) != 0 {
			t.Errorf("Columns not cleared, len=%d", len(stmt.Columns))
		}
		if stmt.Query != nil {
			t.Error("Query not cleared")
		}
		if stmt.WithData != nil {
			t.Error("WithData not cleared")
		}
		if stmt.Tablespace != "" {
			t.Errorf("Tablespace not cleared, got %q", stmt.Tablespace)
		}
	})

	t.Run("Pool roundtrip reuse", func(t *testing.T) {
		stmt1 := GetCreateMaterializedViewStatement()
		stmt1.Name = "my_mv"
		PutCreateMaterializedViewStatement(stmt1)

		stmt2 := GetCreateMaterializedViewStatement()
		if stmt2.Name != "" {
			t.Errorf("Reused statement not clean, Name=%q", stmt2.Name)
		}
		PutCreateMaterializedViewStatement(stmt2)
	})
}

// ============================================================
// RefreshMaterializedViewStatement pool tests
// ============================================================

func TestRefreshMaterializedViewStatementPool(t *testing.T) {
	t.Run("Get returns non-nil", func(t *testing.T) {
		stmt := GetRefreshMaterializedViewStatement()
		if stmt == nil {
			t.Fatal("GetRefreshMaterializedViewStatement() returned nil")
		}
		PutRefreshMaterializedViewStatement(stmt)
	})

	t.Run("Put nil is safe", func(t *testing.T) {
		PutRefreshMaterializedViewStatement(nil)
	})

	t.Run("Fields zeroed after Put", func(t *testing.T) {
		withData := true

		stmt := GetRefreshMaterializedViewStatement()
		stmt.Name = "mv_events"
		stmt.Concurrently = true
		stmt.WithData = &withData

		PutRefreshMaterializedViewStatement(stmt)

		if stmt.Name != "" {
			t.Errorf("Name not cleared, got %q", stmt.Name)
		}
		if stmt.Concurrently {
			t.Error("Concurrently not cleared")
		}
		if stmt.WithData != nil {
			t.Error("WithData not cleared")
		}
	})

	t.Run("Pool roundtrip reuse", func(t *testing.T) {
		stmt1 := GetRefreshMaterializedViewStatement()
		stmt1.Name = "my_mv"
		PutRefreshMaterializedViewStatement(stmt1)

		stmt2 := GetRefreshMaterializedViewStatement()
		if stmt2.Name != "" {
			t.Errorf("Reused statement not clean, Name=%q", stmt2.Name)
		}
		PutRefreshMaterializedViewStatement(stmt2)
	})
}

// ============================================================
// DropStatement pool tests
// ============================================================

func TestDropStatementPool(t *testing.T) {
	t.Run("Get returns non-nil", func(t *testing.T) {
		stmt := GetDropStatement()
		if stmt == nil {
			t.Fatal("GetDropStatement() returned nil")
		}
		PutDropStatement(stmt)
	})

	t.Run("Put nil is safe", func(t *testing.T) {
		PutDropStatement(nil)
	})

	t.Run("Fields zeroed after Put", func(t *testing.T) {
		stmt := GetDropStatement()
		stmt.ObjectType = "TABLE"
		stmt.IfExists = true
		stmt.Names = append(stmt.Names, "users", "orders")
		stmt.CascadeType = "CASCADE"

		PutDropStatement(stmt)

		if stmt.ObjectType != "" {
			t.Errorf("ObjectType not cleared, got %q", stmt.ObjectType)
		}
		if stmt.IfExists {
			t.Error("IfExists not cleared")
		}
		if len(stmt.Names) != 0 {
			t.Errorf("Names not cleared, len=%d", len(stmt.Names))
		}
		if stmt.CascadeType != "" {
			t.Errorf("CascadeType not cleared, got %q", stmt.CascadeType)
		}
	})

	t.Run("Pool roundtrip reuse", func(t *testing.T) {
		stmt1 := GetDropStatement()
		stmt1.ObjectType = "VIEW"
		PutDropStatement(stmt1)

		stmt2 := GetDropStatement()
		if stmt2.ObjectType != "" {
			t.Errorf("Reused statement not clean, ObjectType=%q", stmt2.ObjectType)
		}
		PutDropStatement(stmt2)
	})
}

// ============================================================
// TruncateStatement pool tests
// ============================================================

func TestTruncateStatementPool(t *testing.T) {
	t.Run("Get returns non-nil", func(t *testing.T) {
		stmt := GetTruncateStatement()
		if stmt == nil {
			t.Fatal("GetTruncateStatement() returned nil")
		}
		PutTruncateStatement(stmt)
	})

	t.Run("Put nil is safe", func(t *testing.T) {
		PutTruncateStatement(nil)
	})

	t.Run("Fields zeroed after Put", func(t *testing.T) {
		stmt := GetTruncateStatement()
		stmt.Tables = append(stmt.Tables, "orders", "line_items")
		stmt.RestartIdentity = true
		stmt.ContinueIdentity = true
		stmt.CascadeType = "RESTRICT"

		PutTruncateStatement(stmt)

		if len(stmt.Tables) != 0 {
			t.Errorf("Tables not cleared, len=%d", len(stmt.Tables))
		}
		if stmt.RestartIdentity {
			t.Error("RestartIdentity not cleared")
		}
		if stmt.ContinueIdentity {
			t.Error("ContinueIdentity not cleared")
		}
		if stmt.CascadeType != "" {
			t.Errorf("CascadeType not cleared, got %q", stmt.CascadeType)
		}
	})

	t.Run("Pool roundtrip reuse", func(t *testing.T) {
		stmt1 := GetTruncateStatement()
		stmt1.Tables = append(stmt1.Tables, "logs")
		PutTruncateStatement(stmt1)

		stmt2 := GetTruncateStatement()
		if len(stmt2.Tables) != 0 {
			t.Errorf("Reused statement not clean, Tables len=%d", len(stmt2.Tables))
		}
		PutTruncateStatement(stmt2)
	})
}

// ============================================================
// ShowStatement pool tests
// ============================================================

func TestShowStatementPool(t *testing.T) {
	t.Run("Get returns non-nil", func(t *testing.T) {
		stmt := GetShowStatement()
		if stmt == nil {
			t.Fatal("GetShowStatement() returned nil")
		}
		PutShowStatement(stmt)
	})

	t.Run("Put nil is safe", func(t *testing.T) {
		PutShowStatement(nil)
	})

	t.Run("Fields zeroed after Put", func(t *testing.T) {
		stmt := GetShowStatement()
		stmt.ShowType = "TABLES"
		stmt.ObjectName = "users"
		stmt.From = "mydb"

		PutShowStatement(stmt)

		if stmt.ShowType != "" {
			t.Errorf("ShowType not cleared, got %q", stmt.ShowType)
		}
		if stmt.ObjectName != "" {
			t.Errorf("ObjectName not cleared, got %q", stmt.ObjectName)
		}
		if stmt.From != "" {
			t.Errorf("From not cleared, got %q", stmt.From)
		}
	})

	t.Run("Pool roundtrip reuse", func(t *testing.T) {
		stmt1 := GetShowStatement()
		stmt1.ShowType = "DATABASES"
		PutShowStatement(stmt1)

		stmt2 := GetShowStatement()
		if stmt2.ShowType != "" {
			t.Errorf("Reused statement not clean, ShowType=%q", stmt2.ShowType)
		}
		PutShowStatement(stmt2)
	})
}

// ============================================================
// DescribeStatement pool tests
// ============================================================

func TestDescribeStatementPool(t *testing.T) {
	t.Run("Get returns non-nil", func(t *testing.T) {
		stmt := GetDescribeStatement()
		if stmt == nil {
			t.Fatal("GetDescribeStatement() returned nil")
		}
		PutDescribeStatement(stmt)
	})

	t.Run("Put nil is safe", func(t *testing.T) {
		PutDescribeStatement(nil)
	})

	t.Run("Fields zeroed after Put", func(t *testing.T) {
		stmt := GetDescribeStatement()
		stmt.TableName = "orders"

		PutDescribeStatement(stmt)

		if stmt.TableName != "" {
			t.Errorf("TableName not cleared, got %q", stmt.TableName)
		}
	})

	t.Run("Pool roundtrip reuse", func(t *testing.T) {
		stmt1 := GetDescribeStatement()
		stmt1.TableName = "products"
		PutDescribeStatement(stmt1)

		stmt2 := GetDescribeStatement()
		if stmt2.TableName != "" {
			t.Errorf("Reused statement not clean, TableName=%q", stmt2.TableName)
		}
		PutDescribeStatement(stmt2)
	})
}

// ============================================================
// ReplaceStatement pool tests
// ============================================================

func TestReplaceStatementPool(t *testing.T) {
	t.Run("Get returns non-nil", func(t *testing.T) {
		stmt := GetReplaceStatement()
		if stmt == nil {
			t.Fatal("GetReplaceStatement() returned nil")
		}
		PutReplaceStatement(stmt)
	})

	t.Run("Put nil is safe", func(t *testing.T) {
		PutReplaceStatement(nil)
	})

	t.Run("Fields zeroed after Put", func(t *testing.T) {
		stmt := GetReplaceStatement()
		stmt.TableName = "users"
		stmt.Columns = append(stmt.Columns,
			&Identifier{Name: "id"},
			&Identifier{Name: "name"},
		)
		stmt.Values = append(stmt.Values, []Expression{
			&LiteralValue{Value: "1"},
			&LiteralValue{Value: "Alice"},
		})

		PutReplaceStatement(stmt)

		if stmt.TableName != "" {
			t.Errorf("TableName not cleared, got %q", stmt.TableName)
		}
		if len(stmt.Columns) != 0 {
			t.Errorf("Columns not cleared, len=%d", len(stmt.Columns))
		}
		if len(stmt.Values) != 0 {
			t.Errorf("Values not cleared, len=%d", len(stmt.Values))
		}
	})

	t.Run("Pool roundtrip reuse", func(t *testing.T) {
		stmt1 := GetReplaceStatement()
		stmt1.TableName = "cache"
		PutReplaceStatement(stmt1)

		stmt2 := GetReplaceStatement()
		if stmt2.TableName != "" {
			t.Errorf("Reused statement not clean, TableName=%q", stmt2.TableName)
		}
		PutReplaceStatement(stmt2)
	})
}

// ============================================================
// AlterStatement pool tests
// ============================================================

func TestAlterStatementPool(t *testing.T) {
	t.Run("Get returns non-nil", func(t *testing.T) {
		stmt := GetAlterStatement()
		if stmt == nil {
			t.Fatal("GetAlterStatement() returned nil")
		}
		PutAlterStatement(stmt)
	})

	t.Run("Put nil is safe", func(t *testing.T) {
		PutAlterStatement(nil)
	})

	t.Run("Fields zeroed after Put", func(t *testing.T) {
		stmt := GetAlterStatement()
		stmt.Type = AlterTypeTable
		stmt.Name = "users"
		stmt.Operation = &AlterTableOperation{
			Type:       AddColumn,
			ColumnName: &Ident{Name: "age"},
		}

		PutAlterStatement(stmt)

		if stmt.Type != 0 {
			t.Errorf("Type not cleared, got %v", stmt.Type)
		}
		if stmt.Name != "" {
			t.Errorf("Name not cleared, got %q", stmt.Name)
		}
		if stmt.Operation != nil {
			t.Error("Operation not cleared")
		}
	})

	t.Run("Pool roundtrip reuse", func(t *testing.T) {
		stmt1 := GetAlterStatement()
		stmt1.Name = "orders"
		PutAlterStatement(stmt1)

		stmt2 := GetAlterStatement()
		if stmt2.Name != "" {
			t.Errorf("Reused statement not clean, Name=%q", stmt2.Name)
		}
		PutAlterStatement(stmt2)
	})
}

// ============================================================
// ReleaseAST mixed DML + DDL test
// ============================================================

func TestReleaseASTMixedDMLAndDDL(t *testing.T) {
	t.Run("Mixed DML and DDL statements", func(t *testing.T) {
		a := NewAST()

		// DML statements
		sel := GetSelectStatement()
		sel.TableName = "users"
		a.Statements = append(a.Statements, sel)

		ins := GetInsertStatement()
		ins.TableName = "orders"
		a.Statements = append(a.Statements, ins)

		upd := GetUpdateStatement()
		upd.TableName = "products"
		a.Statements = append(a.Statements, upd)

		del := GetDeleteStatement()
		del.TableName = "temp"
		a.Statements = append(a.Statements, del)

		// DDL statements
		ct := GetCreateTableStatement()
		ct.Name = "new_table"
		a.Statements = append(a.Statements, ct)

		at := GetAlterTableStatement()
		at.Table = "old_table"
		a.Statements = append(a.Statements, at)

		ci := GetCreateIndexStatement()
		ci.Name = "idx_foo"
		a.Statements = append(a.Statements, ci)

		merge := GetMergeStatement()
		merge.TargetAlias = "t"
		a.Statements = append(a.Statements, merge)

		cv := GetCreateViewStatement()
		cv.Name = "v_active"
		a.Statements = append(a.Statements, cv)

		cmv := GetCreateMaterializedViewStatement()
		cmv.Name = "mv_stats"
		a.Statements = append(a.Statements, cmv)

		rmv := GetRefreshMaterializedViewStatement()
		rmv.Name = "mv_stats"
		a.Statements = append(a.Statements, rmv)

		drop := GetDropStatement()
		drop.ObjectType = "TABLE"
		a.Statements = append(a.Statements, drop)

		trunc := GetTruncateStatement()
		trunc.Tables = append(trunc.Tables, "logs")
		a.Statements = append(a.Statements, trunc)

		show := GetShowStatement()
		show.ShowType = "TABLES"
		a.Statements = append(a.Statements, show)

		desc := GetDescribeStatement()
		desc.TableName = "users"
		a.Statements = append(a.Statements, desc)

		repl := GetReplaceStatement()
		repl.TableName = "cache"
		a.Statements = append(a.Statements, repl)

		alt := GetAlterStatement()
		alt.Name = "my_role"
		a.Statements = append(a.Statements, alt)

		// Release everything — must not panic and must clean up
		ReleaseAST(a)

		if len(a.Statements) != 0 {
			t.Errorf("Statements not cleared after ReleaseAST, len=%d", len(a.Statements))
		}
	})
}

// ============================================================
// ReleaseStatements mixed DDL test
// ============================================================

func TestReleaseStatementsMixedDDL(t *testing.T) {
	stmts := []Statement{
		&CreateTableStatement{Name: "t1"},
		&AlterTableStatement{Table: "t2"},
		&CreateIndexStatement{Name: "idx"},
		&MergeStatement{TargetAlias: "tgt"},
		&CreateViewStatement{Name: "v1"},
		&CreateMaterializedViewStatement{Name: "mv1"},
		&RefreshMaterializedViewStatement{Name: "mv1"},
		&DropStatement{ObjectType: "TABLE"},
		&TruncateStatement{Tables: []string{"t1"}},
		&ShowStatement{ShowType: "TABLES"},
		&DescribeStatement{TableName: "users"},
		&ReplaceStatement{TableName: "cache"},
		&AlterStatement{Name: "r1"},
		// DML
		&SelectStatement{TableName: "users"},
		&InsertStatement{TableName: "orders"},
	}

	// Should not panic
	ReleaseStatements(stmts)

	for i, s := range stmts {
		if s != nil {
			t.Errorf("stmts[%d] not cleared after ReleaseStatements", i)
		}
	}
}

// ============================================================
// Benchmarks
// ============================================================

func BenchmarkCreateTableStatementPool(b *testing.B) {
	b.Run("GetPutCreateTableStatement", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			stmt := GetCreateTableStatement()
			stmt.Name = "users"
			stmt.IfNotExists = true
			stmt.Columns = append(stmt.Columns, ColumnDef{
				Name: "id",
				Type: "BIGINT",
				Constraints: []ColumnConstraint{
					{Type: "NOT NULL", Default: &LiteralValue{Value: "0"}},
				},
			})
			PutCreateTableStatement(stmt)
		}
	})

	b.Run("AllocCreateTableStatement", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			stmt := &CreateTableStatement{
				Name:        "users",
				IfNotExists: true,
				Columns: []ColumnDef{
					{
						Name: "id",
						Type: "BIGINT",
						Constraints: []ColumnConstraint{
							{Type: "NOT NULL", Default: &LiteralValue{Value: "0"}},
						},
					},
				},
			}
			_ = stmt
		}
	})
}

func BenchmarkAlterTableStatementPool(b *testing.B) {
	b.Run("GetPutAlterTableStatement", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			stmt := GetAlterTableStatement()
			stmt.Table = "users"
			stmt.Actions = append(stmt.Actions, AlterTableAction{
				Type:       "ADD COLUMN",
				ColumnName: "email",
			})
			PutAlterTableStatement(stmt)
		}
	})
}

func BenchmarkCreateIndexStatementPool(b *testing.B) {
	b.Run("GetPutCreateIndexStatement", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			stmt := GetCreateIndexStatement()
			stmt.Name = "idx_email"
			stmt.Table = "users"
			stmt.Unique = true
			stmt.Columns = append(stmt.Columns, IndexColumn{Column: "email", Direction: "ASC"})
			stmt.Where = &BinaryExpression{
				Left:     &Identifier{Name: "active"},
				Operator: "=",
				Right:    &LiteralValue{Value: "true"},
			}
			PutCreateIndexStatement(stmt)
		}
	})
}

func BenchmarkDropStatementPool(b *testing.B) {
	b.Run("GetPutDropStatement", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			stmt := GetDropStatement()
			stmt.ObjectType = "TABLE"
			stmt.IfExists = true
			stmt.Names = append(stmt.Names, "users")
			PutDropStatement(stmt)
		}
	})
}

func BenchmarkTruncateStatementPool(b *testing.B) {
	b.Run("GetPutTruncateStatement", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			stmt := GetTruncateStatement()
			stmt.Tables = append(stmt.Tables, "logs", "events")
			stmt.RestartIdentity = true
			PutTruncateStatement(stmt)
		}
	})
}

func BenchmarkReplaceStatementPool(b *testing.B) {
	b.Run("GetPutReplaceStatement", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			stmt := GetReplaceStatement()
			stmt.TableName = "cache"
			stmt.Columns = append(stmt.Columns, &Identifier{Name: "key"}, &Identifier{Name: "value"})
			stmt.Values = append(stmt.Values, []Expression{
				&LiteralValue{Value: "k1"},
				&LiteralValue{Value: "v1"},
			})
			PutReplaceStatement(stmt)
		}
	})
}

func BenchmarkMixedDDLReleaseAST(b *testing.B) {
	b.Run("ReleaseAST_AllDDLTypes", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			a := NewAST()
			a.Statements = append(a.Statements,
				GetCreateTableStatement(),
				GetAlterTableStatement(),
				GetCreateIndexStatement(),
				GetMergeStatement(),
				GetCreateViewStatement(),
				GetCreateMaterializedViewStatement(),
				GetRefreshMaterializedViewStatement(),
				GetDropStatement(),
				GetTruncateStatement(),
				GetShowStatement(),
				GetDescribeStatement(),
				GetReplaceStatement(),
				GetAlterStatement(),
			)
			ReleaseAST(a)
		}
	})
}
