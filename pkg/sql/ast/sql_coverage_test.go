package ast

import (
	"strings"
	"testing"
)

func covIntPtr(v int) *int       { return &v }
func covBoolPtr(v bool) *bool    { return &v }
func covStrPtr(v string) *string { return &v }

func TestCreateIndexStatement_SQL(t *testing.T) {
	stmt := &CreateIndexStatement{
		Name:        "idx_users_email",
		Table:       "users",
		Unique:      true,
		IfNotExists: true,
		Using:       "btree",
		Columns:     []IndexColumn{{Column: "email", Direction: "ASC"}, {Column: "name"}},
		Where:       &BinaryExpression{Left: &Identifier{Name: "active"}, Operator: "=", Right: &LiteralValue{Value: "true"}},
	}
	sql := stmt.SQL()
	for _, want := range []string{"CREATE UNIQUE INDEX", "IF NOT EXISTS", "idx_users_email", "ON users", "USING btree", "email ASC", "WHERE"} {
		if !strings.Contains(sql, want) {
			t.Errorf("SQL() missing %q, got: %s", want, sql)
		}
	}
}

func TestAlterTableStatement_SQL(t *testing.T) {
	stmt := &AlterTableStatement{
		Table: "users",
		Actions: []AlterTableAction{
			{Type: "ADD COLUMN", ColumnDef: &ColumnDef{Name: "email", Type: "TEXT"}},
			{Type: "DROP COLUMN", ColumnName: "old_col"},
			{Type: "ADD CONSTRAINT", Constraint: &TableConstraint{Type: "UNIQUE", Columns: []string{"email"}}},
			{Type: "RENAME TO new_table"},
		},
	}
	sql := stmt.SQL()
	for _, want := range []string{"ALTER TABLE users", "ADD COLUMN email TEXT", "DROP COLUMN old_col"} {
		if !strings.Contains(sql, want) {
			t.Errorf("SQL() missing %q, got: %s", want, sql)
		}
	}
}

func TestDropStatement_SQL(t *testing.T) {
	stmt := &DropStatement{
		ObjectType:  "TABLE",
		IfExists:    true,
		Names:       []string{"users", "orders"},
		CascadeType: "CASCADE",
	}
	sql := stmt.SQL()
	for _, want := range []string{"DROP TABLE", "IF EXISTS", "users, orders", "CASCADE"} {
		if !strings.Contains(sql, want) {
			t.Errorf("SQL() missing %q, got: %s", want, sql)
		}
	}
}

func TestTruncateStatement_SQL(t *testing.T) {
	stmt := &TruncateStatement{Tables: []string{"users"}, RestartIdentity: true, CascadeType: "CASCADE"}
	sql := stmt.SQL()
	if !strings.Contains(sql, "TRUNCATE TABLE users") || !strings.Contains(sql, "RESTART IDENTITY") {
		t.Errorf("got: %s", sql)
	}

	stmt2 := &TruncateStatement{Tables: []string{"t"}, ContinueIdentity: true}
	sql2 := stmt2.SQL()
	if !strings.Contains(sql2, "CONTINUE IDENTITY") {
		t.Errorf("got: %s", sql2)
	}
}

func TestWithClause_SQL(t *testing.T) {
	w := &WithClause{
		Recursive: true,
		CTEs: []*CommonTableExpr{
			{
				Name:      "cte1",
				Columns:   []string{"a", "b"},
				Statement: &SelectStatement{Columns: []Expression{&Identifier{Name: "x"}}, From: []TableReference{{Name: "t"}}},
			},
		},
	}
	sql := w.SQL()
	for _, want := range []string{"WITH RECURSIVE", "cte1 (a, b) AS"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in: %s", want, sql)
		}
	}
}

func TestSetOperation_SQL(t *testing.T) {
	s := &SetOperation{
		Left:     &SelectStatement{Columns: []Expression{&Identifier{Name: "a"}}, From: []TableReference{{Name: "t1"}}},
		Right:    &SelectStatement{Columns: []Expression{&Identifier{Name: "b"}}, From: []TableReference{{Name: "t2"}}},
		Operator: "UNION",
		All:      true,
	}
	sql := s.SQL()
	if !strings.Contains(sql, "UNION ALL") {
		t.Errorf("missing UNION ALL in: %s", sql)
	}
}

func TestValues_SQL(t *testing.T) {
	v := &Values{
		Rows: [][]Expression{
			{&LiteralValue{Value: "1"}, &LiteralValue{Value: "'a'"}},
			{&LiteralValue{Value: "2"}, &LiteralValue{Value: "'b'"}},
		},
	}
	sql := v.SQL()
	if !strings.Contains(sql, "VALUES") {
		t.Errorf("got: %s", sql)
	}
}

func TestCreateViewStatement_SQL(t *testing.T) {
	stmt := &CreateViewStatement{
		Name:        "v1",
		OrReplace:   true,
		Temporary:   true,
		IfNotExists: true,
		Columns:     []string{"a", "b"},
		Query:       &SelectStatement{Columns: []Expression{&Identifier{Name: "x"}}},
		WithOption:  "CHECK OPTION",
	}
	sql := stmt.SQL()
	for _, want := range []string{"CREATE OR REPLACE TEMPORARY VIEW", "IF NOT EXISTS", "v1 (a, b) AS", "CHECK OPTION"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in: %s", want, sql)
		}
	}
}

func TestCreateMaterializedViewStatement_SQL(t *testing.T) {
	stmt := &CreateMaterializedViewStatement{
		Name:        "mv1",
		IfNotExists: true,
		Columns:     []string{"x"},
		Query:       &SelectStatement{Columns: []Expression{&Identifier{Name: "a"}}},
		WithData:    covBoolPtr(true),
	}
	sql := stmt.SQL()
	if !strings.Contains(sql, "CREATE MATERIALIZED VIEW") || !strings.Contains(sql, "WITH DATA") {
		t.Errorf("got: %s", sql)
	}

	stmt2 := &CreateMaterializedViewStatement{Name: "mv2", Query: &SelectStatement{Columns: []Expression{&Identifier{Name: "a"}}}, WithData: covBoolPtr(false)}
	if !strings.Contains(stmt2.SQL(), "WITH NO DATA") {
		t.Error("should have WITH NO DATA")
	}
}

func TestRefreshMaterializedViewStatement_SQL(t *testing.T) {
	stmt := &RefreshMaterializedViewStatement{Name: "mv1", Concurrently: true, WithData: covBoolPtr(false)}
	sql := stmt.SQL()
	if !strings.Contains(sql, "REFRESH MATERIALIZED VIEW CONCURRENTLY mv1 WITH NO DATA") {
		t.Errorf("got: %s", sql)
	}
}

func TestMergeStatement_SQL(t *testing.T) {
	stmt := &MergeStatement{
		TargetTable: TableReference{Name: "target"},
		TargetAlias: "t",
		SourceTable: TableReference{Name: "source"},
		SourceAlias: "s",
		OnCondition: &BinaryExpression{Left: &Identifier{Name: "t.id"}, Operator: "=", Right: &Identifier{Name: "s.id"}},
		WhenClauses: []*MergeWhenClause{
			{Type: "MATCHED", Action: &MergeAction{ActionType: "UPDATE", SetClauses: []SetClause{{Column: "name", Value: &Identifier{Name: "s.name"}}}}},
			{Type: "NOT_MATCHED", Action: &MergeAction{ActionType: "INSERT", Columns: []string{"id"}, Values: []Expression{&Identifier{Name: "s.id"}}}},
			{Type: "NOT_MATCHED_BY_SOURCE", Action: &MergeAction{ActionType: "DELETE"}},
			{Type: "MATCHED", Condition: &Identifier{Name: "s.active"}, Action: &MergeAction{ActionType: "UPDATE", SetClauses: []SetClause{{Column: "x", Value: &LiteralValue{Value: "1"}}}}},
		},
	}
	sql := stmt.SQL()
	for _, want := range []string{"MERGE INTO", "USING", "ON", "WHEN MATCHED", "WHEN NOT MATCHED", "NOT MATCHED BY SOURCE", "THEN DELETE"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in: %s", want, sql)
		}
	}
}

func TestMergeAction_InsertDefaultValues(t *testing.T) {
	stmt := &MergeStatement{
		TargetTable: TableReference{Name: "t"},
		SourceTable: TableReference{Name: "s"},
		OnCondition: &Identifier{Name: "true"},
		WhenClauses: []*MergeWhenClause{
			{Type: "NOT_MATCHED", Action: &MergeAction{ActionType: "INSERT", DefaultValues: true}},
		},
	}
	sql := stmt.SQL()
	if !strings.Contains(sql, "INSERT DEFAULT VALUES") {
		t.Errorf("got: %s", sql)
	}
}

func TestSelect_SQL(t *testing.T) {
	lim := int64(10)
	off := int64(5)
	s := &Select{
		Distinct: true,
		Columns:  []Expression{&Identifier{Name: "a"}},
		From:     []TableReference{{Name: "t"}},
		Where:    &Identifier{Name: "true"},
		GroupBy:  []Expression{&Identifier{Name: "a"}},
		Having:   &Identifier{Name: "count(*) > 1"},
		OrderBy:  []OrderByExpression{{Expression: &Identifier{Name: "a"}, Ascending: true}},
		Limit:    &lim,
		Offset:   &off,
	}
	sql := s.SQL()
	for _, want := range []string{"SELECT DISTINCT", "FROM t", "WHERE", "GROUP BY", "HAVING", "ORDER BY", "LIMIT 10", "OFFSET 5"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in: %s", want, sql)
		}
	}
}

func TestInsert_SQL(t *testing.T) {
	i := &Insert{
		Table:           TableReference{Name: "t"},
		Columns:         []Expression{&Identifier{Name: "a"}},
		Values:          [][]Expression{{&LiteralValue{Value: "1"}}},
		ReturningClause: []Expression{&Identifier{Name: "id"}},
	}
	sql := i.SQL()
	if !strings.Contains(sql, "RETURNING id") {
		t.Errorf("got: %s", sql)
	}
}

func TestUpdate_SQL(t *testing.T) {
	u := &Update{
		Table:           TableReference{Name: "t"},
		Updates:         []UpdateExpression{{Column: &Identifier{Name: "x"}, Value: &LiteralValue{Value: "1"}}},
		Where:           &Identifier{Name: "true"},
		ReturningClause: []Expression{&Identifier{Name: "id"}},
	}
	sql := u.SQL()
	if !strings.Contains(sql, "RETURNING id") {
		t.Errorf("got: %s", sql)
	}
}

func TestDelete_SQL(t *testing.T) {
	d := &Delete{
		Table:           TableReference{Name: "t"},
		Where:           &Identifier{Name: "true"},
		ReturningClause: []Expression{&Identifier{Name: "id"}},
	}
	sql := d.SQL()
	if !strings.Contains(sql, "RETURNING id") {
		t.Errorf("got: %s", sql)
	}
}

func TestExtractExpression_SQL(t *testing.T) {
	e := &ExtractExpression{Field: "YEAR", Source: &Identifier{Name: "created_at"}}
	if !strings.Contains(e.SQL(), "EXTRACT(YEAR FROM created_at)") {
		t.Errorf("got: %s", e.SQL())
	}
}

func TestPositionExpression_SQL(t *testing.T) {
	p := &PositionExpression{Substr: &LiteralValue{Value: "'x'"}, Str: &Identifier{Name: "name"}}
	if !strings.Contains(p.SQL(), "POSITION") {
		t.Errorf("got: %s", p.SQL())
	}
}

func TestSubstringExpression_SQL(t *testing.T) {
	s := &SubstringExpression{Str: &Identifier{Name: "name"}, Start: &LiteralValue{Value: "1"}, Length: &LiteralValue{Value: "3"}}
	sql := s.SQL()
	if !strings.Contains(sql, "SUBSTRING") || !strings.Contains(sql, "FOR") {
		t.Errorf("got: %s", sql)
	}
	// Without length
	s2 := &SubstringExpression{Str: &Identifier{Name: "name"}, Start: &LiteralValue{Value: "1"}}
	if strings.Contains(s2.SQL(), "FOR") {
		t.Errorf("should not have FOR without length")
	}
}

func TestIntervalExpression_SQL(t *testing.T) {
	i := &IntervalExpression{Value: "1 day"}
	if i.SQL() != "INTERVAL '1 day'" {
		t.Errorf("got: %s", i.SQL())
	}
}

func TestTupleExpression_SQL(t *testing.T) {
	te := &TupleExpression{Expressions: []Expression{&LiteralValue{Value: "1"}, &LiteralValue{Value: "2"}}}
	if te.SQL() != "(1, 2)" {
		t.Errorf("got: %s", te.SQL())
	}
}

func TestArrayConstructorExpression_SQL(t *testing.T) {
	// With elements
	a := &ArrayConstructorExpression{Elements: []Expression{&LiteralValue{Value: "1"}, &LiteralValue{Value: "2"}}}
	if a.SQL() != "ARRAY[1, 2]" {
		t.Errorf("got: %s", a.SQL())
	}
	// With subquery
	a2 := &ArrayConstructorExpression{Subquery: &SelectStatement{Columns: []Expression{&Identifier{Name: "x"}}}}
	if !strings.Contains(a2.SQL(), "ARRAY(") {
		t.Errorf("got: %s", a2.SQL())
	}
}

func TestArraySubscriptExpression_SQL(t *testing.T) {
	a := &ArraySubscriptExpression{
		Array:   &Identifier{Name: "arr"},
		Indices: []Expression{&LiteralValue{Value: "1"}, &LiteralValue{Value: "2"}},
	}
	if a.SQL() != "arr[1][2]" {
		t.Errorf("got: %s", a.SQL())
	}
}

func TestArraySliceExpression_SQL(t *testing.T) {
	a := &ArraySliceExpression{
		Array: &Identifier{Name: "arr"},
		Start: &LiteralValue{Value: "1"},
		End:   &LiteralValue{Value: "3"},
	}
	if a.SQL() != "arr[1:3]" {
		t.Errorf("got: %s", a.SQL())
	}
	// No start/end
	a2 := &ArraySliceExpression{Array: &Identifier{Name: "arr"}}
	if a2.SQL() != "arr[:]" {
		t.Errorf("got: %s", a2.SQL())
	}
}

func TestRollupExpression_SQL(t *testing.T) {
	r := &RollupExpression{Expressions: []Expression{&Identifier{Name: "a"}, &Identifier{Name: "b"}}}
	if r.SQL() != "ROLLUP(a, b)" {
		t.Errorf("got: %s", r.SQL())
	}
}

func TestCubeExpression_SQL(t *testing.T) {
	c := &CubeExpression{Expressions: []Expression{&Identifier{Name: "a"}}}
	if c.SQL() != "CUBE(a)" {
		t.Errorf("got: %s", c.SQL())
	}
}

func TestGroupingSetsExpression_SQL(t *testing.T) {
	g := &GroupingSetsExpression{Sets: [][]Expression{
		{&Identifier{Name: "a"}},
		{&Identifier{Name: "b"}, &Identifier{Name: "c"}},
	}}
	sql := g.SQL()
	if !strings.Contains(sql, "GROUPING SETS") {
		t.Errorf("got: %s", sql)
	}
}

func TestWindowFrameSQL(t *testing.T) {
	// Test through SelectStatement with window spec that has frame
	stmt := &SelectStatement{
		Columns: []Expression{&Identifier{Name: "x"}},
		From:    []TableReference{{Name: "t"}},
		Windows: []WindowSpec{
			{
				Name: "w1",
				PartitionBy: []Expression{&Identifier{Name: "a"}},
				OrderBy:     []OrderByExpression{{Expression: &Identifier{Name: "b"}, Ascending: true}},
				FrameClause: &WindowFrame{
					Type:  "ROWS",
					Start: WindowFrameBound{Type: "UNBOUNDED PRECEDING"},
					End:   &WindowFrameBound{Type: "CURRENT ROW"},
				},
			},
		},
	}
	sql := stmt.SQL()
	if !strings.Contains(sql, "ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW") {
		t.Errorf("got: %s", sql)
	}
}

func TestFetchSQL(t *testing.T) {
	fv := int64(10)
	ov := int64(5)
	stmt := &SelectStatement{
		Columns: []Expression{&Identifier{Name: "x"}},
		From:    []TableReference{{Name: "t"}},
		Fetch: &FetchClause{
			FetchType:   "FIRST",
			FetchValue:  &fv,
			OffsetValue: &ov,
			IsPercent:   true,
			WithTies:    true,
		},
	}
	sql := stmt.SQL()
	for _, want := range []string{"OFFSET 5 ROWS", "FETCH FIRST 10 PERCENT ROWS WITH TIES"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in: %s", want, sql)
		}
	}
}

func TestForSQL(t *testing.T) {
	stmt := &SelectStatement{
		Columns: []Expression{&Identifier{Name: "x"}},
		From:    []TableReference{{Name: "t"}},
		For: &ForClause{
			LockType:   "UPDATE",
			Tables:     []string{"t"},
			NoWait:     true,
			SkipLocked: true,
		},
	}
	sql := stmt.SQL()
	for _, want := range []string{"FOR UPDATE", "OF t", "NOWAIT", "SKIP LOCKED"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in: %s", want, sql)
		}
	}
}

func TestTableConstraintSQL(t *testing.T) {
	// Via CreateTableStatement
	stmt := &CreateTableStatement{
		Name: "t",
		Columns: []ColumnDef{{Name: "id", Type: "INT"}},
		Constraints: []TableConstraint{
			{Name: "pk", Type: "PRIMARY KEY", Columns: []string{"id"}},
			{Type: "UNIQUE", Columns: []string{"email"}},
			{Type: "FOREIGN KEY", Columns: []string{"user_id"}, References: &ReferenceDefinition{Table: "users", Columns: []string{"id"}, OnDelete: "CASCADE", OnUpdate: "SET NULL"}},
			{Type: "CHECK", Check: &BinaryExpression{Left: &Identifier{Name: "age"}, Operator: ">", Right: &LiteralValue{Value: "0"}}},
		},
	}
	sql := stmt.SQL()
	for _, want := range []string{"CONSTRAINT pk PRIMARY KEY", "UNIQUE (email)", "FOREIGN KEY", "REFERENCES users (id)", "ON DELETE CASCADE", "ON UPDATE SET NULL", "CHECK"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in: %s", want, sql)
		}
	}
}

func TestColumnConstraintSQL_AllTypes(t *testing.T) {
	stmt := &CreateTableStatement{
		Name: "t",
		Columns: []ColumnDef{
			{Name: "a", Type: "INT", Constraints: []ColumnConstraint{{Type: "NOT NULL"}}},
			{Name: "b", Type: "INT", Constraints: []ColumnConstraint{{Type: "UNIQUE"}}},
			{Name: "c", Type: "INT", Constraints: []ColumnConstraint{{Type: "PRIMARY KEY"}}},
			{Name: "d", Type: "INT", Constraints: []ColumnConstraint{{Type: "DEFAULT", Default: &LiteralValue{Value: "0"}}}},
			{Name: "e", Type: "INT", Constraints: []ColumnConstraint{{Type: "REFERENCES", References: &ReferenceDefinition{Table: "other"}}}},
			{Name: "f", Type: "INT", Constraints: []ColumnConstraint{{Type: "CHECK", Check: &Identifier{Name: "f > 0"}}}},
			{Name: "g", Type: "INT", Constraints: []ColumnConstraint{{AutoIncrement: true}}},
		},
	}
	sql := stmt.SQL()
	for _, want := range []string{"NOT NULL", "UNIQUE", "PRIMARY KEY", "DEFAULT 0", "REFERENCES other", "CHECK", "AUTO_INCREMENT"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in: %s", want, sql)
		}
	}
}

func TestCTEWithMaterialized(t *testing.T) {
	w := &WithClause{
		CTEs: []*CommonTableExpr{
			{Name: "cte1", Materialized: covBoolPtr(true), Statement: &SelectStatement{Columns: []Expression{&Identifier{Name: "a"}}}},
			{Name: "cte2", Materialized: covBoolPtr(false), Statement: &SelectStatement{Columns: []Expression{&Identifier{Name: "b"}}}},
		},
	}
	sql := w.SQL()
	if !strings.Contains(sql, "MATERIALIZED") || !strings.Contains(sql, "NOT MATERIALIZED") {
		t.Errorf("got: %s", sql)
	}
}

func TestOnConflictSQL(t *testing.T) {
	// DO NOTHING
	stmt := &InsertStatement{
		TableName: "t",
		Values:    [][]Expression{{&LiteralValue{Value: "1"}}},
		OnConflict: &OnConflict{
			Target:     []Expression{&Identifier{Name: "id"}},
			Constraint: "pk",
			Action:     OnConflictAction{DoNothing: true},
		},
	}
	sql := stmt.SQL()
	if !strings.Contains(sql, "ON CONFLICT (id) ON CONSTRAINT pk DO NOTHING") {
		t.Errorf("got: %s", sql)
	}

	// DO UPDATE with WHERE
	stmt2 := &InsertStatement{
		TableName: "t",
		Values:    [][]Expression{{&LiteralValue{Value: "1"}}},
		OnConflict: &OnConflict{
			Target: []Expression{&Identifier{Name: "id"}},
			Action: OnConflictAction{
				DoUpdate: []UpdateExpression{{Column: &Identifier{Name: "x"}, Value: &LiteralValue{Value: "2"}}},
				Where:    &Identifier{Name: "true"},
			},
		},
	}
	sql2 := stmt2.SQL()
	if !strings.Contains(sql2, "DO UPDATE SET x = 2 WHERE") {
		t.Errorf("got: %s", sql2)
	}
}

func TestNilSQL(t *testing.T) {
	// All nil cases should return ""
	var s *SelectStatement
	if s.SQL() != "" {
		t.Error("nil SelectStatement")
	}
	var i *InsertStatement
	if i.SQL() != "" {
		t.Error("nil InsertStatement")
	}
	var u *UpdateStatement
	if u.SQL() != "" {
		t.Error("nil UpdateStatement")
	}
	var d *DeleteStatement
	if d.SQL() != "" {
		t.Error("nil DeleteStatement")
	}
	var c *CreateTableStatement
	if c.SQL() != "" {
		t.Error("nil CreateTableStatement")
	}
	var ci *CreateIndexStatement
	if ci.SQL() != "" {
		t.Error("nil CreateIndexStatement")
	}
	var at *AlterTableStatement
	if at.SQL() != "" {
		t.Error("nil AlterTableStatement")
	}
	var dr *DropStatement
	if dr.SQL() != "" {
		t.Error("nil DropStatement")
	}
	var tr *TruncateStatement
	if tr.SQL() != "" {
		t.Error("nil TruncateStatement")
	}
	var w *WithClause
	if w.SQL() != "" {
		t.Error("nil WithClause")
	}
	var so *SetOperation
	if so.SQL() != "" {
		t.Error("nil SetOperation")
	}
	var v *Values
	if v.SQL() != "" {
		t.Error("nil Values")
	}
	var cv *CreateViewStatement
	if cv.SQL() != "" {
		t.Error("nil CreateViewStatement")
	}
	var cmv *CreateMaterializedViewStatement
	if cmv.SQL() != "" {
		t.Error("nil CreateMaterializedViewStatement")
	}
	var rmv *RefreshMaterializedViewStatement
	if rmv.SQL() != "" {
		t.Error("nil RefreshMaterializedViewStatement")
	}
	var m *MergeStatement
	if m.SQL() != "" {
		t.Error("nil MergeStatement")
	}
	var sel *Select
	if sel.SQL() != "" {
		t.Error("nil Select")
	}
	var ins *Insert
	if ins.SQL() != "" {
		t.Error("nil Insert")
	}
	var upd *Update
	if upd.SQL() != "" {
		t.Error("nil Update")
	}
	var del *Delete
	if del.SQL() != "" {
		t.Error("nil Delete")
	}
	var ext *ExtractExpression
	if ext.SQL() != "" {
		t.Error("nil ExtractExpression")
	}
	var pos *PositionExpression
	if pos.SQL() != "" {
		t.Error("nil PositionExpression")
	}
	var sub *SubstringExpression
	if sub.SQL() != "" {
		t.Error("nil SubstringExpression")
	}
	var iv *IntervalExpression
	if iv.SQL() != "" {
		t.Error("nil IntervalExpression")
	}
	var le *ListExpression
	if le.SQL() != "" {
		t.Error("nil ListExpression")
	}
	var te *TupleExpression
	if te.SQL() != "" {
		t.Error("nil TupleExpression")
	}
	var ac *ArrayConstructorExpression
	if ac.SQL() != "" {
		t.Error("nil ArrayConstructorExpression")
	}
	var as *ArraySubscriptExpression
	if as.SQL() != "" {
		t.Error("nil ArraySubscriptExpression")
	}
	var asl *ArraySliceExpression
	if asl.SQL() != "" {
		t.Error("nil ArraySliceExpression")
	}
	var re *RollupExpression
	if re.SQL() != "" {
		t.Error("nil RollupExpression")
	}
	var ce *CubeExpression
	if ce.SQL() != "" {
		t.Error("nil CubeExpression")
	}
	var gs *GroupingSetsExpression
	if gs.SQL() != "" {
		t.Error("nil GroupingSetsExpression")
	}
}

func TestSelectStatement_WithAndReturning(t *testing.T) {
	// SelectStatement with With, DistinctOn, Having, Windows, OrderBy, Limit, Offset
	lim := 10
	off := 5
	stmt := &SelectStatement{
		With: &WithClause{CTEs: []*CommonTableExpr{
			{Name: "c", Statement: &SelectStatement{Columns: []Expression{&Identifier{Name: "x"}}}},
		}},
		DistinctOnColumns: []Expression{&Identifier{Name: "a"}},
		Columns:           []Expression{&Identifier{Name: "a"}, &Identifier{Name: "b"}},
		From:              []TableReference{{Name: "t"}},
		Joins:             []JoinClause{{Type: "LEFT", Right: TableReference{Name: "t2"}, Condition: &Identifier{Name: "true"}}},
		Where:             &Identifier{Name: "true"},
		GroupBy:           []Expression{&Identifier{Name: "a"}},
		Having:            &Identifier{Name: "count(*) > 1"},
		Windows:           []WindowSpec{{Name: "w", OrderBy: []OrderByExpression{{Expression: &Identifier{Name: "a"}, Ascending: true}}}},
		OrderBy:           []OrderByExpression{{Expression: &Identifier{Name: "a"}, Ascending: false, NullsFirst: covBoolPtr(true)}},
		Limit:             &lim,
		Offset:            &off,
	}
	sql := stmt.SQL()
	for _, want := range []string{"WITH", "DISTINCT ON", "LEFT JOIN", "GROUP BY", "HAVING", "WINDOW", "ORDER BY", "DESC", "NULLS FIRST", "LIMIT 10", "OFFSET 5"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in: %s", want, sql)
		}
	}
}

func TestInsertStatement_WithQuery(t *testing.T) {
	stmt := &InsertStatement{
		With: &WithClause{CTEs: []*CommonTableExpr{
			{Name: "c", Statement: &SelectStatement{Columns: []Expression{&Identifier{Name: "x"}}}},
		}},
		TableName: "t",
		Query:     &SelectStatement{Columns: []Expression{&Identifier{Name: "a"}}},
		Returning: []Expression{&Identifier{Name: "id"}},
	}
	sql := stmt.SQL()
	for _, want := range []string{"WITH", "INSERT INTO", "SELECT", "RETURNING"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in: %s", want, sql)
		}
	}
}

func TestUpdateStatement_WithFromReturning(t *testing.T) {
	stmt := &UpdateStatement{
		With: &WithClause{CTEs: []*CommonTableExpr{
			{Name: "c", Statement: &SelectStatement{Columns: []Expression{&Identifier{Name: "x"}}}},
		}},
		TableName:   "t",
		Alias:       "tt",
		Assignments: []UpdateExpression{{Column: &Identifier{Name: "x"}, Value: &LiteralValue{Value: "1"}}},
		From:        []TableReference{{Name: "other"}},
		Where:       &Identifier{Name: "true"},
		Returning:   []Expression{&Identifier{Name: "id"}},
	}
	sql := stmt.SQL()
	for _, want := range []string{"WITH", "UPDATE t tt", "FROM other", "WHERE", "RETURNING"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in: %s", want, sql)
		}
	}
}

func TestDeleteStatement_WithUsingReturning(t *testing.T) {
	stmt := &DeleteStatement{
		With: &WithClause{CTEs: []*CommonTableExpr{
			{Name: "c", Statement: &SelectStatement{Columns: []Expression{&Identifier{Name: "x"}}}},
		}},
		TableName: "t",
		Alias:     "tt",
		Using:     []TableReference{{Name: "other"}},
		Where:     &Identifier{Name: "true"},
		Returning: []Expression{&Identifier{Name: "id"}},
	}
	sql := stmt.SQL()
	for _, want := range []string{"WITH", "DELETE FROM t tt", "USING other", "WHERE", "RETURNING"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in: %s", want, sql)
		}
	}
}

func TestCreateTableStatement_AllFeatures(t *testing.T) {
	stmt := &CreateTableStatement{
		Name:        "t",
		Temporary:   true,
		IfNotExists: true,
		Columns:     []ColumnDef{{Name: "id", Type: "INT"}},
		Inherits:    []string{"parent"},
		PartitionBy: &PartitionBy{Type: "RANGE", Columns: []string{"created_at"}},
		Options:     []TableOption{{Name: "engine", Value: "InnoDB"}},
	}
	sql := stmt.SQL()
	for _, want := range []string{"CREATE TEMPORARY TABLE IF NOT EXISTS", "INHERITS (parent)", "PARTITION BY RANGE", "engine=InnoDB"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in: %s", want, sql)
		}
	}
}

func TestLateralTableRef(t *testing.T) {
	stmt := &SelectStatement{
		Columns: []Expression{&Identifier{Name: "x"}},
		From:    []TableReference{{Lateral: true, Subquery: &SelectStatement{Columns: []Expression{&Identifier{Name: "a"}}}, Alias: "sub"}},
	}
	sql := stmt.SQL()
	if !strings.Contains(sql, "LATERAL") {
		t.Errorf("got: %s", sql)
	}
}

func TestOrderByNullsLast(t *testing.T) {
	stmt := &SelectStatement{
		Columns: []Expression{&Identifier{Name: "x"}},
		From:    []TableReference{{Name: "t"}},
		OrderBy: []OrderByExpression{{Expression: &Identifier{Name: "a"}, Ascending: true, NullsFirst: covBoolPtr(false)}},
	}
	sql := stmt.SQL()
	if !strings.Contains(sql, "NULLS LAST") {
		t.Errorf("got: %s", sql)
	}
}
