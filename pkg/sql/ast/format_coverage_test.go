package ast

import (
	"strings"
	"testing"
)

func TestSetOperation_Format(t *testing.T) {
	s := &SetOperation{
		Left:     &SelectStatement{Columns: []Expression{&Identifier{Name: "a"}}, From: []TableReference{{Name: "t1"}}},
		Right:    &SelectStatement{Columns: []Expression{&Identifier{Name: "b"}}, From: []TableReference{{Name: "t2"}}},
		Operator: "UNION",
		All:      true,
	}
	sql := s.Format(ReadableStyle())
	if !strings.Contains(sql, "UNION ALL") {
		t.Errorf("got: %s", sql)
	}
	if !strings.HasSuffix(strings.TrimSpace(sql), ";") {
		t.Error("ReadableStyle should add semicolon")
	}

	// Compact
	compact := s.Format(CompactStyle())
	if strings.Contains(compact, "\n") {
		t.Errorf("compact should be single line: %s", compact)
	}
}

func TestSelectFormat_AllClauses(t *testing.T) {
	lim := 10
	off := 5
	fv := int64(3)
	stmt := &SelectStatement{
		With: &WithClause{
			Recursive: true,
			CTEs: []*CommonTableExpr{
				{Name: "cte", Columns: []string{"x"}, Statement: &SelectStatement{Columns: []Expression{&Identifier{Name: "1"}}}},
			},
		},
		DistinctOnColumns: []Expression{&Identifier{Name: "a"}},
		Columns:           []Expression{&Identifier{Name: "a"}, &Identifier{Name: "b"}},
		From:              []TableReference{{Name: "t"}},
		Joins:             []JoinClause{{Type: "INNER", Right: TableReference{Name: "t2"}, Condition: &Identifier{Name: "true"}}},
		Where:             &Identifier{Name: "x > 0"},
		GroupBy:           []Expression{&Identifier{Name: "a"}},
		Having:            &Identifier{Name: "count(*) > 1"},
		Windows:           []WindowSpec{{Name: "w", OrderBy: []OrderByExpression{{Expression: &Identifier{Name: "a"}, Ascending: true}}}},
		OrderBy:           []OrderByExpression{{Expression: &Identifier{Name: "a"}, Ascending: false}},
		Limit:             &lim,
		Offset:            &off,
		Fetch:             &FetchClause{FetchType: "FIRST", FetchValue: &fv},
		For:               &ForClause{LockType: "UPDATE"},
	}

	result := stmt.Format(ReadableStyle())
	for _, want := range []string{"WITH RECURSIVE", "DISTINCT ON", "FROM", "INNER JOIN", "WHERE", "GROUP BY", "HAVING", "WINDOW", "ORDER BY", "LIMIT", "OFFSET", "FETCH", "FOR UPDATE"} {
		if !strings.Contains(result, want) {
			t.Errorf("missing %q in: %s", want, result)
		}
	}
}

func TestInsertFormat_WithQuery(t *testing.T) {
	stmt := &InsertStatement{
		With: &WithClause{CTEs: []*CommonTableExpr{
			{Name: "c", Statement: &SelectStatement{Columns: []Expression{&Identifier{Name: "x"}}}},
		}},
		TableName: "t",
		Columns:   []Expression{&Identifier{Name: "a"}},
		Query:     &SelectStatement{Columns: []Expression{&Identifier{Name: "x"}}},
		Returning: []Expression{&Identifier{Name: "id"}},
	}
	sql := stmt.Format(ReadableStyle())
	for _, want := range []string{"WITH", "INSERT INTO", "RETURNING"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in: %s", want, sql)
		}
	}
}

func TestInsertFormat_OnConflict(t *testing.T) {
	stmt := &InsertStatement{
		TableName: "t",
		Values:    [][]Expression{{&LiteralValue{Value: "1"}}},
		OnConflict: &OnConflict{
			Target: []Expression{&Identifier{Name: "id"}},
			Action: OnConflictAction{DoNothing: true},
		},
	}
	sql := stmt.Format(CompactStyle())
	if !strings.Contains(sql, "ON CONFLICT") {
		t.Errorf("got: %s", sql)
	}
}

func TestUpdateFormat_AllClauses(t *testing.T) {
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
	sql := stmt.Format(ReadableStyle())
	for _, want := range []string{"WITH", "UPDATE t tt", "SET", "FROM", "WHERE", "RETURNING"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in: %s", want, sql)
		}
	}
}

func TestDeleteFormat_AllClauses(t *testing.T) {
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
	sql := stmt.Format(ReadableStyle())
	for _, want := range []string{"WITH", "DELETE FROM t tt", "USING", "WHERE", "RETURNING"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in: %s", want, sql)
		}
	}
}

func TestCreateTableFormat_AllFeatures(t *testing.T) {
	stmt := &CreateTableStatement{
		Name:        "t",
		Temporary:   true,
		IfNotExists: true,
		Columns: []ColumnDef{
			{Name: "id", Type: "INT"},
			{Name: "name", Type: "TEXT"},
		},
		Constraints: []TableConstraint{
			{Type: "PRIMARY KEY", Columns: []string{"id"}},
		},
		Inherits:    []string{"parent"},
		PartitionBy: &PartitionBy{Type: "HASH", Columns: []string{"id"}},
		Options:     []TableOption{{Name: "engine", Value: "InnoDB"}},
	}

	// Readable
	readable := stmt.Format(ReadableStyle())
	for _, want := range []string{"CREATE TEMPORARY TABLE IF NOT EXISTS", "INHERITS", "PARTITION BY"} {
		if !strings.Contains(readable, want) {
			t.Errorf("missing %q in readable: %s", want, readable)
		}
	}

	// Compact
	compact := stmt.Format(CompactStyle())
	if strings.Contains(compact, "\n") {
		t.Errorf("compact should be single line: %s", compact)
	}
}

func TestNilFormat(t *testing.T) {
	var s *SelectStatement
	if s.Format(CompactStyle()) != "" {
		t.Error("nil should be empty")
	}
	var i *InsertStatement
	if i.Format(CompactStyle()) != "" {
		t.Error("nil should be empty")
	}
	var u *UpdateStatement
	if u.Format(CompactStyle()) != "" {
		t.Error("nil should be empty")
	}
	var d *DeleteStatement
	if d.Format(CompactStyle()) != "" {
		t.Error("nil should be empty")
	}
	var c *CreateTableStatement
	if c.Format(CompactStyle()) != "" {
		t.Error("nil should be empty")
	}
	var so *SetOperation
	if so.Format(CompactStyle()) != "" {
		t.Error("nil should be empty")
	}
}

func TestFormatWithTabs(t *testing.T) {
	// Tabs are used for indentation at depth > 0, which happens in CREATE TABLE columns
	stmt := &CreateTableStatement{
		Name:    "t",
		Columns: []ColumnDef{{Name: "id", Type: "INT"}},
	}
	opts := FormatOptions{
		IndentStyle:      IndentTabs,
		IndentWidth:      1,
		NewlinePerClause: true,
	}
	result := stmt.Format(opts)
	if !strings.Contains(result, "\t") {
		t.Errorf("should use tabs: %s", result)
	}
}

func TestSelectFormat_Distinct(t *testing.T) {
	stmt := &SelectStatement{
		Distinct: true,
		Columns:  []Expression{&Identifier{Name: "a"}},
		From:     []TableReference{{Name: "t"}},
	}
	sql := stmt.Format(CompactStyle())
	if !strings.Contains(sql, "DISTINCT") {
		t.Errorf("got: %s", sql)
	}
}
