package ast

import (
	"strings"
	"testing"
)

func TestCompactStyle(t *testing.T) {
	opts := CompactStyle()
	if opts.NewlinePerClause {
		t.Error("CompactStyle should not have NewlinePerClause")
	}
	if opts.IndentWidth != 0 {
		t.Error("CompactStyle should have IndentWidth 0")
	}
}

func TestReadableStyle(t *testing.T) {
	opts := ReadableStyle()
	if !opts.NewlinePerClause {
		t.Error("ReadableStyle should have NewlinePerClause")
	}
	if opts.KeywordCase != KeywordUpper {
		t.Error("ReadableStyle should have KeywordUpper")
	}
	if !opts.AddSemicolon {
		t.Error("ReadableStyle should add semicolons")
	}
}

func TestSelectFormat_Compact(t *testing.T) {
	stmt := &SelectStatement{
		Columns: []Expression{&Identifier{Name: "a"}, &Identifier{Name: "b"}},
		From:    []TableReference{{Name: "users"}},
		Where:   &BinaryExpression{Left: &Identifier{Name: "active"}, Operator: "=", Right: &LiteralValue{Value: "true"}},
	}

	result := stmt.Format(CompactStyle())
	// Compact: all on one line, keywords preserved case
	if strings.Contains(result, "\n") {
		t.Errorf("CompactStyle should be single line, got: %s", result)
	}
	if !strings.Contains(result, "SELECT") {
		t.Errorf("should contain SELECT, got: %s", result)
	}
	if !strings.Contains(result, "FROM users") {
		t.Errorf("should contain FROM users, got: %s", result)
	}
	if !strings.Contains(result, "WHERE") {
		t.Errorf("should contain WHERE, got: %s", result)
	}
}

func TestSelectFormat_Readable(t *testing.T) {
	stmt := &SelectStatement{
		Columns: []Expression{&Identifier{Name: "a"}, &Identifier{Name: "b"}},
		From:    []TableReference{{Name: "users"}},
		Where:   &BinaryExpression{Left: &Identifier{Name: "active"}, Operator: "=", Right: &LiteralValue{Value: "true"}},
	}

	result := stmt.Format(ReadableStyle())
	lines := strings.Split(result, "\n")
	if len(lines) < 3 {
		t.Errorf("ReadableStyle should have multiple lines, got %d: %s", len(lines), result)
	}
	if !strings.HasPrefix(lines[0], "SELECT") {
		t.Errorf("first line should start with SELECT, got: %s", lines[0])
	}
	// Keywords should be uppercase
	if !strings.Contains(result, "FROM") {
		t.Errorf("should contain uppercase FROM, got: %s", result)
	}
	if !strings.Contains(result, "WHERE") {
		t.Errorf("should contain uppercase WHERE, got: %s", result)
	}
	// Should end with semicolon
	if !strings.HasSuffix(strings.TrimSpace(result), ";") {
		t.Errorf("ReadableStyle should end with semicolon, got: %s", result)
	}
}

func TestSelectFormat_LowercaseKeywords(t *testing.T) {
	stmt := &SelectStatement{
		Columns: []Expression{&Identifier{Name: "id"}},
		From:    []TableReference{{Name: "t"}},
	}
	opts := FormatOptions{KeywordCase: KeywordLower, NewlinePerClause: false}
	result := stmt.Format(opts)
	if !strings.Contains(result, "select") {
		t.Errorf("should contain lowercase select, got: %s", result)
	}
	if !strings.Contains(result, "from") {
		t.Errorf("should contain lowercase from, got: %s", result)
	}
}

func TestInsertFormat_Readable(t *testing.T) {
	stmt := &InsertStatement{
		TableName: "users",
		Columns:   []Expression{&Identifier{Name: "name"}, &Identifier{Name: "age"}},
		Values: [][]Expression{
			{&LiteralValue{Value: "'Alice'"}, &LiteralValue{Value: "30"}},
		},
	}

	result := stmt.Format(ReadableStyle())
	if !strings.Contains(result, "INSERT INTO") {
		t.Errorf("should contain INSERT INTO, got: %s", result)
	}
	if !strings.Contains(result, "VALUES") {
		t.Errorf("should contain VALUES, got: %s", result)
	}
	if !strings.HasSuffix(strings.TrimSpace(result), ";") {
		t.Errorf("should end with semicolon, got: %s", result)
	}
}

func TestUpdateFormat_Readable(t *testing.T) {
	stmt := &UpdateStatement{
		TableName: "users",
		Assignments: []UpdateExpression{
			{Column: &Identifier{Name: "name"}, Value: &LiteralValue{Value: "'Bob'"}},
		},
		Where: &BinaryExpression{Left: &Identifier{Name: "id"}, Operator: "=", Right: &LiteralValue{Value: "1"}},
	}

	result := stmt.Format(ReadableStyle())
	if !strings.Contains(result, "UPDATE") {
		t.Errorf("should contain UPDATE, got: %s", result)
	}
	if !strings.Contains(result, "SET") {
		t.Errorf("should contain SET, got: %s", result)
	}
	if !strings.Contains(result, "WHERE") {
		t.Errorf("should contain WHERE, got: %s", result)
	}
	lines := strings.Split(result, "\n")
	if len(lines) < 3 {
		t.Errorf("should have multiple lines, got: %s", result)
	}
}

func TestDeleteFormat_Readable(t *testing.T) {
	stmt := &DeleteStatement{
		TableName: "users",
		Where:     &BinaryExpression{Left: &Identifier{Name: "id"}, Operator: "=", Right: &LiteralValue{Value: "1"}},
	}

	result := stmt.Format(ReadableStyle())
	if !strings.Contains(result, "DELETE FROM") {
		t.Errorf("should contain DELETE FROM, got: %s", result)
	}
	if !strings.Contains(result, "WHERE") {
		t.Errorf("should contain WHERE, got: %s", result)
	}
}

func TestASTFormat_MultiStatement(t *testing.T) {
	a := AST{
		Statements: []Statement{
			&SelectStatement{
				Columns: []Expression{&Identifier{Name: "a"}},
				From:    []TableReference{{Name: "t1"}},
			},
			&SelectStatement{
				Columns: []Expression{&Identifier{Name: "b"}},
				From:    []TableReference{{Name: "t2"}},
			},
		},
	}

	result := a.Format(CompactStyle())
	if !strings.Contains(result, "SELECT a FROM t1") {
		t.Errorf("should contain first statement, got: %s", result)
	}
	if !strings.Contains(result, "SELECT b FROM t2") {
		t.Errorf("should contain second statement, got: %s", result)
	}
}

func TestCreateTableFormat_Readable(t *testing.T) {
	stmt := &CreateTableStatement{
		Name: "users",
		Columns: []ColumnDef{
			{Name: "id", Type: "INT"},
			{Name: "name", Type: "TEXT"},
		},
	}

	result := stmt.Format(ReadableStyle())
	if !strings.Contains(result, "CREATE TABLE") {
		t.Errorf("should contain CREATE TABLE, got: %s", result)
	}
	// Readable style should indent columns
	if !strings.Contains(result, "\n") {
		t.Errorf("should have newlines for readable, got: %s", result)
	}
}

func TestKeywordCase(t *testing.T) {
	f := newFormatter(FormatOptions{KeywordCase: KeywordUpper})
	if f.kw("select") != "SELECT" {
		t.Error("KeywordUpper should uppercase")
	}
	f2 := newFormatter(FormatOptions{KeywordCase: KeywordLower})
	if f2.kw("SELECT") != "select" {
		t.Error("KeywordLower should lowercase")
	}
	f3 := newFormatter(FormatOptions{KeywordCase: KeywordPreserve})
	if f3.kw("Select") != "Select" {
		t.Error("KeywordPreserve should preserve case")
	}
}

func TestFormatRoundtrip(t *testing.T) {
	// Format with compact style should produce parseable SQL equivalent to SQL()
	stmt := &SelectStatement{
		Columns: []Expression{&Identifier{Name: "id"}, &Identifier{Name: "name"}},
		From:    []TableReference{{Name: "users"}},
		Where:   &BinaryExpression{Left: &Identifier{Name: "active"}, Operator: "=", Right: &LiteralValue{Value: "true"}},
	}

	compact := stmt.Format(CompactStyle())
	sql := stmt.SQL()
	if compact != sql {
		t.Errorf("CompactStyle should match SQL() output\nCompact: %s\nSQL():   %s", compact, sql)
	}
}
