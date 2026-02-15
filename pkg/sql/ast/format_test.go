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

func TestAlterTableFormat_Readable(t *testing.T) {
	stmt := &AlterTableStatement{
		Table: "users",
		Actions: []AlterTableAction{
			{Type: "ADD COLUMN", ColumnDef: &ColumnDef{Name: "email", Type: "VARCHAR(255)"}},
		},
	}

	result := stmt.Format(ReadableStyle())
	if !strings.Contains(result, "ALTER TABLE") {
		t.Error("expected ALTER TABLE keyword")
	}
	if !strings.Contains(result, "ADD COLUMN") {
		t.Error("expected ADD COLUMN")
	}
	if !strings.Contains(result, "email") {
		t.Error("expected column name email")
	}
	if !strings.HasSuffix(result, ";") {
		t.Error("ReadableStyle should end with semicolon")
	}
}

func TestAlterTableFormat_DropColumn(t *testing.T) {
	stmt := &AlterTableStatement{
		Table: "users",
		Actions: []AlterTableAction{
			{Type: "DROP COLUMN", ColumnName: "age"},
		},
	}

	result := stmt.Format(CompactStyle())
	if !strings.Contains(result, "DROP COLUMN age") {
		t.Errorf("expected DROP COLUMN age, got: %s", result)
	}
}

func TestAlterTableFormat_MultipleActions(t *testing.T) {
	stmt := &AlterTableStatement{
		Table: "users",
		Actions: []AlterTableAction{
			{Type: "ADD COLUMN", ColumnDef: &ColumnDef{Name: "email", Type: "TEXT"}},
			{Type: "DROP COLUMN", ColumnName: "age"},
		},
	}

	result := stmt.Format(CompactStyle())
	if !strings.Contains(result, ",") {
		t.Errorf("expected comma between actions, got: %s", result)
	}
}

func TestAlterTableFormat_Nil(t *testing.T) {
	var stmt *AlterTableStatement
	if stmt.Format(CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

func TestCreateIndexFormat_Readable(t *testing.T) {
	stmt := &CreateIndexStatement{
		Unique:      true,
		IfNotExists: true,
		Name:        "idx_users_email",
		Table:       "users",
		Columns:     []IndexColumn{{Column: "email", Direction: "ASC"}},
		Using:       "btree",
	}

	result := stmt.Format(ReadableStyle())
	if !strings.Contains(result, "CREATE UNIQUE INDEX IF NOT EXISTS") {
		t.Errorf("expected CREATE UNIQUE INDEX IF NOT EXISTS, got: %s", result)
	}
	if !strings.Contains(result, "ON users") {
		t.Errorf("expected ON users, got: %s", result)
	}
	if !strings.Contains(result, "USING btree") {
		t.Errorf("expected USING btree, got: %s", result)
	}
	if !strings.Contains(result, "email ASC") {
		t.Errorf("expected email ASC, got: %s", result)
	}
}

func TestCreateIndexFormat_WithWhere(t *testing.T) {
	stmt := &CreateIndexStatement{
		Name:    "idx_active",
		Table:   "users",
		Columns: []IndexColumn{{Column: "id"}},
		Where:   &BinaryExpression{Left: &Identifier{Name: "active"}, Operator: "=", Right: &LiteralValue{Value: "true"}},
	}

	result := stmt.Format(CompactStyle())
	if !strings.Contains(result, "WHERE") {
		t.Errorf("expected WHERE clause, got: %s", result)
	}
}

func TestCreateIndexFormat_Nil(t *testing.T) {
	var stmt *CreateIndexStatement
	if stmt.Format(CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

func TestCreateIndexFormat_NullsLast(t *testing.T) {
	stmt := &CreateIndexStatement{
		Name:    "idx_test",
		Table:   "t",
		Columns: []IndexColumn{{Column: "a", NullsLast: true, Collate: "en_US"}},
	}
	result := stmt.Format(ReadableStyle())
	if !strings.Contains(result, "COLLATE en_US") {
		t.Errorf("expected COLLATE, got: %s", result)
	}
	if !strings.Contains(result, "NULLS LAST") {
		t.Errorf("expected NULLS LAST, got: %s", result)
	}
}

func TestCreateViewFormat_Readable(t *testing.T) {
	stmt := &CreateViewStatement{
		OrReplace: true,
		Name:      "active_users",
		Columns:   []string{"id", "name"},
		Query: &SelectStatement{
			Columns: []Expression{&Identifier{Name: "id"}, &Identifier{Name: "name"}},
			From:    []TableReference{{Name: "users"}},
			Where:   &BinaryExpression{Left: &Identifier{Name: "active"}, Operator: "=", Right: &LiteralValue{Value: "true"}},
		},
	}

	result := stmt.Format(ReadableStyle())
	if !strings.Contains(result, "CREATE OR REPLACE VIEW") {
		t.Errorf("expected CREATE OR REPLACE VIEW, got: %s", result)
	}
	if !strings.Contains(result, "(id, name)") {
		t.Errorf("expected column list, got: %s", result)
	}
	if !strings.Contains(result, "AS") {
		t.Errorf("expected AS keyword, got: %s", result)
	}
}

func TestCreateViewFormat_Nil(t *testing.T) {
	var stmt *CreateViewStatement
	if stmt.Format(CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

func TestCreateViewFormat_WithOption(t *testing.T) {
	stmt := &CreateViewStatement{
		Name:       "v",
		Query:      &SelectStatement{Columns: []Expression{&Identifier{Name: "1"}}},
		WithOption: "WITH CHECK OPTION",
	}
	result := stmt.Format(ReadableStyle())
	if !strings.Contains(result, "WITH CHECK OPTION") {
		t.Errorf("expected WITH CHECK OPTION, got: %s", result)
	}
}

func TestCreateMaterializedViewFormat_Readable(t *testing.T) {
	withData := true
	stmt := &CreateMaterializedViewStatement{
		IfNotExists: true,
		Name:        "mv_stats",
		Columns:     []string{"cnt"},
		Query: &SelectStatement{
			Columns: []Expression{&FunctionCall{Name: "count", Arguments: []Expression{&Identifier{Name: "*"}}}},
			From:    []TableReference{{Name: "events"}},
		},
		WithData: &withData,
	}

	result := stmt.Format(ReadableStyle())
	if !strings.Contains(result, "CREATE MATERIALIZED VIEW IF NOT EXISTS") {
		t.Errorf("expected CREATE MATERIALIZED VIEW IF NOT EXISTS, got: %s", result)
	}
	if !strings.Contains(result, "WITH DATA") {
		t.Errorf("expected WITH DATA, got: %s", result)
	}
}

func TestCreateMaterializedViewFormat_NoData(t *testing.T) {
	noData := false
	stmt := &CreateMaterializedViewStatement{
		Name:     "mv_test",
		Query:    &SelectStatement{Columns: []Expression{&Identifier{Name: "1"}}},
		WithData: &noData,
	}
	result := stmt.Format(CompactStyle())
	if !strings.Contains(result, "WITH NO DATA") {
		t.Errorf("expected WITH NO DATA, got: %s", result)
	}
}

func TestCreateMaterializedViewFormat_Nil(t *testing.T) {
	var stmt *CreateMaterializedViewStatement
	if stmt.Format(CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

func TestCreateMaterializedViewFormat_Tablespace(t *testing.T) {
	stmt := &CreateMaterializedViewStatement{
		Name:       "mv_ts",
		Query:      &SelectStatement{Columns: []Expression{&Identifier{Name: "1"}}},
		Tablespace: "fast_ssd",
	}
	result := stmt.Format(ReadableStyle())
	if !strings.Contains(result, "TABLESPACE fast_ssd") {
		t.Errorf("expected TABLESPACE, got: %s", result)
	}
}

func TestRefreshMaterializedViewFormat_Readable(t *testing.T) {
	withData := true
	stmt := &RefreshMaterializedViewStatement{
		Concurrently: true,
		Name:         "mv_stats",
		WithData:     &withData,
	}

	result := stmt.Format(ReadableStyle())
	if !strings.Contains(result, "REFRESH MATERIALIZED VIEW CONCURRENTLY") {
		t.Errorf("expected REFRESH MATERIALIZED VIEW CONCURRENTLY, got: %s", result)
	}
	if !strings.Contains(result, "WITH DATA") {
		t.Errorf("expected WITH DATA, got: %s", result)
	}
}

func TestRefreshMaterializedViewFormat_Nil(t *testing.T) {
	var stmt *RefreshMaterializedViewStatement
	if stmt.Format(CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

func TestDropFormat_Readable(t *testing.T) {
	stmt := &DropStatement{
		ObjectType:  "TABLE",
		IfExists:    true,
		Names:       []string{"users", "orders"},
		CascadeType: "CASCADE",
	}

	result := stmt.Format(ReadableStyle())
	if !strings.Contains(result, "DROP TABLE IF EXISTS") {
		t.Errorf("expected DROP TABLE IF EXISTS, got: %s", result)
	}
	if !strings.Contains(result, "users, orders") {
		t.Errorf("expected multiple table names, got: %s", result)
	}
	if !strings.Contains(result, "CASCADE") {
		t.Errorf("expected CASCADE, got: %s", result)
	}
}

func TestDropFormat_Simple(t *testing.T) {
	stmt := &DropStatement{
		ObjectType: "INDEX",
		Names:      []string{"idx_test"},
	}
	result := stmt.Format(CompactStyle())
	expected := "DROP INDEX idx_test"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestDropFormat_Nil(t *testing.T) {
	var stmt *DropStatement
	if stmt.Format(CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

func TestTruncateFormat_Readable(t *testing.T) {
	stmt := &TruncateStatement{
		Tables:          []string{"users", "orders"},
		RestartIdentity: true,
		CascadeType:     "CASCADE",
	}

	result := stmt.Format(ReadableStyle())
	if !strings.Contains(result, "TRUNCATE TABLE") {
		t.Errorf("expected TRUNCATE TABLE, got: %s", result)
	}
	if !strings.Contains(result, "users, orders") {
		t.Errorf("expected table names, got: %s", result)
	}
	if !strings.Contains(result, "RESTART IDENTITY") {
		t.Errorf("expected RESTART IDENTITY, got: %s", result)
	}
	if !strings.Contains(result, "CASCADE") {
		t.Errorf("expected CASCADE, got: %s", result)
	}
}

func TestTruncateFormat_ContinueIdentity(t *testing.T) {
	stmt := &TruncateStatement{
		Tables:           []string{"t"},
		ContinueIdentity: true,
	}
	result := stmt.Format(ReadableStyle())
	if !strings.Contains(result, "CONTINUE IDENTITY") {
		t.Errorf("expected CONTINUE IDENTITY, got: %s", result)
	}
}

func TestTruncateFormat_Nil(t *testing.T) {
	var stmt *TruncateStatement
	if stmt.Format(CompactStyle()) != "" {
		t.Error("nil should return empty string")
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
