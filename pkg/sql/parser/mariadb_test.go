package parser_test

import (
	"os"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// ── Task 7: SEQUENCE Tests ────────────────────────────────────────────────────

func TestMariaDB_CreateSequence_Basic(t *testing.T) {
	sql := "CREATE SEQUENCE seq_orders START WITH 1 INCREMENT BY 1"
	tree, err := parser.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}
	stmt, ok := tree.Statements[0].(*ast.CreateSequenceStatement)
	if !ok {
		t.Fatalf("expected CreateSequenceStatement, got %T", tree.Statements[0])
	}
	if stmt.Name.Name != "seq_orders" {
		t.Errorf("expected name %q, got %q", "seq_orders", stmt.Name.Name)
	}
	if stmt.Options.StartWith == nil {
		t.Error("expected StartWith to be set")
	}
}

func TestMariaDB_CreateSequence_AllOptions(t *testing.T) {
	sql := `CREATE SEQUENCE s START WITH 100 INCREMENT BY 5 MINVALUE 1 MAXVALUE 9999 CYCLE CACHE 20`
	tree, err := parser.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := tree.Statements[0].(*ast.CreateSequenceStatement)
	if !stmt.Options.Cycle {
		t.Error("expected Cycle = true")
	}
	if stmt.Options.Cache == nil {
		t.Error("expected Cache to be set")
	}
}

func TestMariaDB_CreateSequence_IfNotExists(t *testing.T) {
	sql := "CREATE SEQUENCE IF NOT EXISTS my_seq"
	tree, err := parser.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := tree.Statements[0].(*ast.CreateSequenceStatement)
	if !stmt.IfNotExists {
		t.Error("expected IfNotExists = true")
	}
}

func TestMariaDB_DropSequence(t *testing.T) {
	sql := "DROP SEQUENCE IF EXISTS seq_orders"
	tree, err := parser.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt, ok := tree.Statements[0].(*ast.DropSequenceStatement)
	if !ok {
		t.Fatalf("expected DropSequenceStatement, got %T", tree.Statements[0])
	}
	if !stmt.IfExists {
		t.Error("expected IfExists = true")
	}
}

func TestMariaDB_AlterSequence_Restart(t *testing.T) {
	sql := "ALTER SEQUENCE seq_orders RESTART WITH 500"
	tree, err := parser.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt, ok := tree.Statements[0].(*ast.AlterSequenceStatement)
	if !ok {
		t.Fatalf("expected AlterSequenceStatement, got %T", tree.Statements[0])
	}
	if stmt.Options.RestartWith == nil {
		t.Error("expected RestartWith to be set")
	}
}

func TestMariaDB_AlterSequence_RestartBare(t *testing.T) {
	sql := "ALTER SEQUENCE seq_orders RESTART"
	tree, err := parser.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt, ok := tree.Statements[0].(*ast.AlterSequenceStatement)
	if !ok {
		t.Fatalf("expected AlterSequenceStatement, got %T", tree.Statements[0])
	}
	if !stmt.Options.Restart {
		t.Error("expected Restart = true")
	}
	if stmt.Options.RestartWith != nil {
		t.Error("expected RestartWith = nil for bare RESTART")
	}
}

func TestMariaDB_SequenceNotRecognizedInMySQL(t *testing.T) {
	sql := "CREATE SEQUENCE seq1 START WITH 1"
	_, err := parser.ParseWithDialect(sql, keywords.DialectMySQL)
	if err == nil {
		t.Error("expected error when parsing CREATE SEQUENCE in MySQL dialect")
	}
}

// ── Task 8: Temporal Table Tests ──────────────────────────────────────────────

func TestMariaDB_CreateTable_WithSystemVersioning(t *testing.T) {
	sql := "CREATE TABLE orders (id INT PRIMARY KEY, total DECIMAL(10,2)) WITH SYSTEM VERSIONING"
	tree, err := parser.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt, ok := tree.Statements[0].(*ast.CreateTableStatement)
	if !ok {
		t.Fatalf("expected CreateTableStatement, got %T", tree.Statements[0])
	}
	if !stmt.WithSystemVersioning {
		t.Error("expected WithSystemVersioning = true")
	}
}

func TestMariaDB_SelectForSystemTime_AsOf(t *testing.T) {
	sql := "SELECT id FROM orders FOR SYSTEM_TIME AS OF TIMESTAMP '2024-01-15 10:00:00'"
	tree, err := parser.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sel := tree.Statements[0].(*ast.SelectStatement)
	if len(sel.From) == 0 {
		t.Fatal("expected FROM clause")
	}
	ref := &sel.From[0]
	if ref.ForSystemTime == nil {
		t.Error("expected ForSystemTime to be set")
	}
	if ref.ForSystemTime.Type != ast.SystemTimeAsOf {
		t.Errorf("expected AS OF, got %v", ref.ForSystemTime.Type)
	}
}

func TestMariaDB_SelectForSystemTime_All(t *testing.T) {
	sql := "SELECT * FROM orders FOR SYSTEM_TIME ALL"
	tree, err := parser.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sel := tree.Statements[0].(*ast.SelectStatement)
	ref := &sel.From[0]
	if ref.ForSystemTime == nil || ref.ForSystemTime.Type != ast.SystemTimeAll {
		t.Error("expected SystemTimeAll")
	}
}

func TestMariaDB_SelectForSystemTime_Between(t *testing.T) {
	sql := "SELECT * FROM orders FOR SYSTEM_TIME BETWEEN '2020-01-01' AND '2024-01-01'"
	tree, err := parser.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sel := tree.Statements[0].(*ast.SelectStatement)
	ref := &sel.From[0]
	if ref.ForSystemTime == nil || ref.ForSystemTime.Type != ast.SystemTimeBetween {
		t.Error("expected SystemTimeBetween")
	}
}

// ── Task 9: CONNECT BY Tests ──────────────────────────────────────────────────

func TestMariaDB_ConnectBy_Basic(t *testing.T) {
	sql := `SELECT id, name FROM category START WITH parent_id IS NULL CONNECT BY PRIOR id = parent_id`
	tree, err := parser.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	if sel.StartWith == nil {
		t.Error("expected StartWith to be set")
	}
	if sel.ConnectBy == nil {
		t.Error("expected ConnectBy to be set")
	}
	if sel.ConnectBy.NoCycle {
		t.Error("expected NoCycle = false")
	}
}

func TestMariaDB_ConnectBy_NoCycle(t *testing.T) {
	sql := `SELECT id FROM t CONNECT BY NOCYCLE PRIOR id = parent_id`
	tree, err := parser.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sel := tree.Statements[0].(*ast.SelectStatement)
	if sel.ConnectBy == nil || !sel.ConnectBy.NoCycle {
		t.Error("expected NoCycle = true")
	}
}

func TestMariaDB_ConnectBy_NoStartWith(t *testing.T) {
	sql := `SELECT id FROM t CONNECT BY PRIOR id = parent_id`
	tree, err := parser.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sel := tree.Statements[0].(*ast.SelectStatement)
	if sel.ConnectBy == nil {
		t.Error("expected ConnectBy to be set")
	}
}

// TestMariaDB_ConnectBy_PriorOnRight verifies PRIOR on the right-hand side of the condition.
func TestMariaDB_ConnectBy_PriorOnRight(t *testing.T) {
	sql := "SELECT id FROM employees CONNECT BY id = PRIOR parent_id"
	tree, err := parser.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement")
	}
	if sel.ConnectBy == nil {
		t.Fatal("expected ConnectBy clause")
	}
	bin, ok := sel.ConnectBy.Condition.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected BinaryExpression, got %T", sel.ConnectBy.Condition)
	}
	// Right side should be PRIOR parent_id
	unary, ok := bin.Right.(*ast.UnaryExpression)
	if !ok {
		t.Fatalf("expected UnaryExpression on right, got %T", bin.Right)
	}
	if unary.Operator != ast.Prior {
		t.Errorf("expected Prior operator, got %v", unary.Operator)
	}
}

// TestMariaDB_DropSequence_IfNotExists verifies DROP SEQUENCE IF NOT EXISTS is accepted.
func TestMariaDB_DropSequence_IfNotExists(t *testing.T) {
	sql := "DROP SEQUENCE IF NOT EXISTS my_seq"
	tree, err := parser.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	stmt, ok := tree.Statements[0].(*ast.DropSequenceStatement)
	if !ok {
		t.Fatalf("expected DropSequenceStatement, got %T", tree.Statements[0])
	}
	if !stmt.IfExists {
		t.Error("expected IfExists=true")
	}
	if stmt.Name == nil || stmt.Name.Name != "my_seq" {
		t.Errorf("expected name my_seq, got %v", stmt.Name)
	}
}

// TestMariaDB_Sequence_NoCache verifies NOCACHE sets the NoCache field.
func TestMariaDB_Sequence_NoCache(t *testing.T) {
	sql := "CREATE SEQUENCE s NOCACHE"
	tree, err := parser.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	stmt, ok := tree.Statements[0].(*ast.CreateSequenceStatement)
	if !ok {
		t.Fatalf("expected CreateSequenceStatement")
	}
	if !stmt.Options.NoCache {
		t.Error("expected NoCache=true")
	}
}

// ── Task 10: File-based Integration Tests ─────────────────────────────────────

func TestMariaDB_SQLFiles(t *testing.T) {
	files := []string{
		"testdata/mariadb/sequences.sql",
		"testdata/mariadb/temporal.sql",
		"testdata/mariadb/connect_by.sql",
		"testdata/mariadb/mixed.sql",
	}
	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatalf("failed to read %s: %v", f, err)
			}
			// Split on semicolons to get individual statements
			stmts := strings.Split(string(data), ";")
			for _, raw := range stmts {
				sql := strings.TrimSpace(raw)
				if sql == "" {
					continue
				}
				_, err := parser.ParseWithDialect(sql, keywords.DialectMariaDB)
				if err != nil {
					t.Errorf("failed to parse %q: %v", sql, err)
				}
			}
		})
	}
}

func TestMariaDB_CreateTable_PeriodForSystemTime(t *testing.T) {
	sql := `CREATE TABLE t (
		id INT,
		row_start DATETIME(6) GENERATED ALWAYS AS ROW START,
		row_end   DATETIME(6) GENERATED ALWAYS AS ROW END,
		PERIOD FOR SYSTEM_TIME(row_start, row_end)
	) WITH SYSTEM VERSIONING`
	tree, err := parser.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}
	stmt, ok := tree.Statements[0].(*ast.CreateTableStatement)
	if !ok {
		t.Fatalf("expected CreateTableStatement, got %T", tree.Statements[0])
	}
	if len(stmt.PeriodDefinitions) == 0 {
		t.Fatal("expected at least one PeriodDefinition")
	}
	pd := stmt.PeriodDefinitions[0]
	if pd.Name == nil || !strings.EqualFold(pd.Name.Name, "SYSTEM_TIME") {
		t.Errorf("expected period name SYSTEM_TIME, got %v", pd.Name)
	}
	if pd.StartCol == nil || pd.StartCol.Name != "row_start" {
		t.Errorf("expected StartCol=row_start, got %v", pd.StartCol)
	}
	if pd.EndCol == nil || pd.EndCol.Name != "row_end" {
		t.Errorf("expected EndCol=row_end, got %v", pd.EndCol)
	}
	if !stmt.WithSystemVersioning {
		t.Error("expected WithSystemVersioning = true")
	}
}
