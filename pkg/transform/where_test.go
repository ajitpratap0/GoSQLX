package transform

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func mustParse(t *testing.T, sql string) ast.Statement {
	t.Helper()
	tree, err := ParseSQL(sql)
	if err != nil {
		t.Fatalf("parse %q: %v", sql, err)
	}
	if len(tree.Statements) == 0 {
		t.Fatalf("no statements from %q", sql)
	}
	return tree.Statements[0]
}

func format(stmt ast.Statement) string {
	return FormatSQL(stmt)
}

func assertContains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(strings.ToUpper(got), strings.ToUpper(want)) {
		t.Errorf("expected output to contain %q, got: %s", want, got)
	}
}

func assertNotContains(t *testing.T, got, want string) {
	t.Helper()
	if strings.Contains(strings.ToUpper(got), strings.ToUpper(want)) {
		t.Errorf("expected output NOT to contain %q, got: %s", want, got)
	}
}

func TestAddWhere_NewCondition(t *testing.T) {
	stmt := mustParse(t, "SELECT id, name FROM users")
	err := Apply(stmt, AddWhereFromSQL("active = true"))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "WHERE")
	assertContains(t, out, "active")
}

func TestAddWhere_ExistingCondition(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users WHERE age > 18")
	err := Apply(stmt, AddWhereFromSQL("status = 'active'"))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "AND")
	assertContains(t, out, "status")
	assertContains(t, out, "age")
}

func TestAddWhere_UpdateStatement(t *testing.T) {
	stmt := mustParse(t, "UPDATE users SET name = 'bob'")
	err := Apply(stmt, AddWhereFromSQL("id = 1"))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "WHERE")
	assertContains(t, out, "id")
}

func TestAddWhere_DeleteStatement(t *testing.T) {
	stmt := mustParse(t, "DELETE FROM users")
	err := Apply(stmt, AddWhereFromSQL("id = 1"))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "WHERE")
}

func TestRemoveWhere(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users WHERE active = true")
	err := Apply(stmt, RemoveWhere())
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertNotContains(t, out, "WHERE")
}

func TestReplaceWhere(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users WHERE active = true")
	cond := &ast.BinaryExpression{
		Left:     &ast.Identifier{Name: "id"},
		Operator: "=",
		Right:    &ast.LiteralValue{Value: 42, Type: "INTEGER"},
	}
	err := Apply(stmt, ReplaceWhere(cond))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "id")
	assertContains(t, out, "42")
	assertNotContains(t, out, "active")
}

func TestAddWhere_UnsupportedStatement(t *testing.T) {
	stmt := mustParse(t, "INSERT INTO users (name) VALUES ('bob')")
	err := Apply(stmt, AddWhereFromSQL("id = 1"))
	if err == nil {
		t.Fatal("expected error for INSERT statement")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAddWhere_DirectExpression(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")
	cond := &ast.BinaryExpression{
		Left:     &ast.Identifier{Name: "status"},
		Operator: "=",
		Right:    &ast.LiteralValue{Value: "active", Type: "STRING"},
	}
	err := Apply(stmt, AddWhere(cond))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "WHERE")
	assertContains(t, out, "status")
}
