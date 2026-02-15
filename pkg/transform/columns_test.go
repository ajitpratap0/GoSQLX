package transform

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestAddColumn(t *testing.T) {
	stmt := mustParse(t, "SELECT id FROM users")
	err := Apply(stmt, AddColumn(&ast.Identifier{Name: "email"}))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "email")
	assertContains(t, out, "id")
}

func TestRemoveColumn(t *testing.T) {
	stmt := mustParse(t, "SELECT id, name, email FROM users")
	err := Apply(stmt, RemoveColumn("name"))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertNotContains(t, out, "name")
	assertContains(t, out, "id")
	assertContains(t, out, "email")
}

func TestReplaceColumn(t *testing.T) {
	stmt := mustParse(t, "SELECT id, name FROM users")
	err := Apply(stmt, ReplaceColumn("name", "full_name"))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "full_name")
	assertNotContains(t, out, " name")
}

func TestAddSelectStar(t *testing.T) {
	stmt := mustParse(t, "SELECT id FROM users")
	err := Apply(stmt, AddSelectStar())
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "*")
}

func TestColumns_UnsupportedStatement(t *testing.T) {
	stmt := mustParse(t, "UPDATE users SET name = 'bob'")
	err := Apply(stmt, AddColumn(&ast.Identifier{Name: "x"}))
	if err == nil {
		t.Fatal("expected error for UPDATE")
	}
}
