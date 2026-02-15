package transform

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestAddJoin(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")
	cond := &ast.BinaryExpression{
		Left:     &ast.Identifier{Name: "id", Table: "orders"},
		Operator: "=",
		Right:    &ast.Identifier{Name: "user_id", Table: "users"},
	}
	err := Apply(stmt, AddJoin("LEFT", "orders", cond))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "LEFT JOIN")
	assertContains(t, out, "orders")
}

func TestRemoveJoin(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users INNER JOIN orders ON orders.user_id = users.id")
	err := Apply(stmt, RemoveJoin("orders"))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertNotContains(t, out, "JOIN")
	assertNotContains(t, out, "orders")
}

func TestAddJoinFromSQL(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt, AddJoinFromSQL("LEFT JOIN orders ON orders.user_id = users.id"))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "LEFT JOIN")
	assertContains(t, out, "orders")
}

func TestJoin_UnsupportedStatement(t *testing.T) {
	stmt := mustParse(t, "DELETE FROM users")
	err := Apply(stmt, AddJoin("LEFT", "orders", nil))
	if err == nil {
		t.Fatal("expected error for DELETE")
	}
}
