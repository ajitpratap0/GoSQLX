package transform

import (
	"testing"
)

func TestReplaceTable(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users WHERE users.active = true")
	err := Apply(stmt, ReplaceTable("users", "accounts"))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "accounts")
	assertNotContains(t, out, "users")
}

func TestReplaceTable_Update(t *testing.T) {
	stmt := mustParse(t, "UPDATE users SET name = 'bob' WHERE id = 1")
	err := Apply(stmt, ReplaceTable("users", "accounts"))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "accounts")
}

func TestReplaceTable_Delete(t *testing.T) {
	stmt := mustParse(t, "DELETE FROM users WHERE id = 1")
	err := Apply(stmt, ReplaceTable("users", "accounts"))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "accounts")
}

func TestAddTableAlias(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt, AddTableAlias("users", "u"))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "u")
}

func TestQualifyColumns(t *testing.T) {
	stmt := mustParse(t, "SELECT id, name FROM users")
	err := Apply(stmt, QualifyColumns("users"))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "users.id")
	assertContains(t, out, "users.name")
}

func TestReplaceTable_SubqueryInWhere(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users WHERE users.id IN (SELECT user_id FROM orders WHERE orders.active = true)")
	err := Apply(stmt, ReplaceTable("orders", "purchases"))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "purchases")
	assertNotContains(t, out, "orders")
}

func TestReplaceTable_InSubquery(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users WHERE EXISTS (SELECT 1 FROM orders WHERE orders.user_id = users.id)")
	err := Apply(stmt, ReplaceTable("orders", "purchases"))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "purchases")
	assertNotContains(t, out, "orders")
}

func TestQualifyColumns_NestedExpressions(t *testing.T) {
	stmt := mustParse(t, "SELECT COALESCE(name, email) FROM users WHERE active = true")
	err := Apply(stmt, QualifyColumns("users"))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "users.name")
	assertContains(t, out, "users.email")
	assertContains(t, out, "users.active")
}

func TestReplaceTable_UnsupportedStatement(t *testing.T) {
	stmt := mustParse(t, "INSERT INTO users (name) VALUES ('bob')")
	err := Apply(stmt, ReplaceTable("users", "accounts"))
	if err == nil {
		t.Fatal("expected error for INSERT")
	}
}
