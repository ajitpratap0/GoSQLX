package transform

import (
	"testing"
)

func TestAddOrderBy(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt, AddOrderBy("created_at", true))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "ORDER BY")
	assertContains(t, out, "created_at")
	assertContains(t, out, "DESC")
}

func TestAddOrderBy_Ascending(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt, AddOrderBy("name", false))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "ORDER BY")
	assertContains(t, out, "name")
}

func TestRemoveOrderBy(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users ORDER BY name ASC")
	err := Apply(stmt, RemoveOrderBy())
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertNotContains(t, out, "ORDER BY")
}

func TestAddOrderBy_Multiple(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt,
		AddOrderBy("last_name", false),
		AddOrderBy("first_name", false),
	)
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "last_name")
	assertContains(t, out, "first_name")
}

func TestOrderBy_UnsupportedStatement(t *testing.T) {
	stmt := mustParse(t, "DELETE FROM users")
	err := Apply(stmt, AddOrderBy("id", false))
	if err == nil {
		t.Fatal("expected error for DELETE")
	}
}

// Test composability: chain multiple transforms
func TestComposability(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt,
		AddWhereFromSQL("active = true"),
		SetLimit(10),
		SetOffset(20),
		AddOrderBy("created_at", true),
	)
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "WHERE")
	assertContains(t, out, "LIMIT")
	assertContains(t, out, "OFFSET")
	assertContains(t, out, "ORDER BY")
}
