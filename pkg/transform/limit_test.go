package transform

import (
	"testing"
)

func TestSetLimit(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt, SetLimit(10))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "LIMIT")
	assertContains(t, out, "10")
}

func TestSetOffset(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt, SetOffset(20))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "OFFSET")
	assertContains(t, out, "20")
}

func TestRemoveLimit(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users LIMIT 10")
	err := Apply(stmt, RemoveLimit())
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertNotContains(t, out, "LIMIT")
}

func TestRemoveOffset(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users LIMIT 10 OFFSET 5")
	err := Apply(stmt, RemoveOffset())
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertNotContains(t, out, "OFFSET")
}

func TestSetLimit_ReplaceExisting(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users LIMIT 5")
	err := Apply(stmt, SetLimit(100))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "100")
}

func TestLimit_UnsupportedStatement(t *testing.T) {
	stmt := mustParse(t, "DELETE FROM users")
	err := Apply(stmt, SetLimit(10))
	if err == nil {
		t.Fatal("expected error for DELETE")
	}
}

func TestSetLimit_Negative(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt, SetLimit(-1))
	if err == nil {
		t.Fatal("expected error for negative limit")
	}
}

func TestSetLimit_NegativeLarge(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt, SetLimit(-100))
	if err == nil {
		t.Fatal("expected error for negative limit")
	}
}

func TestSetLimit_Zero(t *testing.T) {
	// LIMIT 0 is valid SQL — returns an empty result set.
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt, SetLimit(0))
	if err != nil {
		t.Fatalf("SetLimit(0) should succeed: %v", err)
	}
	out := format(stmt)
	assertContains(t, out, "LIMIT")
	assertContains(t, out, "0")
}

func TestSetOffset_Zero(t *testing.T) {
	// OFFSET 0 is valid SQL — no offset applied.
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt, SetOffset(0))
	if err != nil {
		t.Fatalf("SetOffset(0) should succeed: %v", err)
	}
	out := format(stmt)
	assertContains(t, out, "OFFSET")
	assertContains(t, out, "0")
}

func TestSetOffset_Negative(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt, SetOffset(-5))
	if err == nil {
		t.Fatal("expected error for negative offset")
	}
}
