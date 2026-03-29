// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transform

import (
	"testing"
)

func TestAddSetClause_Basic(t *testing.T) {
	stmt := mustParse(t, "UPDATE users SET name = 'old'")

	err := Apply(stmt, AddSetClause("status", "'active'"))
	if err != nil {
		t.Fatalf("AddSetClause: %v", err)
	}

	out := format(stmt)
	assertContains(t, out, "status")
	assertContains(t, out, "active")
}

func TestAddSetClause_ReplacesExisting(t *testing.T) {
	stmt := mustParse(t, "UPDATE users SET name = 'old', status = 'inactive'")

	err := Apply(stmt, AddSetClause("name", "'new'"))
	if err != nil {
		t.Fatalf("AddSetClause: %v", err)
	}

	out := format(stmt)
	assertContains(t, out, "new")
	assertNotContains(t, out, "old")
	// status should still be present
	assertContains(t, out, "status")
}

func TestSetClause_ReplaceExisting(t *testing.T) {
	stmt := mustParse(t, "UPDATE users SET name = 'old', status = 'active'")

	err := Apply(stmt, SetClause("name", "'new'"))
	if err != nil {
		t.Fatalf("SetClause: %v", err)
	}

	out := format(stmt)
	assertContains(t, out, "new")
	assertNotContains(t, out, "old")
}

func TestRemoveSetClause_RemovesColumn(t *testing.T) {
	stmt := mustParse(t, "UPDATE users SET name = 'alice', status = 'active', age = 30")

	err := Apply(stmt, RemoveSetClause("status"))
	if err != nil {
		t.Fatalf("RemoveSetClause: %v", err)
	}

	out := format(stmt)
	assertNotContains(t, out, "status")
	assertContains(t, out, "name")
	assertContains(t, out, "age")
}

func TestRemoveSetClause_NonExistentColumn_NoError(t *testing.T) {
	stmt := mustParse(t, "UPDATE users SET name = 'alice'")

	err := Apply(stmt, RemoveSetClause("nonexistent"))
	if err != nil {
		t.Fatalf("RemoveSetClause on nonexistent column should not error: %v", err)
	}

	out := format(stmt)
	assertContains(t, out, "name")
}

func TestReplaceSetClause_ReplacesAll(t *testing.T) {
	stmt := mustParse(t, "UPDATE users SET name = 'old', status = 'x'")

	err := Apply(stmt, ReplaceSetClause(map[string]string{
		"email": "'user@example.com'",
	}))
	if err != nil {
		t.Fatalf("ReplaceSetClause: %v", err)
	}

	out := format(stmt)
	assertNotContains(t, out, "name")
	assertNotContains(t, out, "status")
	assertContains(t, out, "email")
}

func TestReplaceSetClause_MultipleColumns(t *testing.T) {
	stmt := mustParse(t, "UPDATE orders SET status = 'pending'")

	err := Apply(stmt, ReplaceSetClause(map[string]string{
		"status":     "'shipped'",
		"updated_at": "NOW()",
	}))
	if err != nil {
		t.Fatalf("ReplaceSetClause: %v", err)
	}

	out := format(stmt)
	assertContains(t, out, "status")
	assertContains(t, out, "shipped")
}

func TestAddSetClause_OnNonUpdate_ReturnsError(t *testing.T) {
	stmt := mustParse(t, "DELETE FROM users WHERE id = 1")

	err := Apply(stmt, AddSetClause("name", "'x'"))
	if err == nil {
		t.Error("expected error applying AddSetClause to DELETE statement")
	}
}

func TestRemoveSetClause_OnNonUpdate_ReturnsError(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")

	err := Apply(stmt, RemoveSetClause("name"))
	if err == nil {
		t.Error("expected error applying RemoveSetClause to SELECT statement")
	}
}

func TestReplaceSetClause_OnNonUpdate_ReturnsError(t *testing.T) {
	stmt := mustParse(t, "INSERT INTO users (name) VALUES ('bob')")

	err := Apply(stmt, ReplaceSetClause(map[string]string{"name": "'x'"}))
	if err == nil {
		t.Error("expected error applying ReplaceSetClause to INSERT statement")
	}
}

func TestAddSetClause_CaseInsensitiveColumn(t *testing.T) {
	stmt := mustParse(t, "UPDATE users SET Name = 'old'")

	err := Apply(stmt, AddSetClause("name", "'new'"))
	if err != nil {
		t.Fatalf("AddSetClause: %v", err)
	}

	out := format(stmt)
	assertContains(t, out, "new")
	assertNotContains(t, out, "old")
}

func TestAddSetClause_WithNumericValue(t *testing.T) {
	stmt := mustParse(t, "UPDATE counters SET total = 0")

	err := Apply(stmt, AddSetClause("total", "42"))
	if err != nil {
		t.Fatalf("AddSetClause with numeric: %v", err)
	}

	out := format(stmt)
	assertContains(t, out, "42")
}
