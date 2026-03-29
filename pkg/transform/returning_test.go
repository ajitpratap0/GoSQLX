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

func TestAddReturning_OnInsert(t *testing.T) {
	stmt := mustParse(t, "INSERT INTO users (name) VALUES ('alice')")

	err := Apply(stmt, AddReturning("id"))
	if err != nil {
		t.Fatalf("AddReturning on INSERT: %v", err)
	}

	out := format(stmt)
	assertContains(t, out, "RETURNING")
	assertContains(t, out, "id")
}

func TestAddReturning_OnUpdate(t *testing.T) {
	stmt := mustParse(t, "UPDATE users SET status = 'active' WHERE id = 1")

	err := Apply(stmt, AddReturning("id", "updated_at"))
	if err != nil {
		t.Fatalf("AddReturning on UPDATE: %v", err)
	}

	out := format(stmt)
	assertContains(t, out, "RETURNING")
	assertContains(t, out, "id")
	assertContains(t, out, "updated_at")
}

func TestAddReturning_OnDelete(t *testing.T) {
	stmt := mustParse(t, "DELETE FROM users WHERE id = 1")

	err := Apply(stmt, AddReturning("id"))
	if err != nil {
		t.Fatalf("AddReturning on DELETE: %v", err)
	}

	out := format(stmt)
	assertContains(t, out, "RETURNING")
	assertContains(t, out, "id")
}

func TestAddReturning_MultipleColumns(t *testing.T) {
	stmt := mustParse(t, "INSERT INTO orders (product_id, qty) VALUES (1, 5)")

	err := Apply(stmt, AddReturning("id", "created_at", "total"))
	if err != nil {
		t.Fatalf("AddReturning multiple columns: %v", err)
	}

	out := format(stmt)
	assertContains(t, out, "RETURNING")
	assertContains(t, out, "id")
	assertContains(t, out, "created_at")
	assertContains(t, out, "total")
}

func TestAddReturning_AppendsToPreviousReturning(t *testing.T) {
	stmt := mustParse(t, "INSERT INTO users (name) VALUES ('alice')")

	// Add returning in two steps
	_ = Apply(stmt, AddReturning("id"))
	err := Apply(stmt, AddReturning("created_at"))
	if err != nil {
		t.Fatalf("second AddReturning: %v", err)
	}

	out := format(stmt)
	assertContains(t, out, "id")
	assertContains(t, out, "created_at")
}

func TestRemoveReturning_RemovesClause(t *testing.T) {
	stmt := mustParse(t, "DELETE FROM users WHERE id = 1")

	_ = Apply(stmt, AddReturning("id"))
	err := Apply(stmt, RemoveReturning())
	if err != nil {
		t.Fatalf("RemoveReturning: %v", err)
	}

	out := format(stmt)
	assertNotContains(t, out, "RETURNING")
}

func TestRemoveReturning_OnUpdate(t *testing.T) {
	stmt := mustParse(t, "UPDATE users SET status = 'active'")

	_ = Apply(stmt, AddReturning("id", "status"))
	err := Apply(stmt, RemoveReturning())
	if err != nil {
		t.Fatalf("RemoveReturning on UPDATE: %v", err)
	}

	out := format(stmt)
	assertNotContains(t, out, "RETURNING")
}

func TestRemoveReturning_WhenAlreadyEmpty_NoError(t *testing.T) {
	stmt := mustParse(t, "DELETE FROM users WHERE active = false")

	err := Apply(stmt, RemoveReturning())
	if err != nil {
		t.Fatalf("RemoveReturning on empty clause should not error: %v", err)
	}
}

func TestAddReturning_OnSelect_ReturnsError(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")

	err := Apply(stmt, AddReturning("id"))
	if err == nil {
		t.Error("expected error applying AddReturning to SELECT statement")
	}
}

func TestRemoveReturning_OnSelect_ReturnsError(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")

	err := Apply(stmt, RemoveReturning())
	if err == nil {
		t.Error("expected error applying RemoveReturning to SELECT statement")
	}
}
