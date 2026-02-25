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

func TestRemoveColumn_Nonexistent(t *testing.T) {
	stmt := mustParse(t, "SELECT id, name FROM users")
	err := Apply(stmt, RemoveColumn("nonexistent"))
	if err == nil {
		t.Fatal("expected error for nonexistent column")
	}
	if err.Error() != `column "nonexistent" not found` {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRemoveColumn_SingleColumn(t *testing.T) {
	stmt := mustParse(t, "SELECT id, name FROM users")
	err := Apply(stmt, RemoveColumn("id"))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertNotContains(t, out, "id")
	assertContains(t, out, "name")
}

func TestColumns_UnsupportedStatement(t *testing.T) {
	stmt := mustParse(t, "UPDATE users SET name = 'bob'")
	err := Apply(stmt, AddColumn(&ast.Identifier{Name: "x"}))
	if err == nil {
		t.Fatal("expected error for UPDATE")
	}
}
