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

func TestAddJoin_InvalidType(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt, AddJoin("LATERAL", "orders", nil))
	if err == nil {
		t.Fatal("expected error for invalid join type")
	}
}
