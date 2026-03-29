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

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestConnectBy_Oracle_Basic tests basic Oracle CONNECT BY syntax.
func TestConnectBy_Oracle_Basic(t *testing.T) {
	sql := `SELECT employee_id, manager_id, name
	        FROM employees
	        START WITH manager_id IS NULL
	        CONNECT BY PRIOR employee_id = manager_id`
	tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectOracle)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	if sel.ConnectBy == nil {
		t.Error("expected ConnectBy clause to be populated")
	}
	if sel.StartWith == nil {
		t.Error("expected StartWith expression to be populated")
	}
}

// TestConnectBy_Oracle_NoCycle tests Oracle CONNECT BY with NOCYCLE modifier.
func TestConnectBy_Oracle_NoCycle(t *testing.T) {
	sql := `SELECT id, parent_id FROM categories
	        START WITH parent_id IS NULL
	        CONNECT BY NOCYCLE PRIOR id = parent_id`
	tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectOracle)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	if sel.ConnectBy == nil {
		t.Fatal("expected ConnectBy")
	}
	if !sel.ConnectBy.NoCycle {
		t.Error("expected NoCycle = true")
	}
}

// TestConnectBy_Oracle_ConnectByOnly tests CONNECT BY without START WITH.
func TestConnectBy_Oracle_ConnectByOnly(t *testing.T) {
	sql := `SELECT id, parent_id FROM categories
	        CONNECT BY PRIOR id = parent_id`
	tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectOracle)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	if sel.ConnectBy == nil {
		t.Error("expected ConnectBy clause")
	}
	if sel.StartWith != nil {
		t.Error("expected StartWith to be nil when not specified")
	}
}

// TestConnectBy_MariaDB_StillWorks ensures existing MariaDB CONNECT BY parsing remains intact.
func TestConnectBy_MariaDB_StillWorks(t *testing.T) {
	sql := `SELECT id, parent_id FROM categories
	        START WITH parent_id IS NULL
	        CONNECT BY PRIOR id = parent_id`
	tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	if sel.ConnectBy == nil {
		t.Error("expected ConnectBy clause")
	}
	if sel.StartWith == nil {
		t.Error("expected StartWith expression")
	}
}
