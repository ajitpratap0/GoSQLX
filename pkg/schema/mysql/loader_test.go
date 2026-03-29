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

package mysql_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	myschema "github.com/ajitpratap0/GoSQLX/pkg/schema/mysql"
)

func startMySQL(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "mysql:8.0",
		ExposedPorts: []string{"3306/tcp"},
		Env: map[string]string{
			"MYSQL_ROOT_PASSWORD": "root",
			"MYSQL_DATABASE":      "testdb",
		},
		WaitingFor: wait.ForLog("port: 3306  MySQL Community Server"),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })

	host, _ := c.Host(ctx)
	port, _ := c.MappedPort(ctx, "3306")
	dsn := fmt.Sprintf("root:root@tcp(%s:%s)/testdb", host, port.Port())
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	_, err = db.Exec(`
		CREATE TABLE products (
			id   INT AUTO_INCREMENT PRIMARY KEY,
			sku  VARCHAR(100) NOT NULL UNIQUE,
			price DECIMAL(10,2)
		)
	`)
	if err != nil {
		t.Fatalf("create products table: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE line_items (
			id         INT AUTO_INCREMENT PRIMARY KEY,
			product_id INT NOT NULL,
			qty        INT DEFAULT 1,
			FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE RESTRICT
		)
	`)
	if err != nil {
		t.Fatalf("create line_items table: %v", err)
	}
	return db
}

func TestMySQLLoader_Load(t *testing.T) {
	db := startMySQL(t)
	loader := myschema.NewLoader()
	s, err := loader.Load(db, "testdb")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.Name != "testdb" {
		t.Errorf("schema name: got %q want testdb", s.Name)
	}
	names := make(map[string]bool)
	for _, tbl := range s.Tables {
		names[tbl.Name] = true
	}
	if !names["products"] || !names["line_items"] {
		t.Errorf("missing tables in schema: %v", names)
	}
}

func TestMySQLLoader_LoadTable_Columns(t *testing.T) {
	db := startMySQL(t)
	loader := myschema.NewLoader()
	tbl, err := loader.LoadTable(db, "testdb", "products")
	if err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if len(tbl.Columns) != 3 {
		t.Errorf("columns: got %d want 3", len(tbl.Columns))
	}
	var found bool
	for i := range tbl.Columns {
		if tbl.Columns[i].Name == "id" {
			if !tbl.Columns[i].IsPrimary {
				t.Error("expected id to be primary key")
			}
			found = true
		}
	}
	if !found {
		t.Error("id column not found")
	}
}

func TestMySQLLoader_LoadTable_ForeignKeys(t *testing.T) {
	db := startMySQL(t)
	loader := myschema.NewLoader()
	tbl, err := loader.LoadTable(db, "testdb", "line_items")
	if err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if len(tbl.ForeignKeys) != 1 {
		t.Fatalf("foreign keys: got %d want 1", len(tbl.ForeignKeys))
	}
	if tbl.ForeignKeys[0].RefTable != "products" {
		t.Errorf("fk ref table: got %q want products", tbl.ForeignKeys[0].RefTable)
	}
}
