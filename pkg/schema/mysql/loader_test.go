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
	"os/exec"
	"reflect"
	"runtime"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	dbschema "github.com/ajitpratap0/GoSQLX/pkg/schema/db"
	myschema "github.com/ajitpratap0/GoSQLX/pkg/schema/mysql"
)

// isDockerAvailable checks whether the Docker daemon is reachable.
// Returns false on macOS CI runners that have no Docker installed.
func isDockerAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "info")
	return cmd.Run() == nil
}

func startMySQL(t *testing.T) *sql.DB {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping testcontainers test in -short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("Testcontainers not supported on Windows CI")
	}
	if !isDockerAvailable() {
		t.Skip("Docker not available, skipping integration test")
	}
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

	// Recover from testcontainers panics (e.g. rootless Docker on Windows).
	var c testcontainers.Container
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Skipf("testcontainers panicked: %v", r)
			}
		}()
		c, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
	}()
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

	// Wait for MySQL to be fully ready to accept queries.
	for i := 0; i < 30; i++ {
		if err := db.PingContext(ctx); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping db after retries: %v", err)
	}

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
	assertMySQLDetail(t, s)
}

func findTable(s *dbschema.DatabaseSchema, name string) *dbschema.Table {
	for i := range s.Tables {
		if s.Tables[i].Name == name {
			return &s.Tables[i]
		}
	}
	return nil
}

// assertMySQLDetail checks per-table columns, key flags, indexes and foreign
// keys of the fixture loaded via Load.
func assertMySQLDetail(t *testing.T, s *dbschema.DatabaseSchema) {
	t.Helper()
	products := findTable(s, "products")
	lineItems := findTable(s, "line_items")
	if products == nil || lineItems == nil {
		t.Fatalf("missing products/line_items tables: %+v", s.Tables)
	}
	if len(products.Columns) != 3 {
		t.Fatalf("products columns: got %d want 3", len(products.Columns))
	}
	for _, c := range products.Columns {
		switch c.Name {
		case "id":
			if !c.IsPrimary {
				t.Error("products.id: expected primary key")
			}
		case "sku":
			if !c.IsUnique {
				t.Error("products.sku: expected unique")
			}
		}
	}
	if len(lineItems.Columns) != 3 {
		t.Errorf("line_items columns: got %d want 3", len(lineItems.Columns))
	}
	if len(lineItems.ForeignKeys) != 1 {
		t.Fatalf("line_items foreign keys: got %d want 1", len(lineItems.ForeignKeys))
	}
	fk := lineItems.ForeignKeys[0]
	if fk.RefTable != "products" || fk.OnDelete != "RESTRICT" ||
		!reflect.DeepEqual(fk.Columns, []string{"product_id"}) ||
		!reflect.DeepEqual(fk.RefColumns, []string{"id"}) {
		t.Errorf("line_items fk: got %+v", fk)
	}
	if len(products.Indexes) == 0 {
		t.Error("products: expected indexes")
	}
	for _, idx := range products.Indexes {
		if len(idx.Columns) == 0 || idx.TableName != "products" {
			t.Errorf("products index: got %+v", idx)
		}
	}
}

func TestMySQLLoader_Load_MaxOpenConns1(t *testing.T) {
	db := startMySQL(t)
	db.SetMaxOpenConns(1)
	type result struct {
		s   *dbschema.DatabaseSchema
		err error
	}
	done := make(chan result, 1)
	go func() {
		s, err := myschema.NewLoader().Load(db, "testdb")
		done <- result{s, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Load: %v", r.err)
		}
		assertMySQLDetail(t, r.s)
	case <-time.After(30 * time.Second):
		t.Fatal("Load deadlocked with MaxOpenConns=1")
	}
}

func TestMySQLLoader_LoadMatchesLoadTable(t *testing.T) {
	db := startMySQL(t)
	loader := myschema.NewLoader()
	s, err := loader.Load(db, "testdb")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(s.Tables) == 0 {
		t.Fatal("Load returned no tables")
	}
	for i := range s.Tables {
		want := s.Tables[i]
		got, err := loader.LoadTable(db, "testdb", want.Name)
		if err != nil {
			t.Fatalf("LoadTable(%q): %v", want.Name, err)
		}
		if !reflect.DeepEqual(*got, want) {
			t.Errorf("LoadTable(%q) differs from Load:\n got: %+v\nwant: %+v", want.Name, *got, want)
		}
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

// The name is validated before any query, so no database is needed.
func TestMySQLLoader_LoadTable_EmptyName(t *testing.T) {
	if _, err := myschema.NewLoader().LoadTable(nil, "db", ""); err == nil {
		t.Fatal("expected error for empty table name")
	}
}
