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

// startMySQL starts a MySQL 8.0 container loaded with the shared fixture.
func startMySQL(t *testing.T) *sql.DB {
	t.Helper()
	return startMySQLImage(t, "mysql:8.0", map[string]string{
		"MYSQL_ROOT_PASSWORD": "root",
		"MYSQL_DATABASE":      "testdb",
	}, wait.ForLog("port: 3306  MySQL Community Server"))
}

// startMariaDB starts a MariaDB container loaded with the same fixture. The
// loader targets the MySQL information_schema layout, which MariaDB shares.
func startMariaDB(t *testing.T) *sql.DB {
	t.Helper()
	// The init-phase temporary server logs "port: 0", so this matches only the
	// real server.
	return startMySQLImage(t, "mariadb:11.4", map[string]string{
		"MARIADB_ROOT_PASSWORD": "root",
		"MARIADB_DATABASE":      "testdb",
	}, wait.ForLog("port: 3306  mariadb.org binary distribution"))
}

// startMySQLImage starts a MySQL-protocol container from image and loads the
// shared fixture into its testdb database.
func startMySQLImage(t *testing.T, image string, env map[string]string, waitFor wait.Strategy) *sql.DB {
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
	// Bound the container start by the test binary's deadline. A slow image
	// pull or server init on CI otherwise runs into the -timeout panic, which
	// fails the whole package instead of skipping this integration test.
	startCtx := ctx
	if deadline, ok := t.Deadline(); ok {
		var cancel context.CancelFunc
		startCtx, cancel = context.WithDeadline(ctx, deadline.Add(-30*time.Second))
		defer cancel()
	}
	req := testcontainers.ContainerRequest{
		Image:        image,
		ExposedPorts: []string{"3306/tcp"},
		Env:          env,
		WaitingFor:   waitFor,
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
		c, err = testcontainers.GenericContainer(startCtx, testcontainers.GenericContainerRequest{
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
	// Composite FK: the referenced columns must lead an index in the same
	// order (InnoDB), hence the extra UNIQUE KEY (code, region).
	_, err = db.Exec(`
		CREATE TABLE warehouses (
			region VARCHAR(10) NOT NULL,
			code   INT NOT NULL,
			PRIMARY KEY (region, code),
			UNIQUE KEY uq_wh_code_region (code, region)
		)
	`)
	if err != nil {
		t.Fatalf("create warehouses table: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE bins (
			id         INT AUTO_INCREMENT PRIMARY KEY,
			wh_code    INT NOT NULL,
			wh_region  VARCHAR(10) NOT NULL,
			CONSTRAINT fk_bins_wh FOREIGN KEY (wh_code, wh_region)
				REFERENCES warehouses (code, region) ON DELETE CASCADE ON UPDATE CASCADE
		)
	`)
	if err != nil {
		t.Fatalf("create bins table: %v", err)
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
	assertLoadMatchesLoadTable(t, startMySQL(t))
}

// assertLoadMatchesLoadTable checks that LoadTable returns, for every table,
// exactly what Load reports for it.
func assertLoadMatchesLoadTable(t *testing.T, db *sql.DB) {
	t.Helper()
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

// TestMySQLLoader_CompositeForeignKey is a regression test for #579: a
// composite foreign key pairs local and referenced columns by position and
// carries its own ON DELETE/ON UPDATE rules.
func TestMySQLLoader_CompositeForeignKey(t *testing.T) {
	assertCompositeForeignKey(t, startMySQL(t))
}

// assertCompositeForeignKey checks the composite foreign key of the fixture.
func assertCompositeForeignKey(t *testing.T, db *sql.DB) {
	t.Helper()
	loader := myschema.NewLoader()
	want := []dbschema.ForeignKey{{
		Name: "fk_bins_wh", TableName: "bins",
		Columns: []string{"wh_code", "wh_region"}, RefTable: "warehouses",
		RefColumns: []string{"code", "region"},
		OnDelete:   "CASCADE", OnUpdate: "CASCADE",
	}}

	s, err := loader.Load(db, "testdb")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	var bins *dbschema.Table
	for i := range s.Tables {
		if s.Tables[i].Name == "bins" {
			bins = &s.Tables[i]
		}
	}
	if bins == nil {
		t.Fatal("Load: table bins missing")
	}
	if !reflect.DeepEqual(bins.ForeignKeys, want) {
		t.Errorf("Load bins foreign keys:\n got: %+v\nwant: %+v", bins.ForeignKeys, want)
	}

	one, err := loader.LoadTable(db, "testdb", "bins")
	if err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if !reflect.DeepEqual(one.ForeignKeys, want) {
		t.Errorf("LoadTable bins foreign keys:\n got: %+v\nwant: %+v", one.ForeignKeys, want)
	}
}

// TestMariaDBLoader runs the MySQL loader checks against MariaDB, which reports
// the same information_schema layout, in a single container.
func TestMariaDBLoader(t *testing.T) {
	db := startMariaDB(t)
	t.Run("load", func(t *testing.T) {
		s, err := myschema.NewLoader().Load(db, "testdb")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		assertMySQLDetail(t, s)
	})
	t.Run("load_matches_load_table", func(t *testing.T) { assertLoadMatchesLoadTable(t, db) })
	t.Run("composite_foreign_key", func(t *testing.T) { assertCompositeForeignKey(t, db) })
}

// The name is validated before any query, so no database is needed.
func TestMySQLLoader_LoadTable_EmptyName(t *testing.T) {
	if _, err := myschema.NewLoader().LoadTable(nil, "db", ""); err == nil {
		t.Fatal("expected error for empty table name")
	}
}
