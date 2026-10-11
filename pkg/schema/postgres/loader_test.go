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

package postgres_test

import (
	"context"
	"database/sql"
	"fmt"
	"os/exec"
	"reflect"
	"runtime"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	dbschema "github.com/ajitpratap0/GoSQLX/pkg/schema/db"
	pgschema "github.com/ajitpratap0/GoSQLX/pkg/schema/postgres"
)

// isDockerAvailable checks whether the Docker daemon is reachable.
// Returns false on macOS CI runners that have no Docker installed.
func isDockerAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "info")
	return cmd.Run() == nil
}

func startPostgres(t *testing.T) *sql.DB {
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
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
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
	port, _ := c.MappedPort(ctx, "5432")
	dsn := fmt.Sprintf("host=%s port=%s user=test password=test dbname=testdb sslmode=disable", host, port.Port())
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Wait for the database to be fully ready to accept queries.
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
		CREATE TABLE users (
			id   SERIAL PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			email TEXT UNIQUE
		);
		CREATE TABLE orders (
			id      SERIAL PRIMARY KEY,
			user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			total   NUMERIC(10,2)
		);
		CREATE INDEX idx_orders_user ON orders(user_id);
	`)
	if err != nil {
		t.Fatalf("create tables: %v", err)
	}
	return db
}

func TestPostgresLoader_Load(t *testing.T) {
	db := startPostgres(t)
	loader := pgschema.NewLoader()
	s, err := loader.Load(db, "public")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.Name != "public" {
		t.Errorf("schema name: got %q want %q", s.Name, "public")
	}
	tableNames := make(map[string]bool)
	for _, tbl := range s.Tables {
		tableNames[tbl.Name] = true
	}
	if !tableNames["users"] {
		t.Error("expected users table")
	}
	if !tableNames["orders"] {
		t.Error("expected orders table")
	}
	assertPostgresDetail(t, s)
}

func findTable(s *dbschema.DatabaseSchema, name string) *dbschema.Table {
	for i := range s.Tables {
		if s.Tables[i].Name == name {
			return &s.Tables[i]
		}
	}
	return nil
}

// assertPostgresDetail checks per-table columns, PK/UNIQUE flags, indexes and
// foreign keys of the fixture loaded via Load.
func assertPostgresDetail(t *testing.T, s *dbschema.DatabaseSchema) {
	t.Helper()
	users := findTable(s, "users")
	orders := findTable(s, "orders")
	if users == nil || orders == nil {
		t.Fatalf("missing users/orders tables: %+v", s.Tables)
	}
	if len(users.Columns) != 3 {
		t.Fatalf("users columns: got %d want 3", len(users.Columns))
	}
	for _, c := range users.Columns {
		switch c.Name {
		case "id":
			if !c.IsPrimary || c.IsUnique {
				t.Errorf("users.id: primary=%v unique=%v, want primary only", c.IsPrimary, c.IsUnique)
			}
		case "email":
			if !c.IsUnique || c.IsPrimary {
				t.Errorf("users.email: primary=%v unique=%v, want unique only", c.IsPrimary, c.IsUnique)
			}
		case "name":
			if c.IsUnique || c.IsPrimary {
				t.Errorf("users.name: primary=%v unique=%v, want neither", c.IsPrimary, c.IsUnique)
			}
		}
	}
	if len(orders.Columns) != 3 {
		t.Errorf("orders columns: got %d want 3", len(orders.Columns))
	}
	for _, c := range orders.Columns {
		// PK/UNIQUE flags must not leak across tables that share column names.
		if c.IsUnique {
			t.Errorf("orders.%s unexpectedly unique", c.Name)
		}
		if c.IsPrimary != (c.Name == "id") {
			t.Errorf("orders.%s primary=%v", c.Name, c.IsPrimary)
		}
	}
	if len(orders.ForeignKeys) != 1 {
		t.Fatalf("orders foreign keys: got %d want 1", len(orders.ForeignKeys))
	}
	fk := orders.ForeignKeys[0]
	if fk.RefTable != "users" || fk.OnDelete != "CASCADE" ||
		!reflect.DeepEqual(fk.Columns, []string{"user_id"}) {
		t.Errorf("orders fk: got %+v", fk)
	}
	var found bool
	for _, idx := range orders.Indexes {
		if idx.Name == "idx_orders_user" {
			found = true
			if !reflect.DeepEqual(idx.Columns, []string{"user_id"}) || idx.TableName != "orders" {
				t.Errorf("idx_orders_user: got %+v", idx)
			}
		}
	}
	if !found {
		t.Error("idx_orders_user not found")
	}
}

func TestPostgresLoader_Load_MaxOpenConns1(t *testing.T) {
	db := startPostgres(t)
	db.SetMaxOpenConns(1)
	type result struct {
		s   *dbschema.DatabaseSchema
		err error
	}
	done := make(chan result, 1)
	go func() {
		s, err := pgschema.NewLoader().Load(db, "public")
		done <- result{s, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Load: %v", r.err)
		}
		assertPostgresDetail(t, r.s)
	case <-time.After(30 * time.Second):
		t.Fatal("Load deadlocked with MaxOpenConns=1")
	}
}

func TestPostgresLoader_LoadMatchesLoadTable(t *testing.T) {
	db := startPostgres(t)
	loader := pgschema.NewLoader()
	s, err := loader.Load(db, "public")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(s.Tables) == 0 {
		t.Fatal("Load returned no tables")
	}
	for i := range s.Tables {
		want := s.Tables[i]
		got, err := loader.LoadTable(db, "public", want.Name)
		if err != nil {
			t.Fatalf("LoadTable(%q): %v", want.Name, err)
		}
		if !reflect.DeepEqual(*got, want) {
			t.Errorf("LoadTable(%q) differs from Load:\n got: %+v\nwant: %+v", want.Name, *got, want)
		}
	}
}

func TestPostgresLoader_LoadTable_Columns(t *testing.T) {
	db := startPostgres(t)
	loader := pgschema.NewLoader()
	tbl, err := loader.LoadTable(db, "public", "users")
	if err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if tbl.Name != "users" {
		t.Errorf("table name: got %q want users", tbl.Name)
	}
	if len(tbl.Columns) != 3 {
		t.Errorf("columns: got %d want 3", len(tbl.Columns))
	}
	var found bool
	for i := range tbl.Columns {
		if tbl.Columns[i].Name == "id" {
			if !tbl.Columns[i].IsPrimary {
				t.Error("expected id column to be primary key")
			}
			found = true
		}
	}
	if !found {
		t.Error("id column not found")
	}
}

func TestPostgresLoader_LoadTable_ForeignKeys(t *testing.T) {
	db := startPostgres(t)
	loader := pgschema.NewLoader()
	tbl, err := loader.LoadTable(db, "public", "orders")
	if err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if len(tbl.ForeignKeys) != 1 {
		t.Fatalf("foreign keys: got %d want 1", len(tbl.ForeignKeys))
	}
	fk := tbl.ForeignKeys[0]
	if fk.RefTable != "users" {
		t.Errorf("fk ref table: got %q want users", fk.RefTable)
	}
	if fk.OnDelete != "CASCADE" {
		t.Errorf("fk on delete: got %q want CASCADE", fk.OnDelete)
	}
}
