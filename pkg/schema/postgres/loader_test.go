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

// startPostgres starts a PostgreSQL container loaded with the shared fixture and
// returns a connection as the owning role.
func startPostgres(t *testing.T) *sql.DB {
	t.Helper()
	db, _, _ := startPostgresServer(t)
	return db
}

// startPostgresServer is startPostgres that also returns the container's host
// and mapped port so a test can open a second connection as another role.
func startPostgresServer(t *testing.T) (db *sql.DB, host, port string) {
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
	// Bound the container start by the test binary's deadline so a slow CI
	// pull or init skips this integration test instead of panicking the package.
	startCtx := ctx
	if deadline, ok := t.Deadline(); ok {
		var cancel context.CancelFunc
		startCtx, cancel = context.WithDeadline(ctx, deadline.Add(-30*time.Second))
		defer cancel()
	}
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
		c, err = testcontainers.GenericContainer(startCtx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
	}()
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })

	host, _ = c.Host(ctx)
	mapped, _ := c.MappedPort(ctx, "5432")
	port = mapped.Port()
	dsn := fmt.Sprintf("host=%s port=%s user=test password=test dbname=testdb sslmode=disable", host, port)
	db, err = sql.Open("postgres", dsn)
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

		-- Composite FK whose referenced column order differs from the PK order.
		CREATE TABLE accounts (tenant_id INT, account_no INT, PRIMARY KEY (tenant_id, account_no));
		CREATE TABLE ledger (
			id     SERIAL PRIMARY KEY,
			acct   INT NOT NULL,
			tenant INT NOT NULL,
			CONSTRAINT fk_ledger_account FOREIGN KEY (acct, tenant)
				REFERENCES accounts (account_no, tenant_id) ON DELETE CASCADE ON UPDATE CASCADE
		);

		-- Same FK name on two different tables with different targets and rules.
		CREATE TABLE invoices (
			id       SERIAL PRIMARY KEY,
			buyer_id INT,
			CONSTRAINT fk_parent FOREIGN KEY (buyer_id) REFERENCES users(id) ON DELETE SET NULL
		);
		CREATE TABLE shipments (
			id        SERIAL PRIMARY KEY,
			order_ref INT,
			CONSTRAINT fk_parent FOREIGN KEY (order_ref) REFERENCES orders(id) ON DELETE RESTRICT
		);

		-- FK that references a partitioned table (Postgres clones it per partition).
		CREATE TABLE events (id INT, region TEXT, PRIMARY KEY (id, region)) PARTITION BY LIST (region);
		CREATE TABLE events_eu PARTITION OF events FOR VALUES IN ('eu');
		CREATE TABLE events_us PARTITION OF events FOR VALUES IN ('us');
		CREATE TABLE event_refs (
			id       SERIAL PRIMARY KEY,
			event_id INT,
			region   TEXT,
			CONSTRAINT fk_event FOREIGN KEY (event_id, region) REFERENCES events (id, region)
		);

		-- FK declared on a partitioned table (same constraint name on parent and partition).
		CREATE TABLE prefs (user_id INT REFERENCES users(id), region TEXT) PARTITION BY LIST (region);
		CREATE TABLE prefs_eu PARTITION OF prefs FOR VALUES IN ('eu');

		-- Index over quoted identifiers containing commas, quotes, braces and spaces.
		CREATE TABLE odd ("a,b" INT, "q""x" INT, "{br}" INT, "sp ace" INT);
		CREATE INDEX idx_odd ON odd ("sp ace", "a,b", "{br}", "q""x");

		-- #620: index key order, INCLUDE and expression keys.
		CREATE TABLE t (a INT, b INT, c INT, email TEXT);
		CREATE INDEX idx_ba    ON t (b, a);
		CREATE INDEX idx_incl  ON t (c) INCLUDE (a);
		CREATE INDEX idx_expr  ON t (lower(email));
		CREATE INDEX idx_mixed ON t (lower(email), b);

		-- #620: composite UNIQUE constraints share columns with a single-column one.
		CREATE TABLE u (id INT PRIMARY KEY, k INT, UNIQUE (k), UNIQUE (k, id));

		-- #620: partitioned parent (relkind 'p') and its partition.
		CREATE TABLE p (id INT, region TEXT, PRIMARY KEY (id, region)) PARTITION BY LIST (region);
		CREATE TABLE p_eu PARTITION OF p FOR VALUES IN ('eu');

		-- #620: foreign key into another schema.
		CREATE SCHEMA other;
		CREATE TABLE other.users (id INT PRIMARY KEY);
		CREATE TABLE r (id INT PRIMARY KEY, uid INT REFERENCES other.users(id));

		-- #620: a role with only SELECT must see the same keys (must stay last).
		CREATE ROLE ro LOGIN PASSWORD 'ro';
		GRANT USAGE ON SCHEMA public TO ro;
		GRANT SELECT ON ALL TABLES IN SCHEMA public TO ro;
	`)
	if err != nil {
		t.Fatalf("create tables: %v", err)
	}
	return db, host, port
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

// TestPostgresLoader_ForeignKeyJoinKeys is a regression test for #579: foreign
// keys must be keyed by (table, constraint) and composite keys must pair each
// local column with its referenced column by position.
func TestPostgresLoader_ForeignKeyJoinKeys(t *testing.T) {
	db := startPostgres(t)
	loader := pgschema.NewLoader()
	s, err := loader.Load(db, "public")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	cases := []struct {
		name  string
		table string
		want  []dbschema.ForeignKey
	}{
		{"composite", "ledger", []dbschema.ForeignKey{{
			Name: "fk_ledger_account", TableName: "ledger",
			Columns: []string{"acct", "tenant"}, RefSchema: "public", RefTable: "accounts",
			RefColumns: []string{"account_no", "tenant_id"},
			OnDelete:   "CASCADE", OnUpdate: "CASCADE",
		}}},
		{"shared_name_set_null", "invoices", []dbschema.ForeignKey{{
			Name: "fk_parent", TableName: "invoices",
			Columns: []string{"buyer_id"}, RefSchema: "public", RefTable: "users", RefColumns: []string{"id"},
			OnDelete: "SET NULL", OnUpdate: "NO ACTION",
		}}},
		{"shared_name_restrict", "shipments", []dbschema.ForeignKey{{
			Name: "fk_parent", TableName: "shipments",
			Columns: []string{"order_ref"}, RefSchema: "public", RefTable: "orders", RefColumns: []string{"id"},
			OnDelete: "RESTRICT", OnUpdate: "NO ACTION",
		}}},
		{"references_partitioned", "event_refs", []dbschema.ForeignKey{{
			Name: "fk_event", TableName: "event_refs",
			Columns: []string{"event_id", "region"}, RefSchema: "public", RefTable: "events",
			RefColumns: []string{"id", "region"},
			OnDelete:   "NO ACTION", OnUpdate: "NO ACTION",
		}}},
		{"partitioned_parent", "prefs", []dbschema.ForeignKey{{
			Name: "prefs_user_id_fkey", TableName: "prefs",
			Columns: []string{"user_id"}, RefSchema: "public", RefTable: "users", RefColumns: []string{"id"},
			OnDelete: "NO ACTION", OnUpdate: "NO ACTION",
		}}},
		{"partition", "prefs_eu", []dbschema.ForeignKey{{
			Name: "prefs_user_id_fkey", TableName: "prefs_eu",
			Columns: []string{"user_id"}, RefSchema: "public", RefTable: "users", RefColumns: []string{"id"},
			OnDelete: "NO ACTION", OnUpdate: "NO ACTION",
		}}},
		{"single_column_cascade", "orders", []dbschema.ForeignKey{{
			Name: "orders_user_id_fkey", TableName: "orders",
			Columns: []string{"user_id"}, RefSchema: "public", RefTable: "users", RefColumns: []string{"id"},
			OnDelete: "CASCADE", OnUpdate: "NO ACTION",
		}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			full := findTable(s, tc.table)
			if full == nil {
				t.Fatalf("Load: table %q missing", tc.table)
			}
			if !reflect.DeepEqual(full.ForeignKeys, tc.want) {
				t.Errorf("Load %s foreign keys:\n got: %+v\nwant: %+v", tc.table, full.ForeignKeys, tc.want)
			}
			one, err := loader.LoadTable(db, "public", tc.table)
			if err != nil {
				t.Fatalf("LoadTable(%q): %v", tc.table, err)
			}
			if one == nil {
				t.Fatalf("LoadTable(%q) returned nil", tc.table)
			}
			if !reflect.DeepEqual(one.ForeignKeys, tc.want) {
				t.Errorf("LoadTable %s foreign keys:\n got: %+v\nwant: %+v", tc.table, one.ForeignKeys, tc.want)
			}
		})
	}
}

// TestPostgresLoader_QuotedIndexColumns is a regression test for #579: index
// columns whose quoted names contain commas, quotes, braces or spaces must
// decode exactly.
func TestPostgresLoader_QuotedIndexColumns(t *testing.T) {
	db := startPostgres(t)
	s, err := pgschema.NewLoader().Load(db, "public")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	odd := findTable(s, "odd")
	if odd == nil {
		t.Fatal("table odd missing")
	}
	var found bool
	for _, idx := range odd.Indexes {
		if idx.Name != "idx_odd" {
			continue
		}
		found = true
		want := []string{"sp ace", "a,b", "{br}", `q"x`}
		if !reflect.DeepEqual(idx.Columns, want) {
			t.Errorf("idx_odd columns: got %q want %q", idx.Columns, want)
		}
		if idx.IsUnique || idx.IsPrimary {
			t.Errorf("idx_odd: unique=%v primary=%v, want neither", idx.IsUnique, idx.IsPrimary)
		}
	}
	if !found {
		t.Error("idx_odd not found")
	}
}

// TestPostgresLoader_IndexAndKeyMetadata is a regression test for #620: index
// key order, INCLUDE and expression keys, partitioned parents, per-column
// PK/UNIQUE flags, the referenced schema of foreign keys, and visibility of
// all of it to a role that only has SELECT.
func TestPostgresLoader_IndexAndKeyMetadata(t *testing.T) {
	db, host, port := startPostgresServer(t)
	loader := pgschema.NewLoader()
	s, err := loader.Load(db, "public")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// load returns the table from both Load and LoadTable, which must agree.
	load := func(t *testing.T, name string) *dbschema.Table {
		t.Helper()
		full := findTable(s, name)
		if full == nil {
			t.Fatalf("Load: table %q missing", name)
		}
		one, err := loader.LoadTable(db, "public", name)
		if err != nil {
			t.Fatalf("LoadTable(%q): %v", name, err)
		}
		if !reflect.DeepEqual(one, full) {
			t.Fatalf("LoadTable(%q) differs from Load:\n got: %+v\nwant: %+v", name, *one, *full)
		}
		return full
	}

	t.Run("index_order_include_expression", func(t *testing.T) {
		want := []dbschema.Index{
			{Name: "idx_ba", TableName: "t", Columns: []string{"b", "a"}},
			{Name: "idx_expr", TableName: "t", Columns: []string{"lower(email)"}},
			{Name: "idx_incl", TableName: "t", Columns: []string{"c"}, IncludeColumns: []string{"a"}},
			{Name: "idx_mixed", TableName: "t", Columns: []string{"lower(email)", "b"}},
		}
		if got := load(t, "t").Indexes; !reflect.DeepEqual(got, want) {
			t.Errorf("t indexes:\n got: %+v\nwant: %+v", got, want)
		}
	})

	t.Run("composite_unique_order", func(t *testing.T) {
		want := []dbschema.Index{
			{Name: "u_k_id_key", TableName: "u", Columns: []string{"k", "id"}, IsUnique: true},
			{Name: "u_k_key", TableName: "u", Columns: []string{"k"}, IsUnique: true},
			{Name: "u_pkey", TableName: "u", Columns: []string{"id"}, IsUnique: true, IsPrimary: true},
		}
		if got := load(t, "u").Indexes; !reflect.DeepEqual(got, want) {
			t.Errorf("u indexes:\n got: %+v\nwant: %+v", got, want)
		}
	})

	t.Run("partitioned_parent", func(t *testing.T) {
		cases := []struct{ table, index string }{
			{"p", "p_pkey"},
			{"p_eu", "p_eu_pkey"},
			{"events", "events_pkey"},
		}
		for _, tc := range cases {
			want := []dbschema.Index{{
				Name: tc.index, TableName: tc.table, Columns: []string{"id", "region"},
				IsUnique: true, IsPrimary: true,
			}}
			if got := load(t, tc.table).Indexes; !reflect.DeepEqual(got, want) {
				t.Errorf("%s indexes:\n got: %+v\nwant: %+v", tc.table, got, want)
			}
		}
	})

	t.Run("column_flags", func(t *testing.T) {
		u := load(t, "u")
		if len(u.Columns) != 2 {
			t.Fatalf("u columns: got %d want 2: %+v", len(u.Columns), u.Columns)
		}
		for _, c := range u.Columns {
			switch c.Name {
			case "id":
				if !c.IsPrimary || c.IsUnique {
					t.Errorf("u.id: primary=%v unique=%v, want primary only", c.IsPrimary, c.IsUnique)
				}
			case "k":
				if c.IsPrimary || !c.IsUnique {
					t.Errorf("u.k: primary=%v unique=%v, want unique only", c.IsPrimary, c.IsUnique)
				}
			default:
				t.Errorf("unexpected column %q", c.Name)
			}
		}
		for _, c := range load(t, "p").Columns {
			if !c.IsPrimary {
				t.Errorf("p.%s: want primary", c.Name)
			}
		}
	})

	t.Run("cross_schema_fk", func(t *testing.T) {
		want := []dbschema.ForeignKey{{
			Name: "r_uid_fkey", TableName: "r", Columns: []string{"uid"},
			RefSchema: "other", RefTable: "users", RefColumns: []string{"id"},
			OnDelete: "NO ACTION", OnUpdate: "NO ACTION",
		}}
		if got := load(t, "r").ForeignKeys; !reflect.DeepEqual(got, want) {
			t.Errorf("r foreign keys:\n got: %+v\nwant: %+v", got, want)
		}
	})

	t.Run("select_only_role", func(t *testing.T) {
		dsn := fmt.Sprintf("host=%s port=%s user=ro password=ro dbname=testdb sslmode=disable", host, port)
		ro, err := sql.Open("postgres", dsn)
		if err != nil {
			t.Fatalf("open ro db: %v", err)
		}
		t.Cleanup(func() { _ = ro.Close() })
		var pingErr error
		for i := 0; i < 30; i++ {
			if pingErr = ro.Ping(); pingErr == nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if pingErr != nil {
			t.Fatalf("ping ro db after retries: %v", pingErr)
		}
		got, err := loader.Load(ro, "public")
		if err != nil {
			t.Fatalf("Load as ro: %v", err)
		}
		if !reflect.DeepEqual(got, s) {
			t.Errorf("Load as SELECT-only role differs from owner:\n got: %+v\nwant: %+v", got, s)
		}
		users := findTable(got, "users")
		if users == nil {
			t.Fatal("users missing for ro")
		}
		for _, c := range users.Columns {
			if c.Name == "id" && !c.IsPrimary {
				t.Error("users.id not primary for SELECT-only role")
			}
		}
	})
}

// The name is validated before any query, so no database is needed.
func TestPostgresLoader_LoadTable_EmptyName(t *testing.T) {
	if _, err := pgschema.NewLoader().LoadTable(nil, "public", ""); err == nil {
		t.Fatal("expected error for empty table name")
	}
}
