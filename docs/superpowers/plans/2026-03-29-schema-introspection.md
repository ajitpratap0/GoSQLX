# Live DB Schema Introspection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `pkg/schema/` package that connects to a live database and returns structured schema metadata (tables, columns, indexes, foreign keys) compatible with GoSQLX AST types.

**Architecture:** A `Loader` interface with dialect-specific implementations (`postgres`, `mysql`, `sqlite`) each using `database/sql` queries against information_schema / system catalogs. Results are returned as plain Go structs (not AST nodes) to avoid coupling. A `gosqlx.LoadSchema()` convenience wrapper exposes it at the top level.

**Tech Stack:** Go `database/sql`, `github.com/lib/pq` (Postgres), `github.com/go-sql-driver/mysql` (MySQL), `modernc.org/sqlite` (SQLite, pure Go — no cgo), `testcontainers-go` for integration tests (Postgres + MySQL containers), standard `testing` package.

---

### Task 1: Define schema types and Loader interface

**Files:**
- Create: `pkg/schema/schema.go`
- Create: `pkg/schema/loader.go`

- [ ] **Step 1: Create schema types**

```go
// pkg/schema/schema.go
package schema

// Column describes a single column in a table.
type Column struct {
	Name         string
	OrdinalPos   int
	DataType     string
	IsNullable   bool
	DefaultValue *string
	MaxLength    *int
	Precision    *int
	Scale        *int
	IsPrimary    bool
	IsUnique     bool
}

// Index describes a table index.
type Index struct {
	Name      string
	TableName string
	Columns   []string
	IsUnique  bool
	IsPrimary bool
}

// ForeignKey describes a foreign key constraint.
type ForeignKey struct {
	Name           string
	TableName      string
	Columns        []string
	RefTable       string
	RefColumns     []string
	OnDelete       string
	OnUpdate       string
}

// Table describes a database table with its columns, indexes, and foreign keys.
type Table struct {
	Schema      string
	Name        string
	Columns     []Column
	Indexes     []Index
	ForeignKeys []ForeignKey
}

// DatabaseSchema is the top-level result from schema introspection.
type DatabaseSchema struct {
	Name   string
	Tables []Table
}
```

- [ ] **Step 2: Create Loader interface**

```go
// pkg/schema/loader.go
package schema

import "database/sql"

// Loader connects to a live database and reads its schema.
type Loader interface {
	// Load returns the full schema for all user tables in the database.
	// schemaName may be empty to use the database default.
	Load(db *sql.DB, schemaName string) (*DatabaseSchema, error)
	// LoadTable returns schema for a single named table.
	LoadTable(db *sql.DB, schemaName, tableName string) (*Table, error)
}
```

- [ ] **Step 3: Commit**

```bash
git add pkg/schema/schema.go pkg/schema/loader.go
git commit -m "feat(schema): define schema types and Loader interface"
```

---

### Task 2: Write failing tests for Postgres loader

**Files:**
- Create: `pkg/schema/postgres/loader_test.go`

Requires `testcontainers-go`. Add to go.mod:
```
require (
    github.com/testcontainers/testcontainers-go v0.32.0
    github.com/lib/pq v1.10.9
)
```

- [ ] **Step 1: Write integration test**

```go
// pkg/schema/postgres/loader_test.go
package postgres_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	pgschema "github.com/ajitpratap0/GoSQLX/pkg/schema/postgres"
)

func startPostgres(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp"),
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
	port, _ := c.MappedPort(ctx, "5432")
	dsn := fmt.Sprintf("host=%s port=%s user=test password=test dbname=testdb sslmode=disable", host, port.Port())
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

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
	schema, err := loader.Load(db, "public")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if schema.Name != "public" {
		t.Errorf("schema name: got %q want %q", schema.Name, "public")
	}
	tableNames := make(map[string]bool)
	for _, tbl := range schema.Tables {
		tableNames[tbl.Name] = true
	}
	if !tableNames["users"] {
		t.Error("expected users table")
	}
	if !tableNames["orders"] {
		t.Error("expected orders table")
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
	// id, name, email = 3 columns
	if len(tbl.Columns) != 3 {
		t.Errorf("columns: got %d want 3", len(tbl.Columns))
	}
	// id must be primary
	var idCol *schema.Column
	for i := range tbl.Columns {
		if tbl.Columns[i].Name == "id" {
			idCol = &tbl.Columns[i]
		}
	}
	if idCol == nil || !idCol.IsPrimary {
		t.Error("expected id column to be primary key")
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
```

- [ ] **Step 2: Run test — verify it fails**

```bash
go test ./pkg/schema/postgres/... -v -run TestPostgresLoader
```
Expected: compile error — package `postgres` doesn't exist yet.

---

### Task 3: Implement Postgres loader

**Files:**
- Create: `pkg/schema/postgres/loader.go`

- [ ] **Step 1: Implement Loader**

```go
// pkg/schema/postgres/loader.go
package postgres

import (
	"database/sql"
	"fmt"

	schemalib "github.com/ajitpratap0/GoSQLX/pkg/schema"
)

// Loader implements schema.Loader for PostgreSQL.
type Loader struct{}

// NewLoader returns a new Postgres schema loader.
func NewLoader() *Loader { return &Loader{} }

func (l *Loader) Load(db *sql.DB, schemaName string) (*schemalib.DatabaseSchema, error) {
	if schemaName == "" {
		schemaName = "public"
	}
	rows, err := db.Query(`
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = $1
		  AND table_type = 'BASE TABLE'
		ORDER BY table_name
	`, schemaName)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	defer rows.Close()

	ds := &schemalib.DatabaseSchema{Name: schemaName}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tbl, err := l.LoadTable(db, schemaName, name)
		if err != nil {
			return nil, err
		}
		ds.Tables = append(ds.Tables, *tbl)
	}
	return ds, rows.Err()
}

func (l *Loader) LoadTable(db *sql.DB, schemaName, tableName string) (*schemalib.Table, error) {
	if schemaName == "" {
		schemaName = "public"
	}
	tbl := &schemalib.Table{Schema: schemaName, Name: tableName}
	var err error
	tbl.Columns, err = l.loadColumns(db, schemaName, tableName)
	if err != nil {
		return nil, err
	}
	tbl.Indexes, err = l.loadIndexes(db, schemaName, tableName)
	if err != nil {
		return nil, err
	}
	tbl.ForeignKeys, err = l.loadForeignKeys(db, schemaName, tableName)
	if err != nil {
		return nil, err
	}
	return tbl, nil
}

func (l *Loader) loadColumns(db *sql.DB, schemaName, tableName string) ([]schemalib.Column, error) {
	rows, err := db.Query(`
		SELECT
			c.column_name,
			c.ordinal_position,
			c.data_type,
			c.is_nullable,
			c.column_default,
			c.character_maximum_length,
			c.numeric_precision,
			c.numeric_scale,
			COALESCE(pk.is_primary, false),
			COALESCE(uq.is_unique, false)
		FROM information_schema.columns c
		LEFT JOIN (
			SELECT kcu.column_name, true AS is_primary
			FROM information_schema.table_constraints tc
			JOIN information_schema.key_column_usage kcu
				ON tc.constraint_name = kcu.constraint_name
				AND tc.table_schema = kcu.table_schema
			WHERE tc.table_schema = $1 AND tc.table_name = $2
			  AND tc.constraint_type = 'PRIMARY KEY'
		) pk ON pk.column_name = c.column_name
		LEFT JOIN (
			SELECT kcu.column_name, true AS is_unique
			FROM information_schema.table_constraints tc
			JOIN information_schema.key_column_usage kcu
				ON tc.constraint_name = kcu.constraint_name
				AND tc.table_schema = kcu.table_schema
			WHERE tc.table_schema = $1 AND tc.table_name = $2
			  AND tc.constraint_type = 'UNIQUE'
		) uq ON uq.column_name = c.column_name
		WHERE c.table_schema = $1 AND c.table_name = $2
		ORDER BY c.ordinal_position
	`, schemaName, tableName)
	if err != nil {
		return nil, fmt.Errorf("load columns: %w", err)
	}
	defer rows.Close()

	var cols []schemalib.Column
	for rows.Next() {
		var col schemalib.Column
		var isNullable string
		err := rows.Scan(
			&col.Name, &col.OrdinalPos, &col.DataType, &isNullable,
			&col.DefaultValue, &col.MaxLength, &col.Precision, &col.Scale,
			&col.IsPrimary, &col.IsUnique,
		)
		if err != nil {
			return nil, err
		}
		col.IsNullable = isNullable == "YES"
		cols = append(cols, col)
	}
	return cols, rows.Err()
}

func (l *Loader) loadIndexes(db *sql.DB, schemaName, tableName string) ([]schemalib.Index, error) {
	rows, err := db.Query(`
		SELECT
			i.relname AS index_name,
			ix.indisunique,
			ix.indisprimary,
			array_agg(a.attname ORDER BY a.attnum) AS columns
		FROM pg_class t
		JOIN pg_index ix ON t.oid = ix.indrelid
		JOIN pg_class i ON i.oid = ix.indexrelid
		JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
		JOIN pg_namespace n ON n.oid = t.relnamespace
		WHERE n.nspname = $1 AND t.relname = $2 AND t.relkind = 'r'
		GROUP BY i.relname, ix.indisunique, ix.indisprimary
		ORDER BY i.relname
	`, schemaName, tableName)
	if err != nil {
		return nil, fmt.Errorf("load indexes: %w", err)
	}
	defer rows.Close()

	var indexes []schemalib.Index
	for rows.Next() {
		var idx schemalib.Index
		var colArray string
		if err := rows.Scan(&idx.Name, &idx.IsUnique, &idx.IsPrimary, &colArray); err != nil {
			return nil, err
		}
		idx.TableName = tableName
		// colArray is like "{col1,col2}" from array_agg
		idx.Columns = parseArrayAgg(colArray)
		indexes = append(indexes, idx)
	}
	return indexes, rows.Err()
}

func (l *Loader) loadForeignKeys(db *sql.DB, schemaName, tableName string) ([]schemalib.ForeignKey, error) {
	rows, err := db.Query(`
		SELECT
			tc.constraint_name,
			kcu.column_name,
			ccu.table_name AS foreign_table_name,
			ccu.column_name AS foreign_column_name,
			rc.delete_rule,
			rc.update_rule
		FROM information_schema.table_constraints AS tc
		JOIN information_schema.key_column_usage AS kcu
			ON tc.constraint_name = kcu.constraint_name
			AND tc.table_schema = kcu.table_schema
		JOIN information_schema.constraint_column_usage AS ccu
			ON ccu.constraint_name = tc.constraint_name
			AND ccu.table_schema = tc.table_schema
		JOIN information_schema.referential_constraints AS rc
			ON rc.constraint_name = tc.constraint_name
		WHERE tc.constraint_type = 'FOREIGN KEY'
		  AND tc.table_schema = $1 AND tc.table_name = $2
		ORDER BY tc.constraint_name, kcu.ordinal_position
	`, schemaName, tableName)
	if err != nil {
		return nil, fmt.Errorf("load fks: %w", err)
	}
	defer rows.Close()

	fkMap := make(map[string]*schemalib.ForeignKey)
	var order []string
	for rows.Next() {
		var name, col, refTable, refCol, onDelete, onUpdate string
		if err := rows.Scan(&name, &col, &refTable, &refCol, &onDelete, &onUpdate); err != nil {
			return nil, err
		}
		if _, ok := fkMap[name]; !ok {
			fkMap[name] = &schemalib.ForeignKey{
				Name:      name,
				TableName: tableName,
				RefTable:  refTable,
				OnDelete:  onDelete,
				OnUpdate:  onUpdate,
			}
			order = append(order, name)
		}
		fkMap[name].Columns = append(fkMap[name].Columns, col)
		fkMap[name].RefColumns = append(fkMap[name].RefColumns, refCol)
	}
	fks := make([]schemalib.ForeignKey, 0, len(order))
	for _, n := range order {
		fks = append(fks, *fkMap[n])
	}
	return fks, rows.Err()
}

// parseArrayAgg parses Postgres array literal "{a,b,c}" into []string{"a","b","c"}.
func parseArrayAgg(s string) []string {
	if len(s) < 2 {
		return nil
	}
	s = s[1 : len(s)-1] // strip braces
	if s == "" {
		return nil
	}
	var result []string
	for _, p := range strings.Split(s, ",") {
		result = append(result, strings.TrimSpace(p))
	}
	return result
}
```

Add `"strings"` to imports in the file above.

- [ ] **Step 2: Run tests — verify they pass**

```bash
go test ./pkg/schema/postgres/... -v -run TestPostgresLoader -timeout 120s
```
Expected: PASS (requires Docker for testcontainers).

- [ ] **Step 3: Commit**

```bash
git add pkg/schema/
git commit -m "feat(schema): Postgres schema loader with testcontainers integration tests"
```

---

### Task 4: Write failing tests for MySQL loader

**Files:**
- Create: `pkg/schema/mysql/loader_test.go`

- [ ] **Step 1: Write MySQL integration test**

```go
// pkg/schema/mysql/loader_test.go
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
	schemalib "github.com/ajitpratap0/GoSQLX/pkg/schema"
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
		);
		CREATE TABLE line_items (
			id         INT AUTO_INCREMENT PRIMARY KEY,
			product_id INT NOT NULL,
			qty        INT DEFAULT 1,
			FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE RESTRICT
		);
	`)
	if err != nil {
		t.Fatalf("create tables: %v", err)
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
	var idCol *schemalib.Column
	for i := range tbl.Columns {
		if tbl.Columns[i].Name == "id" {
			idCol = &tbl.Columns[i]
		}
	}
	if idCol == nil || !idCol.IsPrimary {
		t.Error("expected id to be primary key")
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
```

- [ ] **Step 2: Run test — verify it fails**

```bash
go test ./pkg/schema/mysql/... -v -run TestMySQLLoader
```
Expected: compile error — package `mysql` doesn't exist yet.

---

### Task 5: Implement MySQL loader

**Files:**
- Create: `pkg/schema/mysql/loader.go`

- [ ] **Step 1: Implement MySQL Loader**

```go
// pkg/schema/mysql/loader.go
package mysql

import (
	"database/sql"
	"fmt"
	"strings"

	schemalib "github.com/ajitpratap0/GoSQLX/pkg/schema"
)

// Loader implements schema.Loader for MySQL.
type Loader struct{}

// NewLoader returns a new MySQL schema loader.
func NewLoader() *Loader { return &Loader{} }

func (l *Loader) Load(db *sql.DB, schemaName string) (*schemalib.DatabaseSchema, error) {
	rows, err := db.Query(`
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = ? AND table_type = 'BASE TABLE'
		ORDER BY table_name
	`, schemaName)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	defer rows.Close()

	ds := &schemalib.DatabaseSchema{Name: schemaName}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tbl, err := l.LoadTable(db, schemaName, name)
		if err != nil {
			return nil, err
		}
		ds.Tables = append(ds.Tables, *tbl)
	}
	return ds, rows.Err()
}

func (l *Loader) LoadTable(db *sql.DB, schemaName, tableName string) (*schemalib.Table, error) {
	tbl := &schemalib.Table{Schema: schemaName, Name: tableName}
	var err error
	tbl.Columns, err = l.loadColumns(db, schemaName, tableName)
	if err != nil {
		return nil, err
	}
	tbl.Indexes, err = l.loadIndexes(db, schemaName, tableName)
	if err != nil {
		return nil, err
	}
	tbl.ForeignKeys, err = l.loadForeignKeys(db, schemaName, tableName)
	if err != nil {
		return nil, err
	}
	return tbl, nil
}

func (l *Loader) loadColumns(db *sql.DB, schemaName, tableName string) ([]schemalib.Column, error) {
	rows, err := db.Query(`
		SELECT
			c.column_name,
			c.ordinal_position,
			c.data_type,
			c.is_nullable,
			c.column_default,
			c.character_maximum_length,
			c.numeric_precision,
			c.numeric_scale,
			c.column_key
		FROM information_schema.columns c
		WHERE c.table_schema = ? AND c.table_name = ?
		ORDER BY c.ordinal_position
	`, schemaName, tableName)
	if err != nil {
		return nil, fmt.Errorf("load columns: %w", err)
	}
	defer rows.Close()

	var cols []schemalib.Column
	for rows.Next() {
		var col schemalib.Column
		var isNullable, columnKey string
		err := rows.Scan(
			&col.Name, &col.OrdinalPos, &col.DataType, &isNullable,
			&col.DefaultValue, &col.MaxLength, &col.Precision, &col.Scale,
			&columnKey,
		)
		if err != nil {
			return nil, err
		}
		col.IsNullable = isNullable == "YES"
		col.IsPrimary = columnKey == "PRI"
		col.IsUnique = columnKey == "UNI"
		cols = append(cols, col)
	}
	return cols, rows.Err()
}

func (l *Loader) loadIndexes(db *sql.DB, schemaName, tableName string) ([]schemalib.Index, error) {
	rows, err := db.Query(`
		SELECT index_name, non_unique, column_name
		FROM information_schema.statistics
		WHERE table_schema = ? AND table_name = ?
		ORDER BY index_name, seq_in_index
	`, schemaName, tableName)
	if err != nil {
		return nil, fmt.Errorf("load indexes: %w", err)
	}
	defer rows.Close()

	idxMap := make(map[string]*schemalib.Index)
	var order []string
	for rows.Next() {
		var name, col string
		var nonUnique int
		if err := rows.Scan(&name, &nonUnique, &col); err != nil {
			return nil, err
		}
		if _, ok := idxMap[name]; !ok {
			idxMap[name] = &schemalib.Index{
				Name:      name,
				TableName: tableName,
				IsUnique:  nonUnique == 0,
				IsPrimary: name == "PRIMARY",
			}
			order = append(order, name)
		}
		idxMap[name].Columns = append(idxMap[name].Columns, col)
	}
	result := make([]schemalib.Index, 0, len(order))
	for _, n := range order {
		result = append(result, *idxMap[n])
	}
	return result, rows.Err()
}

func (l *Loader) loadForeignKeys(db *sql.DB, schemaName, tableName string) ([]schemalib.ForeignKey, error) {
	rows, err := db.Query(`
		SELECT
			kcu.constraint_name,
			kcu.column_name,
			kcu.referenced_table_name,
			kcu.referenced_column_name,
			rc.delete_rule,
			rc.update_rule
		FROM information_schema.key_column_usage kcu
		JOIN information_schema.referential_constraints rc
			ON rc.constraint_name = kcu.constraint_name
			AND rc.constraint_schema = kcu.table_schema
		WHERE kcu.table_schema = ? AND kcu.table_name = ?
		  AND kcu.referenced_table_name IS NOT NULL
		ORDER BY kcu.constraint_name, kcu.ordinal_position
	`, schemaName, tableName)
	if err != nil {
		return nil, fmt.Errorf("load fks: %w", err)
	}
	defer rows.Close()

	fkMap := make(map[string]*schemalib.ForeignKey)
	var order []string
	for rows.Next() {
		var name, col, refTable, refCol, onDelete, onUpdate string
		if err := rows.Scan(&name, &col, &refTable, &refCol, &onDelete, &onUpdate); err != nil {
			return nil, err
		}
		if _, ok := fkMap[name]; !ok {
			fkMap[name] = &schemalib.ForeignKey{
				Name:      name,
				TableName: tableName,
				RefTable:  refTable,
				OnDelete:  onDelete,
				OnUpdate:  onUpdate,
			}
			order = append(order, name)
		}
		fkMap[name].Columns = append(fkMap[name].Columns, col)
		fkMap[name].RefColumns = append(fkMap[name].RefColumns, refCol)
	}
	fks := make([]schemalib.ForeignKey, 0, len(order))
	for _, n := range order {
		fks = append(fks, *fkMap[n])
	}
	return fks, rows.Err()
}

// ensure Loader satisfies the interface (compile-time check)
var _ schemalib.Loader = (*Loader)(nil)
```

- [ ] **Step 2: Run MySQL tests**

```bash
go test ./pkg/schema/mysql/... -v -run TestMySQLLoader -timeout 120s
```
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add pkg/schema/mysql/
git commit -m "feat(schema): MySQL schema loader with testcontainers integration tests"
```

---

### Task 6: SQLite loader (pure Go, no containers needed)

**Files:**
- Create: `pkg/schema/sqlite/loader.go`
- Create: `pkg/schema/sqlite/loader_test.go`

- [ ] **Step 1: Write test**

```go
// pkg/schema/sqlite/loader_test.go
package sqlite_test

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
	sqschema "github.com/ajitpratap0/GoSQLX/pkg/schema/sqlite"
)

func openSQLite(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.Exec(`
		CREATE TABLE items (
			id   INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			qty  INTEGER DEFAULT 0
		);
		CREATE TABLE tags (
			item_id INTEGER NOT NULL REFERENCES items(id),
			tag     TEXT NOT NULL
		);
		CREATE INDEX idx_tags_item ON tags(item_id);
	`)
	if err != nil {
		t.Fatalf("create tables: %v", err)
	}
	return db
}

func TestSQLiteLoader_Load(t *testing.T) {
	db := openSQLite(t)
	loader := sqschema.NewLoader()
	s, err := loader.Load(db, "main")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	names := make(map[string]bool)
	for _, tbl := range s.Tables {
		names[tbl.Name] = true
	}
	if !names["items"] || !names["tags"] {
		t.Errorf("missing tables: %v", names)
	}
}

func TestSQLiteLoader_LoadTable_Columns(t *testing.T) {
	db := openSQLite(t)
	loader := sqschema.NewLoader()
	tbl, err := loader.LoadTable(db, "main", "items")
	if err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if len(tbl.Columns) != 3 {
		t.Errorf("columns: got %d want 3", len(tbl.Columns))
	}
}
```

- [ ] **Step 2: Run test — verify it fails**

```bash
go test ./pkg/schema/sqlite/... -v -run TestSQLiteLoader
```

- [ ] **Step 3: Implement SQLite loader**

```go
// pkg/schema/sqlite/loader.go
package sqlite

import (
	"database/sql"
	"fmt"
	"strings"

	schemalib "github.com/ajitpratap0/GoSQLX/pkg/schema"
)

// Loader implements schema.Loader for SQLite.
// SQLite uses PRAGMA commands instead of information_schema.
type Loader struct{}

// NewLoader returns a new SQLite schema loader.
func NewLoader() *Loader { return &Loader{} }

func (l *Loader) Load(db *sql.DB, schemaName string) (*schemalib.DatabaseSchema, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	defer rows.Close()

	ds := &schemalib.DatabaseSchema{Name: schemaName}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tbl, err := l.LoadTable(db, schemaName, name)
		if err != nil {
			return nil, err
		}
		ds.Tables = append(ds.Tables, *tbl)
	}
	return ds, rows.Err()
}

func (l *Loader) LoadTable(db *sql.DB, schemaName, tableName string) (*schemalib.Table, error) {
	tbl := &schemalib.Table{Schema: schemaName, Name: tableName}
	var err error
	tbl.Columns, err = l.loadColumns(db, tableName)
	if err != nil {
		return nil, err
	}
	tbl.Indexes, err = l.loadIndexes(db, tableName)
	if err != nil {
		return nil, err
	}
	tbl.ForeignKeys, err = l.loadForeignKeys(db, tableName)
	if err != nil {
		return nil, err
	}
	return tbl, nil
}

func (l *Loader) loadColumns(db *sql.DB, tableName string) ([]schemalib.Column, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%q)", tableName))
	if err != nil {
		return nil, fmt.Errorf("pragma table_info: %w", err)
	}
	defer rows.Close()

	var cols []schemalib.Column
	for rows.Next() {
		// cid, name, type, notnull, dflt_value, pk
		var cid, notNull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return nil, err
		}
		col := schemalib.Column{
			Name:       name,
			OrdinalPos: cid + 1,
			DataType:   typ,
			IsNullable: notNull == 0,
			IsPrimary:  pk > 0,
		}
		if dflt.Valid {
			col.DefaultValue = &dflt.String
		}
		cols = append(cols, col)
	}
	return cols, rows.Err()
}

func (l *Loader) loadIndexes(db *sql.DB, tableName string) ([]schemalib.Index, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA index_list(%q)", tableName))
	if err != nil {
		return nil, fmt.Errorf("pragma index_list: %w", err)
	}
	defer rows.Close()

	var indexes []schemalib.Index
	for rows.Next() {
		// seq, name, unique, origin, partial
		var seq, unique, partial int
		var name, origin string
		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			return nil, err
		}
		idx := schemalib.Index{
			Name:      name,
			TableName: tableName,
			IsUnique:  unique == 1,
		}
		// get columns in this index
		icols, err := db.Query(fmt.Sprintf("PRAGMA index_info(%q)", name))
		if err != nil {
			return nil, err
		}
		for icols.Next() {
			var seqno, cid int
			var colName string
			if err := icols.Scan(&seqno, &cid, &colName); err != nil {
				_ = icols.Close()
				return nil, err
			}
			idx.Columns = append(idx.Columns, colName)
		}
		_ = icols.Close()
		indexes = append(indexes, idx)
	}
	return indexes, rows.Err()
}

func (l *Loader) loadForeignKeys(db *sql.DB, tableName string) ([]schemalib.ForeignKey, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA foreign_key_list(%q)", tableName))
	if err != nil {
		return nil, fmt.Errorf("pragma foreign_key_list: %w", err)
	}
	defer rows.Close()

	fkMap := make(map[int]*schemalib.ForeignKey)
	var order []int
	for rows.Next() {
		// id, seq, table, from, to, on_update, on_delete, match
		var id, seq int
		var refTable, fromCol, toCol, onUpdate, onDelete, match string
		if err := rows.Scan(&id, &seq, &refTable, &fromCol, &toCol, &onUpdate, &onDelete, &match); err != nil {
			return nil, err
		}
		if _, ok := fkMap[id]; !ok {
			fkMap[id] = &schemalib.ForeignKey{
				Name:      fmt.Sprintf("fk_%s_%d", strings.ToLower(tableName), id),
				TableName: tableName,
				RefTable:  refTable,
				OnDelete:  onDelete,
				OnUpdate:  onUpdate,
			}
			order = append(order, id)
		}
		fkMap[id].Columns = append(fkMap[id].Columns, fromCol)
		fkMap[id].RefColumns = append(fkMap[id].RefColumns, toCol)
	}
	fks := make([]schemalib.ForeignKey, 0, len(order))
	for _, id := range order {
		fks = append(fks, *fkMap[id])
	}
	return fks, rows.Err()
}

var _ schemalib.Loader = (*Loader)(nil)
```

- [ ] **Step 4: Run SQLite tests**

```bash
go test ./pkg/schema/sqlite/... -v -run TestSQLiteLoader
```
Expected: PASS (no Docker needed).

- [ ] **Step 5: Commit**

```bash
git add pkg/schema/sqlite/
git commit -m "feat(schema): SQLite schema loader using PRAGMA commands"
```

---

### Task 7: Expose schema loading at gosqlx package level

**Files:**
- Modify: `pkg/gosqlx/gosqlx.go`

- [ ] **Step 1: Write test**

```go
// pkg/gosqlx/schema_test.go
package gosqlx_test

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	sqschema "github.com/ajitpratap0/GoSQLX/pkg/schema/sqlite"
)

func TestGoSQLX_LoadSchema(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _ = db.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")

	loader := sqschema.NewLoader()
	s, err := gosqlx.LoadSchema(db, loader, "main")
	if err != nil {
		t.Fatalf("LoadSchema: %v", err)
	}
	if len(s.Tables) == 0 {
		t.Error("expected at least one table")
	}
}
```

- [ ] **Step 2: Run test — verify it fails**

```bash
go test ./pkg/gosqlx/... -v -run TestGoSQLX_LoadSchema
```

- [ ] **Step 3: Add LoadSchema to gosqlx.go**

Add to `pkg/gosqlx/gosqlx.go` after existing functions:

```go
import (
    // existing imports...
    "database/sql"
    schemalib "github.com/ajitpratap0/GoSQLX/pkg/schema"
)

// LoadSchema connects to a live database and returns its schema metadata.
// Pass a dialect-specific loader from pkg/schema/postgres, pkg/schema/mysql, or pkg/schema/sqlite.
func LoadSchema(db *sql.DB, loader schemalib.Loader, schemaName string) (*schemalib.DatabaseSchema, error) {
    return loader.Load(db, schemaName)
}
```

- [ ] **Step 4: Run test**

```bash
go test ./pkg/gosqlx/... -v -run TestGoSQLX_LoadSchema
```
Expected: PASS.

- [ ] **Step 5: Run all tests with race detector**

```bash
task test:race
```
Expected: all pass, no races.

- [ ] **Step 6: Commit**

```bash
git add pkg/gosqlx/gosqlx.go pkg/gosqlx/schema_test.go
git commit -m "feat(gosqlx): expose LoadSchema convenience wrapper"
```

---

### Task 8: Update CHANGELOG.md and close GitHub issue

- [ ] **Step 1: Add CHANGELOG entry**

In `CHANGELOG.md` under `[Unreleased]`:

```markdown
### Added
- `pkg/schema/` package with `Loader` interface for live database schema introspection
- Postgres loader (`pkg/schema/postgres`) using `information_schema` and `pg_catalog`
- MySQL loader (`pkg/schema/mysql`) using `information_schema`
- SQLite loader (`pkg/schema/sqlite`) using PRAGMA commands (pure Go, no cgo)
- `gosqlx.LoadSchema()` top-level convenience wrapper
- Integration tests using `testcontainers-go` for Postgres and MySQL loaders
```

- [ ] **Step 2: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: add schema introspection to CHANGELOG"
```

- [ ] **Step 3: Close GitHub issue #448**

```bash
gh issue close 448 --comment "Implemented in pkg/schema/ with Postgres, MySQL, and SQLite loaders. See docs/superpowers/plans/2026-03-29-schema-introspection.md for implementation plan."
```
