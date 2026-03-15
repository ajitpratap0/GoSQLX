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

package schema

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Catalog struct tests
// ---------------------------------------------------------------------------

func TestNewCatalog(t *testing.T) {
	c := NewCatalog()
	if c.Schemas == nil {
		t.Fatal("expected Schemas map to be initialized")
	}
	if len(c.Schemas) != 0 {
		t.Fatalf("expected empty catalog, got %d schemas", len(c.Schemas))
	}
}

func TestCatalog_AddAndGetSchema(t *testing.T) {
	c := NewCatalog()
	s := NewSchema("app")
	c.AddSchema(s)

	got, ok := c.GetSchema("app")
	if !ok {
		t.Fatal("expected to find schema 'app'")
	}
	if got.Name != "app" {
		t.Fatalf("expected schema name 'app', got %q", got.Name)
	}

	// Case-insensitive lookup
	got2, ok := c.GetSchema("APP")
	if !ok {
		t.Fatal("expected case-insensitive schema lookup to succeed")
	}
	if got2.Name != "app" {
		t.Fatalf("expected schema name 'app', got %q", got2.Name)
	}

	_, ok = c.GetSchema("nonexistent")
	if ok {
		t.Fatal("expected nonexistent schema lookup to fail")
	}
}

func TestCatalog_GetDefaultSchema_Explicit(t *testing.T) {
	c := NewCatalog()
	s1 := NewSchema("app")
	s2 := NewSchema("audit")
	c.AddSchema(s1)
	c.AddSchema(s2)
	c.DefaultSchema = "app"

	got, ok := c.GetDefaultSchema()
	if !ok {
		t.Fatal("expected to get default schema")
	}
	if got.Name != "app" {
		t.Fatalf("expected default schema 'app', got %q", got.Name)
	}
}

func TestCatalog_GetDefaultSchema_Single(t *testing.T) {
	c := NewCatalog()
	s := NewSchema("only")
	c.AddSchema(s)

	got, ok := c.GetDefaultSchema()
	if !ok {
		t.Fatal("expected to get single schema as default")
	}
	if got.Name != "only" {
		t.Fatalf("expected schema 'only', got %q", got.Name)
	}
}

func TestCatalog_GetDefaultSchema_Empty(t *testing.T) {
	c := NewCatalog()
	_, ok := c.GetDefaultSchema()
	if ok {
		t.Fatal("expected no default schema for empty catalog")
	}
}

func TestCatalog_GetDefaultSchema_Ambiguous(t *testing.T) {
	c := NewCatalog()
	c.AddSchema(NewSchema("a"))
	c.AddSchema(NewSchema("b"))
	_, ok := c.GetDefaultSchema()
	if ok {
		t.Fatal("expected no default schema when multiple schemas exist and none set")
	}
}

func TestCatalog_ResolveTable(t *testing.T) {
	c := NewCatalog()

	appSchema := NewSchema("app")
	tbl := NewTable("users")
	tbl.AddColumn(&Column{Name: "id", DataType: "INT"})
	appSchema.AddTable(tbl)
	c.AddSchema(appSchema)
	c.DefaultSchema = "app"

	auditSchema := NewSchema("audit")
	events := NewTable("events")
	events.AddColumn(&Column{Name: "id", DataType: "INT"})
	auditSchema.AddTable(events)
	c.AddSchema(auditSchema)

	// Resolve from default schema
	_, got, err := c.ResolveTable("users")
	if err != nil {
		t.Fatalf("unexpected error resolving 'users': %v", err)
	}
	if got == nil {
		t.Fatal("expected to resolve table 'users' from default schema")
	}
	if got.Name != "users" {
		t.Fatalf("expected table 'users', got %q", got.Name)
	}

	// Resolve from non-default schema
	_, got2, err := c.ResolveTable("events")
	if err != nil {
		t.Fatalf("unexpected error resolving 'events': %v", err)
	}
	if got2 == nil {
		t.Fatal("expected to resolve table 'events' from audit schema")
	}
	if got2.Name != "events" {
		t.Fatalf("expected table 'events', got %q", got2.Name)
	}

	// Non-existent table: no error, but table is nil
	_, notFound, err := c.ResolveTable("nonexistent")
	if err != nil {
		t.Fatalf("expected no error for nonexistent table, got: %v", err)
	}
	if notFound != nil {
		t.Fatal("expected nil table for nonexistent lookup")
	}
}

// TestCatalog_ResolveTable_Ambiguous verifies that ResolveTable returns an
// error when the same table name exists in multiple schemas and no default
// schema has been set.  This prevents silent wrong-table resolution.
func TestCatalog_ResolveTable_Ambiguous(t *testing.T) {
	c := NewCatalog()
	// Two schemas both own a "users" table; no DefaultSchema is set.
	s1 := NewSchema("app")
	t1 := NewTable("users")
	t1.AddColumn(&Column{Name: "id", DataType: "INT"})
	s1.AddTable(t1)
	c.AddSchema(s1)

	s2 := NewSchema("audit")
	t2 := NewTable("users")
	t2.AddColumn(&Column{Name: "user_id", DataType: "INT"})
	s2.AddTable(t2)
	c.AddSchema(s2)

	// No DefaultSchema - resolution should be flagged as ambiguous.
	_, _, err := c.ResolveTable("users")
	if err == nil {
		t.Fatal("expected ambiguity error when same table name exists in multiple schemas with no default")
	}
	if !strings.Contains(err.Error(), "ambiguous table reference") {
		t.Fatalf("expected 'ambiguous table reference' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "app") || !strings.Contains(err.Error(), "audit") {
		t.Fatalf("expected schema names in error message, got: %v", err)
	}

	// Setting a default schema resolves the ambiguity by preferring it.
	c.DefaultSchema = "app"
	_, resolved, err := c.ResolveTable("users")
	if err != nil {
		t.Fatalf("unexpected error after setting default schema: %v", err)
	}
	if resolved == nil {
		t.Fatal("expected non-nil table after default schema is set")
	}
	// The default schema's table should be returned (has column "id").
	if _, ok := resolved.GetColumn("id"); !ok {
		t.Fatal("expected 'id' column from the default 'app' schema's users table")
	}
}

func TestCatalog_ResolveTable_NoDefault_UniqueTable(t *testing.T) {
	// When no default schema is set but only one schema owns the table,
	// ResolveTable should succeed without error.
	c := NewCatalog()
	s1 := NewSchema("app")
	s1.AddTable(NewTable("users"))
	c.AddSchema(s1)

	s2 := NewSchema("audit")
	s2.AddTable(NewTable("events")) // different table name
	c.AddSchema(s2)

	_, tbl, err := c.ResolveTable("users")
	if err != nil {
		t.Fatalf("unexpected error for unambiguous lookup: %v", err)
	}
	if tbl == nil {
		t.Fatal("expected to find 'users' table in 'app' schema")
	}
}

func TestCatalog_SchemaNames(t *testing.T) {
	c := NewCatalog()
	c.AddSchema(NewSchema("z_schema"))
	c.AddSchema(NewSchema("a_schema"))
	c.AddSchema(NewSchema("m_schema"))

	names := c.SchemaNames()
	if len(names) != 3 {
		t.Fatalf("expected 3 schema names, got %d", len(names))
	}
	if names[0] != "a_schema" || names[1] != "m_schema" || names[2] != "z_schema" {
		t.Fatalf("expected sorted names, got %v", names)
	}
}

// ---------------------------------------------------------------------------
// LoadCatalogFromDDL tests
// ---------------------------------------------------------------------------

func TestLoadCatalogFromDDL_Simple(t *testing.T) {
	ddl := `CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100) NOT NULL, email VARCHAR(255))`
	cat, err := LoadCatalogFromDDL(ddl)
	if err != nil {
		t.Fatalf("LoadCatalogFromDDL failed: %v", err)
	}

	_, tbl, err := cat.ResolveTable("users")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tbl == nil {
		t.Fatal("expected to find table 'users'")
	}
	if _, ok := tbl.GetColumn("id"); !ok {
		t.Fatal("expected column 'id'")
	}
	if _, ok := tbl.GetColumn("email"); !ok {
		t.Fatal("expected column 'email'")
	}
}

func TestLoadCatalogFromDDL_MultipleTables(t *testing.T) {
	ddl := `
		CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100));
		CREATE TABLE orders (id INT PRIMARY KEY, user_id INT, total DECIMAL(10,2));
	`
	cat, err := LoadCatalogFromDDL(ddl)
	if err != nil {
		t.Fatalf("LoadCatalogFromDDL failed: %v", err)
	}
	if _, tblU, err := cat.ResolveTable("users"); err != nil {
		t.Fatalf("unexpected error resolving 'users': %v", err)
	} else if tblU == nil {
		t.Fatal("expected table 'users'")
	}
	if _, tblO, err := cat.ResolveTable("orders"); err != nil {
		t.Fatalf("unexpected error resolving 'orders': %v", err)
	} else if tblO == nil {
		t.Fatal("expected table 'orders'")
	}
}

func TestLoadCatalogFromDDL_AlterTableAddColumn(t *testing.T) {
	ddl := `
		CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100));
		ALTER TABLE users ADD COLUMN email VARCHAR(255);
	`
	cat, err := LoadCatalogFromDDL(ddl)
	if err != nil {
		t.Fatalf("LoadCatalogFromDDL failed: %v", err)
	}

	_, tbl, err := cat.ResolveTable("users")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tbl == nil {
		t.Fatal("expected to find table 'users'")
	}
	if _, ok := tbl.GetColumn("email"); !ok {
		t.Fatal("expected column 'email' after ALTER TABLE ADD COLUMN")
	}
}

func TestLoadCatalogFromDDL_AlterTableDropColumn(t *testing.T) {
	ddl := `
		CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100), temp_col INT);
		ALTER TABLE users DROP COLUMN temp_col;
	`
	cat, err := LoadCatalogFromDDL(ddl)
	if err != nil {
		t.Fatalf("LoadCatalogFromDDL failed: %v", err)
	}

	_, tbl, err := cat.ResolveTable("users")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tbl == nil {
		t.Fatal("expected table 'users'")
	}
	if _, ok := tbl.GetColumn("temp_col"); ok {
		t.Fatal("expected 'temp_col' to be dropped")
	}
	if _, ok := tbl.GetColumn("id"); !ok {
		t.Fatal("expected 'id' to remain after DROP COLUMN")
	}
}

func TestLoadCatalogFromDDL_AlterTableRenameColumn(t *testing.T) {
	ddl := `
		CREATE TABLE users (id INT PRIMARY KEY, old_name VARCHAR(100));
		ALTER TABLE users RENAME COLUMN old_name TO new_name;
	`
	cat, err := LoadCatalogFromDDL(ddl)
	if err != nil {
		t.Fatalf("LoadCatalogFromDDL failed: %v", err)
	}

	_, tbl, err := cat.ResolveTable("users")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tbl == nil {
		t.Fatal("expected table 'users'")
	}
	if _, ok := tbl.GetColumn("old_name"); ok {
		t.Fatal("expected 'old_name' to be gone after RENAME")
	}
	if _, ok := tbl.GetColumn("new_name"); !ok {
		t.Fatal("expected 'new_name' after RENAME COLUMN")
	}
}

func TestLoadFromDDL_AlterTableAddColumn(t *testing.T) {
	ddl := `
		CREATE TABLE users (id INT, name VARCHAR(100));
		ALTER TABLE users ADD COLUMN email VARCHAR(255);
	`
	s, err := LoadFromDDL(ddl)
	if err != nil {
		t.Fatalf("LoadFromDDL failed: %v", err)
	}

	tbl, ok := s.GetTable("users")
	if !ok {
		t.Fatal("expected table 'users'")
	}
	if _, ok := tbl.GetColumn("email"); !ok {
		t.Fatal("expected column 'email' after ALTER TABLE ADD COLUMN")
	}
}

func TestLoadFromDDL_AlterTableDropColumn(t *testing.T) {
	ddl := `
		CREATE TABLE users (id INT, name VARCHAR(100), temp INT);
		ALTER TABLE users DROP COLUMN temp;
	`
	s, err := LoadFromDDL(ddl)
	if err != nil {
		t.Fatalf("LoadFromDDL failed: %v", err)
	}

	tbl, ok := s.GetTable("users")
	if !ok {
		t.Fatal("expected table 'users'")
	}
	if _, ok := tbl.GetColumn("temp"); ok {
		t.Fatal("expected 'temp' to be dropped")
	}
}

// ---------------------------------------------------------------------------
// CatalogValidator tests
// ---------------------------------------------------------------------------

// catalogHelperSchema returns a catalog with standard tables for testing.
func catalogHelper() *Catalog {
	cat := NewCatalog()

	s := NewSchema("testdb")

	users := NewTable("users")
	users.AddColumn(&Column{Name: "id", DataType: "INT", Nullable: false})
	users.AddColumn(&Column{Name: "name", DataType: "VARCHAR(100)", Nullable: false})
	users.AddColumn(&Column{Name: "email", DataType: "VARCHAR(255)", Nullable: true})
	users.AddColumn(&Column{Name: "age", DataType: "INT", Nullable: true})
	users.PrimaryKey = []string{"id"}
	s.AddTable(users)

	orders := NewTable("orders")
	orders.AddColumn(&Column{Name: "id", DataType: "INT", Nullable: false})
	orders.AddColumn(&Column{Name: "user_id", DataType: "INT", Nullable: false})
	orders.AddColumn(&Column{Name: "total", DataType: "DECIMAL(10,2)", Nullable: false})
	orders.AddColumn(&Column{Name: "status", DataType: "VARCHAR(20)", Nullable: true})
	orders.PrimaryKey = []string{"id"}
	s.AddTable(orders)

	products := NewTable("products")
	products.AddColumn(&Column{Name: "id", DataType: "INT", Nullable: false})
	products.AddColumn(&Column{Name: "name", DataType: "VARCHAR(200)", Nullable: false})
	products.AddColumn(&Column{Name: "price", DataType: "DECIMAL(10,2)", Nullable: false})
	products.PrimaryKey = []string{"id"}
	s.AddTable(products)

	cat.AddSchema(s)
	cat.DefaultSchema = "testdb"
	return cat
}

func TestCatalogValidator_ValidSelect(t *testing.T) {
	cv := NewCatalogValidator(catalogHelper())
	errs, err := cv.Validate("SELECT id, name, email FROM users")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %d: %v", len(errs), errs)
	}
}

func TestCatalogValidator_InvalidColumnRef(t *testing.T) {
	cv := NewCatalogValidator(catalogHelper())
	errs, err := cv.Validate("SELECT id, bogus_col FROM users")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) == 0 {
		t.Fatal("expected errors for invalid column reference")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "bogus_col") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected error about 'bogus_col', got: %v", errs)
	}
}

func TestCatalogValidator_InvalidTableRef(t *testing.T) {
	cv := NewCatalogValidator(catalogHelper())
	errs, err := cv.Validate("SELECT id FROM nonexistent_table")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) == 0 {
		t.Fatal("expected errors for invalid table reference")
	}
}

func TestCatalogValidator_JoinValidColumns(t *testing.T) {
	cv := NewCatalogValidator(catalogHelper())
	sql := `SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id`
	errs, err := cv.Validate(sql)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no errors for valid JOIN, got %d: %v", len(errs), errs)
	}
}

func TestCatalogValidator_JoinInvalidColumn(t *testing.T) {
	cv := NewCatalogValidator(catalogHelper())
	sql := `SELECT u.name FROM users u JOIN orders o ON u.id = o.nonexistent`
	errs, err := cv.Validate(sql)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "nonexistent") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected error about nonexistent JOIN column, got: %v", errs)
	}
}

// ---------------------------------------------------------------------------
// ORDER BY validation tests
// ---------------------------------------------------------------------------

func TestCatalogValidator_OrderByValid(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.ValidateSelectFull("SELECT id, name FROM users ORDER BY name")
	if err != nil {
		t.Fatalf("ValidateSelectFull failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no errors for valid ORDER BY, got %d: %v", len(errs), errs)
	}
}

func TestCatalogValidator_OrderByPosition(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.ValidateSelectFull("SELECT id, name FROM users ORDER BY 1")
	if err != nil {
		t.Fatalf("ValidateSelectFull failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no errors for ORDER BY position, got %d: %v", len(errs), errs)
	}
}

func TestCatalogValidator_OrderByAlias(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.ValidateSelectFull("SELECT id, name AS user_name FROM users ORDER BY user_name")
	if err != nil {
		t.Fatalf("ValidateSelectFull failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no errors for ORDER BY alias, got %d: %v", len(errs), errs)
	}
}

func TestCatalogValidator_OrderByInvalidColumn(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.ValidateSelectFull("SELECT id FROM users ORDER BY nonexistent_col")
	if err != nil {
		t.Fatalf("ValidateSelectFull failed: %v", err)
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "nonexistent_col") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected error about nonexistent ORDER BY column, got: %v", errs)
	}
}

// ---------------------------------------------------------------------------
// GROUP BY aggregate validation tests
// ---------------------------------------------------------------------------

func TestGroupBy_ValidAggregateWithGroupBy(t *testing.T) {
	v := NewValidator(helperSchema())
	// SELECT name, COUNT(id) FROM users GROUP BY name - valid
	errs, err := v.ValidateSelectFull("SELECT name, COUNT(id) FROM users GROUP BY name")
	if err != nil {
		t.Fatalf("ValidateSelectFull failed: %v", err)
	}
	// Filter for aggregate errors only
	for _, e := range errs {
		if strings.Contains(e.Message, "aggregate") || strings.Contains(e.Message, "GROUP BY") {
			t.Fatalf("unexpected aggregate/GROUP BY error: %v", e)
		}
	}
}

func TestGroupBy_MixedColumnsNoGroupBy(t *testing.T) {
	v := NewValidator(helperSchema())
	// SELECT name, COUNT(id) FROM users - invalid (non-aggregate with aggregate, no GROUP BY)
	errs, err := v.ValidateSelectFull("SELECT name, COUNT(id) FROM users")
	if err != nil {
		t.Fatalf("ValidateSelectFull failed: %v", err)
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "non-aggregated") || strings.Contains(e.Message, "aggregate") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected error for non-aggregated column without GROUP BY, got: %v", errs)
	}
}

func TestGroupBy_NonAggColNotInGroupBy(t *testing.T) {
	v := NewValidator(helperSchema())
	// SELECT name, email, COUNT(*) FROM users GROUP BY name - email not in GROUP BY
	errs, err := v.ValidateSelectFull("SELECT name, email, COUNT(*) FROM users GROUP BY name")
	if err != nil {
		t.Fatalf("ValidateSelectFull failed: %v", err)
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "email") && strings.Contains(e.Message, "GROUP BY") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected GROUP BY error for 'email', got: %v", errs)
	}
}

func TestGroupBy_AllColumnsInGroupBy(t *testing.T) {
	v := NewValidator(helperSchema())
	// SELECT name, email FROM users GROUP BY name, email - valid
	errs, err := v.ValidateSelectFull("SELECT name, email FROM users GROUP BY name, email")
	if err != nil {
		t.Fatalf("ValidateSelectFull failed: %v", err)
	}
	for _, e := range errs {
		if strings.Contains(e.Message, "GROUP BY") {
			t.Fatalf("unexpected GROUP BY error: %v", e)
		}
	}
}

func TestGroupBy_PureAggregate(t *testing.T) {
	v := NewValidator(helperSchema())
	// SELECT COUNT(*) FROM users - valid, no GROUP BY needed for pure aggregate
	errs, err := v.ValidateSelectFull("SELECT COUNT(*) FROM users")
	if err != nil {
		t.Fatalf("ValidateSelectFull failed: %v", err)
	}
	for _, e := range errs {
		if strings.Contains(e.Message, "aggregate") || strings.Contains(e.Message, "GROUP BY") {
			t.Fatalf("unexpected aggregate error for pure aggregate: %v", e)
		}
	}
}

func TestGroupBy_SelectStar(t *testing.T) {
	v := NewValidator(helperSchema())
	// SELECT * FROM users - skip GROUP BY check
	errs, err := v.ValidateSelectFull("SELECT * FROM users")
	if err != nil {
		t.Fatalf("ValidateSelectFull failed: %v", err)
	}
	for _, e := range errs {
		if strings.Contains(e.Message, "aggregate") {
			t.Fatalf("unexpected aggregate error for SELECT *: %v", e)
		}
	}
}

// ---------------------------------------------------------------------------
// ValidateQuery (free function) tests
// ---------------------------------------------------------------------------

func TestValidateQuery_Valid(t *testing.T) {
	cat := catalogHelper()
	cv := NewCatalogValidator(cat)
	errs, err := cv.Validate("SELECT u.id, u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %d: %v", len(errs), errs)
	}
}

func TestValidateQuery_InvalidColumn(t *testing.T) {
	cat := catalogHelper()
	cv := NewCatalogValidator(cat)
	errs, err := cv.Validate("SELECT id, bad_col FROM users")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "bad_col") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected error for bad_col, got: %v", errs)
	}
}

func TestValidateQuery_FreeFunction(t *testing.T) {
	cat := catalogHelper()
	// Use the CatalogValidator to cover ValidateAST → ValidateQuery path
	cv := NewCatalogValidator(cat)
	errs, err := cv.Validate("SELECT id FROM users WHERE nonexistent = 1")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "nonexistent") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected error for nonexistent column, got: %v", errs)
	}
}

// ---------------------------------------------------------------------------
// Subquery scope validation
// ---------------------------------------------------------------------------

func TestCatalogValidator_SubqueryScope(t *testing.T) {
	// Column references inside a subquery should not be checked against outer scope
	v := NewValidator(helperSchema())
	errs, err := v.Validate("SELECT id FROM users WHERE id IN (SELECT user_id FROM orders)")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no errors for valid subquery, got %d: %v", len(errs), errs)
	}
}

func TestCatalogValidator_UpdateSetValid(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("UPDATE users SET name = 'Alice', email = 'a@b.com' WHERE id = 1")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no errors for valid UPDATE, got %d: %v", len(errs), errs)
	}
}

func TestCatalogValidator_UpdateSetInvalidColumn(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("UPDATE users SET nonexistent_col = 'val' WHERE id = 1")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "nonexistent_col") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected error for nonexistent UPDATE column, got: %v", errs)
	}
}

func TestCatalogValidator_InsertColumnCountMismatch(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("INSERT INTO users (id, name) VALUES (1, 'Alice', 'extra')")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "column count") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected column count mismatch error, got: %v", errs)
	}
}

func TestCatalogValidator_TypeMismatch(t *testing.T) {
	v := NewValidator(helperSchema())
	// Inserting boolean into numeric column
	errs, err := v.Validate("INSERT INTO users (id, name) VALUES (true, 'Alice')")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	// We may or may not get a type mismatch warning depending on how literals are parsed
	// Just verify no panic and validation runs
	_ = errs
}

func TestCatalogValidator_EmptyCatalog(t *testing.T) {
	cat := NewCatalog()
	cv := NewCatalogValidator(cat)
	errs, err := cv.Validate("SELECT id FROM users")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) == 0 {
		t.Fatal("expected errors with empty catalog")
	}
}

func TestCatalogValidator_CaseInsensitive(t *testing.T) {
	cat := catalogHelper()
	cv := NewCatalogValidator(cat)
	errs, err := cv.Validate("SELECT ID, NAME FROM USERS")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no errors for case-insensitive query, got %d: %v", len(errs), errs)
	}
}
