package schema

import (
	"testing"
)

func TestNewSchema(t *testing.T) {
	s := NewSchema("testdb")
	if s.Name != "testdb" {
		t.Fatalf("expected schema name %q, got %q", "testdb", s.Name)
	}
	if s.Tables == nil {
		t.Fatal("expected Tables map to be initialized")
	}
	if len(s.Tables) != 0 {
		t.Fatalf("expected empty Tables, got %d", len(s.Tables))
	}
}

func TestNewTable(t *testing.T) {
	tbl := NewTable("users")
	if tbl.Name != "users" {
		t.Fatalf("expected table name %q, got %q", "users", tbl.Name)
	}
	if tbl.Columns == nil {
		t.Fatal("expected Columns map to be initialized")
	}
	if len(tbl.Columns) != 0 {
		t.Fatalf("expected empty Columns, got %d", len(tbl.Columns))
	}
}

func TestSchema_AddAndGetTable(t *testing.T) {
	s := NewSchema("testdb")
	tbl := NewTable("users")
	tbl.AddColumn(&Column{Name: "id", DataType: "INT"})

	s.AddTable(tbl)

	// Successful lookup
	got, ok := s.GetTable("users")
	if !ok {
		t.Fatal("expected to find table 'users'")
	}
	if got.Name != "users" {
		t.Fatalf("expected table name %q, got %q", "users", got.Name)
	}

	// Missing table lookup
	_, ok = s.GetTable("nonexistent")
	if ok {
		t.Fatal("expected not to find table 'nonexistent'")
	}
}

func TestSchema_AddTable_Replacement(t *testing.T) {
	s := NewSchema("testdb")
	tbl1 := NewTable("users")
	tbl1.AddColumn(&Column{Name: "id", DataType: "INT"})
	s.AddTable(tbl1)

	// Replace with a different table of the same name
	tbl2 := NewTable("users")
	tbl2.AddColumn(&Column{Name: "id", DataType: "BIGINT"})
	tbl2.AddColumn(&Column{Name: "name", DataType: "VARCHAR(100)"})
	s.AddTable(tbl2)

	got, ok := s.GetTable("users")
	if !ok {
		t.Fatal("expected to find table 'users'")
	}
	if len(got.Columns) != 2 {
		t.Fatalf("expected 2 columns after replacement, got %d", len(got.Columns))
	}
}

func TestSchema_TableNames(t *testing.T) {
	s := NewSchema("testdb")
	s.AddTable(NewTable("orders"))
	s.AddTable(NewTable("users"))
	s.AddTable(NewTable("products"))

	names := s.TableNames()
	expected := []string{"orders", "products", "users"}

	if len(names) != len(expected) {
		t.Fatalf("expected %d table names, got %d", len(expected), len(names))
	}
	for i, name := range names {
		if name != expected[i] {
			t.Fatalf("expected table name %q at index %d, got %q", expected[i], i, name)
		}
	}
}

func TestTable_AddAndGetColumn(t *testing.T) {
	tbl := NewTable("users")
	col := &Column{Name: "id", DataType: "INT", Nullable: false}
	tbl.AddColumn(col)

	// Successful lookup
	got, ok := tbl.GetColumn("id")
	if !ok {
		t.Fatal("expected to find column 'id'")
	}
	if got.Name != "id" {
		t.Fatalf("expected column name %q, got %q", "id", got.Name)
	}
	if got.DataType != "INT" {
		t.Fatalf("expected data type %q, got %q", "INT", got.DataType)
	}
	if got.Nullable {
		t.Fatal("expected column to be non-nullable")
	}

	// Missing column lookup
	_, ok = tbl.GetColumn("nonexistent")
	if ok {
		t.Fatal("expected not to find column 'nonexistent'")
	}
}

func TestTable_ColumnNames(t *testing.T) {
	tbl := NewTable("users")
	tbl.AddColumn(&Column{Name: "name", DataType: "VARCHAR"})
	tbl.AddColumn(&Column{Name: "id", DataType: "INT"})
	tbl.AddColumn(&Column{Name: "email", DataType: "VARCHAR"})

	names := tbl.ColumnNames()
	expected := []string{"email", "id", "name"}

	if len(names) != len(expected) {
		t.Fatalf("expected %d column names, got %d", len(expected), len(names))
	}
	for i, name := range names {
		if name != expected[i] {
			t.Fatalf("expected column name %q at index %d, got %q", expected[i], i, name)
		}
	}
}

func TestColumn_WithReferences(t *testing.T) {
	col := &Column{
		Name:     "user_id",
		DataType: "INT",
		Nullable: false,
		References: &ForeignKeyRef{
			Table:  "users",
			Column: "id",
		},
	}

	if col.References == nil {
		t.Fatal("expected References to be set")
	}
	if col.References.Table != "users" {
		t.Fatalf("expected reference table %q, got %q", "users", col.References.Table)
	}
	if col.References.Column != "id" {
		t.Fatalf("expected reference column %q, got %q", "id", col.References.Column)
	}
}

func TestColumn_WithDefault(t *testing.T) {
	col := &Column{
		Name:     "created_at",
		DataType: "TIMESTAMP",
		Nullable: false,
		Default:  "CURRENT_TIMESTAMP",
	}

	if col.Default != "CURRENT_TIMESTAMP" {
		t.Fatalf("expected default %q, got %q", "CURRENT_TIMESTAMP", col.Default)
	}
}

func TestTable_ForeignKeys(t *testing.T) {
	tbl := NewTable("orders")
	tbl.ForeignKeys = []ForeignKey{
		{
			Name:       "fk_user",
			Columns:    []string{"user_id"},
			RefTable:   "users",
			RefColumns: []string{"id"},
		},
	}

	if len(tbl.ForeignKeys) != 1 {
		t.Fatalf("expected 1 foreign key, got %d", len(tbl.ForeignKeys))
	}
	fk := tbl.ForeignKeys[0]
	if fk.Name != "fk_user" {
		t.Fatalf("expected FK name %q, got %q", "fk_user", fk.Name)
	}
	if fk.RefTable != "users" {
		t.Fatalf("expected FK ref table %q, got %q", "users", fk.RefTable)
	}
}

func TestTable_Indexes(t *testing.T) {
	tbl := NewTable("users")
	tbl.Indexes = []Index{
		{
			Name:    "idx_email",
			Columns: []string{"email"},
			Unique:  true,
		},
		{
			Name:    "idx_name",
			Columns: []string{"first_name", "last_name"},
			Unique:  false,
		},
	}

	if len(tbl.Indexes) != 2 {
		t.Fatalf("expected 2 indexes, got %d", len(tbl.Indexes))
	}
	if !tbl.Indexes[0].Unique {
		t.Fatal("expected first index to be unique")
	}
	if tbl.Indexes[1].Unique {
		t.Fatal("expected second index to not be unique")
	}
}

func TestTable_PrimaryKey(t *testing.T) {
	tbl := NewTable("users")
	tbl.PrimaryKey = []string{"id"}

	if len(tbl.PrimaryKey) != 1 {
		t.Fatalf("expected 1 primary key column, got %d", len(tbl.PrimaryKey))
	}
	if tbl.PrimaryKey[0] != "id" {
		t.Fatalf("expected primary key column %q, got %q", "id", tbl.PrimaryKey[0])
	}
}

func TestSchema_EmptyTableNames(t *testing.T) {
	s := NewSchema("empty")
	names := s.TableNames()
	if len(names) != 0 {
		t.Fatalf("expected 0 table names, got %d", len(names))
	}
}

func TestTable_EmptyColumnNames(t *testing.T) {
	tbl := NewTable("empty")
	names := tbl.ColumnNames()
	if len(names) != 0 {
		t.Fatalf("expected 0 column names, got %d", len(names))
	}
}
