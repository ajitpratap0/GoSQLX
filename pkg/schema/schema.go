// Package schema provides schema-aware SQL validation for GoSQLX.
//
// This package allows users to define database schemas (tables, columns,
// constraints) and validate SQL queries against them. It can detect
// references to non-existent tables or columns, ambiguous column references,
// and INSERT column count mismatches.
//
// Schemas can be built programmatically or loaded from DDL (CREATE TABLE)
// statements using GoSQLX's own parser.
//
// Example - Programmatic schema building:
//
//	s := schema.NewSchema("mydb")
//	t := schema.NewTable("users")
//	t.AddColumn(&schema.Column{Name: "id", DataType: "INT", Nullable: false})
//	t.AddColumn(&schema.Column{Name: "name", DataType: "VARCHAR(100)", Nullable: false})
//	s.AddTable(t)
//
//	v := schema.NewValidator(s)
//	errors, err := v.Validate("SELECT id, name FROM users")
//
// Example - Loading schema from DDL:
//
//	ddl := `CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100) NOT NULL);`
//	s, err := schema.LoadFromDDL(ddl)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	v := schema.NewValidator(s)
//	errors, _ := v.Validate("SELECT email FROM users")
//	// errors[0].Message: column "email" does not exist in table "users"
package schema

import (
	"sort"
	"strings"
)

// Schema represents a database schema with tables, columns, and constraints.
type Schema struct {
	Name   string
	Tables map[string]*Table
}

// Table represents a database table.
type Table struct {
	Name        string
	Columns     map[string]*Column
	PrimaryKey  []string
	ForeignKeys []ForeignKey
	Indexes     []Index
}

// Column represents a table column.
type Column struct {
	Name       string
	DataType   string
	Nullable   bool
	Default    string
	References *ForeignKeyRef // if this column references another table
}

// ForeignKey represents a foreign key constraint.
type ForeignKey struct {
	Name       string
	Columns    []string
	RefTable   string
	RefColumns []string
}

// ForeignKeyRef is a column-level FK reference.
type ForeignKeyRef struct {
	Table  string
	Column string
}

// Index represents a table index.
type Index struct {
	Name    string
	Columns []string
	Unique  bool
}

// NewSchema creates a new Schema with the given name.
func NewSchema(name string) *Schema {
	return &Schema{
		Name:   name,
		Tables: make(map[string]*Table),
	}
}

// AddTable adds a table to the schema. If a table with the same name already
// exists, it is replaced. Tables are stored with their original name but
// lookups are case-insensitive.
func (s *Schema) AddTable(table *Table) {
	s.Tables[strings.ToLower(table.Name)] = table
}

// GetTable looks up a table by name. Returns the table and true if found,
// or nil and false if not found. The lookup is case-insensitive.
func (s *Schema) GetTable(name string) (*Table, bool) {
	t, ok := s.Tables[strings.ToLower(name)]
	return t, ok
}

// TableNames returns a sorted list of all table names in the schema,
// using the original names from the Table structs.
func (s *Schema) TableNames() []string {
	names := make([]string, 0, len(s.Tables))
	for _, t := range s.Tables {
		names = append(names, t.Name)
	}
	sort.Strings(names)
	return names
}

// NewTable creates a new Table with the given name.
func NewTable(name string) *Table {
	return &Table{
		Name:    name,
		Columns: make(map[string]*Column),
	}
}

// AddColumn adds a column to the table. If a column with the same name
// already exists, it is replaced. Columns are stored with their original
// name but lookups are case-insensitive.
func (t *Table) AddColumn(col *Column) {
	t.Columns[strings.ToLower(col.Name)] = col
}

// GetColumn looks up a column by name. Returns the column and true if found,
// or nil and false if not found. The lookup is case-insensitive.
func (t *Table) GetColumn(name string) (*Column, bool) {
	c, ok := t.Columns[strings.ToLower(name)]
	return c, ok
}

// ColumnNames returns a sorted list of all column names in the table,
// using the original names from the Column structs.
func (t *Table) ColumnNames() []string {
	names := make([]string, 0, len(t.Columns))
	for _, c := range t.Columns {
		names = append(names, c.Name)
	}
	sort.Strings(names)
	return names
}
