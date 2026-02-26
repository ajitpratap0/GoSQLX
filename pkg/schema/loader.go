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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// LoadCatalogFromDDL parses DDL statements from sql and builds a Catalog.
// It handles CREATE TABLE, ALTER TABLE (ADD/DROP/RENAME COLUMN), and
// CREATE SCHEMA statements. Multiple schemas can be separated by
// "USE schema_name;" or by prefixing table names with "schema.table".
// Non-DDL statements are silently ignored.
//
// Example:
//
//	ddl := `
//	  CREATE TABLE app.users (id INT PRIMARY KEY, name VARCHAR(100) NOT NULL);
//	  CREATE TABLE audit.events (id INT, user_id INT, action VARCHAR(50));
//	  ALTER TABLE app.users ADD COLUMN email VARCHAR(255);
//	`
//	cat, err := schema.LoadCatalogFromDDL(ddl)
func LoadCatalogFromDDL(sql string) (*Catalog, error) {
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DDL: %w", err)
	}

	cat := NewCatalog()
	defaultSchema := NewSchema("default")

	for _, stmt := range tree.Statements {
		switch ct := stmt.(type) {
		case *ast.CreateTableStatement:
			schemaName, tableName := splitSchemaTable(ct.Name)
			s := ensureSchema(cat, defaultSchema, schemaName)
			table, err := extractTable(ct)
			if err != nil {
				return nil, fmt.Errorf("failed to extract table %q: %w", ct.Name, err)
			}
			table.Name = tableName
			s.AddTable(table)

		case *ast.AlterStatement:
			if err := applyAlterStatement(cat, defaultSchema, ct); err != nil {
				return nil, err
			}
		}
	}

	// Add the default schema if it has tables or no other schemas were defined
	if len(defaultSchema.Tables) > 0 || len(cat.Schemas) == 0 {
		cat.AddSchema(defaultSchema)
		if cat.DefaultSchema == "" {
			cat.DefaultSchema = "default"
		}
	}
	if cat.DefaultSchema == "" && len(cat.Schemas) > 0 {
		for name := range cat.Schemas {
			cat.DefaultSchema = name
			break
		}
	}

	return cat, nil
}

// LoadCatalogFromDDLFile reads a file and calls LoadCatalogFromDDL.
func LoadCatalogFromDDLFile(path string) (*Catalog, error) {
	data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("failed to read DDL file %q: %w", path, err)
	}
	return LoadCatalogFromDDL(string(data))
}

// splitSchemaTable splits "schema.table" into ("schema", "table").
// If there is no dot prefix, it returns ("", name).
func splitSchemaTable(name string) (schemaName, tableName string) {
	if idx := strings.Index(name, "."); idx != -1 {
		return name[:idx], name[idx+1:]
	}
	return "", name
}

// ensureSchema returns the named schema from the catalog (or the defaultSchema
// when schemaName is empty), creating and registering it if it doesn't exist yet.
func ensureSchema(cat *Catalog, defaultSchema *Schema, schemaName string) *Schema {
	if schemaName == "" {
		return defaultSchema
	}
	if s, ok := cat.GetSchema(schemaName); ok {
		return s
	}
	s := NewSchema(schemaName)
	cat.AddSchema(s)
	return s
}

// applyAlterStatement applies an ALTER TABLE statement to the catalog / default schema.
func applyAlterStatement(cat *Catalog, defaultSchema *Schema, stmt *ast.AlterStatement) error {
	if stmt.Type != ast.AlterTypeTable {
		return nil // ignore ALTER ROLE, ALTER POLICY, etc.
	}
	op, ok := stmt.Operation.(*ast.AlterTableOperation)
	if !ok {
		return nil
	}

	schemaName, tableName := splitSchemaTable(stmt.Name)
	s := ensureSchema(cat, defaultSchema, schemaName)
	table, tableExists := s.GetTable(tableName)

	switch op.Type {
	case ast.AddColumn:
		if op.ColumnDef == nil {
			return nil
		}
		// Create table on-demand if it doesn't exist yet
		if !tableExists {
			table = NewTable(tableName)
			s.AddTable(table)
		}
		col := extractColumnFromDef(op.ColumnDef)
		table.AddColumn(col)

	case ast.DropColumn:
		if !tableExists {
			return nil // nothing to drop
		}
		if op.ColumnName != nil {
			delete(table.Columns, strings.ToLower(op.ColumnName.Name))
		}

	case ast.RenameColumn:
		if !tableExists {
			return nil
		}
		if op.ColumnName != nil && op.NewColumnName != nil {
			oldKey := strings.ToLower(op.ColumnName.Name)
			if col, ok := table.Columns[oldKey]; ok {
				col.Name = op.NewColumnName.Name
				delete(table.Columns, oldKey)
				table.Columns[strings.ToLower(col.Name)] = col
			}
		}

	case ast.ModifyColumn, ast.ChangeColumn, ast.AlterColumn:
		if !tableExists || op.ColumnDef == nil {
			return nil
		}
		col := extractColumnFromDef(op.ColumnDef)
		table.AddColumn(col)
	}

	return nil
}

// extractColumnFromDef builds a Column from an AST ColumnDef.
func extractColumnFromDef(colDef *ast.ColumnDef) *Column {
	col := &Column{
		Name:     colDef.Name,
		DataType: colDef.Type,
		Nullable: true,
	}
	for _, constraint := range colDef.Constraints {
		switch strings.ToUpper(constraint.Type) {
		case "NOT NULL":
			col.Nullable = false
		case "PRIMARY KEY":
			col.Nullable = false
		case "DEFAULT":
			if constraint.Default != nil {
				col.Default = constraint.Default.TokenLiteral()
			}
		case "REFERENCES":
			if constraint.References != nil {
				col.References = &ForeignKeyRef{
					Table: constraint.References.Table,
				}
				if len(constraint.References.Columns) > 0 {
					col.References.Column = constraint.References.Columns[0]
				}
			}
		}
	}
	return col
}

// LoadFromDDL parses CREATE TABLE statements from the given SQL string and
// builds a Schema. Multiple CREATE TABLE statements can be included in the
// input, separated by semicolons or newlines. Non-CREATE TABLE statements
// are silently ignored.
//
// Example:
//
//	ddl := `
//	  CREATE TABLE users (
//	    id INT PRIMARY KEY,
//	    name VARCHAR(100) NOT NULL,
//	    email VARCHAR(255) UNIQUE
//	  );
//	  CREATE TABLE orders (
//	    id INT PRIMARY KEY,
//	    user_id INT REFERENCES users(id),
//	    total DECIMAL(10,2)
//	  );
//	`
//	schema, err := LoadFromDDL(ddl)
func LoadFromDDL(sql string) (*Schema, error) {
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DDL: %w", err)
	}

	s := NewSchema("default")

	for _, stmt := range tree.Statements {
		switch ct := stmt.(type) {
		case *ast.CreateTableStatement:
			table, err := extractTable(ct)
			if err != nil {
				return nil, fmt.Errorf("failed to extract table from CREATE TABLE: %w", err)
			}
			s.AddTable(table)

		case *ast.AlterStatement:
			// Treat the default schema as a pseudo-catalog for ALTER TABLE support
			tempCat := NewCatalog()
			if err := applyAlterStatement(tempCat, s, ct); err != nil {
				return nil, fmt.Errorf("failed to apply ALTER TABLE: %w", err)
			}
		}
	}

	return s, nil
}

// LoadFromDDLFile reads a file at the given path and loads schema from the
// DDL statements contained within it.
func LoadFromDDLFile(path string) (*Schema, error) {
	data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("failed to read DDL file %q: %w", path, err)
	}
	return LoadFromDDL(string(data))
}

// extractTable converts a CreateTableStatement AST node into a schema Table.
func extractTable(ct *ast.CreateTableStatement) (*Table, error) {
	table := NewTable(ct.Name)

	// Extract columns
	for i := range ct.Columns {
		colDef := ct.Columns[i] // avoid G601: copy loop variable before taking its address
		col := extractColumnFromDef(&colDef)

		// Process column constraints that also affect table-level metadata
		for _, constraint := range colDef.Constraints {
			switch strings.ToUpper(constraint.Type) {
			case "PRIMARY KEY":
				table.PrimaryKey = append(table.PrimaryKey, colDef.Name)
			case "REFERENCES":
				if constraint.References != nil {
					fk := ForeignKey{
						Columns:    []string{colDef.Name},
						RefTable:   constraint.References.Table,
						RefColumns: constraint.References.Columns,
					}
					table.ForeignKeys = append(table.ForeignKeys, fk)
				}
			case "UNIQUE":
				table.Indexes = append(table.Indexes, Index{
					Columns: []string{colDef.Name},
					Unique:  true,
				})
			}
		}

		table.AddColumn(col)
	}

	// Process table-level constraints
	for _, constraint := range ct.Constraints {
		constraintType := strings.ToUpper(constraint.Type)
		switch constraintType {
		case "PRIMARY KEY":
			table.PrimaryKey = constraint.Columns
			// Mark PK columns as NOT NULL
			for _, colName := range constraint.Columns {
				if col, ok := table.GetColumn(colName); ok {
					col.Nullable = false
				}
			}
		case "FOREIGN KEY":
			if constraint.References != nil {
				fk := ForeignKey{
					Name:       constraint.Name,
					Columns:    constraint.Columns,
					RefTable:   constraint.References.Table,
					RefColumns: constraint.References.Columns,
				}
				table.ForeignKeys = append(table.ForeignKeys, fk)
			}
		case "UNIQUE":
			table.Indexes = append(table.Indexes, Index{
				Name:    constraint.Name,
				Columns: constraint.Columns,
				Unique:  true,
			})
		}
	}

	return table, nil
}
