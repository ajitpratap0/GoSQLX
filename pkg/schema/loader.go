package schema

import (
	"fmt"
	"os"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

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
		ct, ok := stmt.(*ast.CreateTableStatement)
		if !ok {
			// Skip non-CREATE TABLE statements
			continue
		}
		table, err := extractTable(ct)
		if err != nil {
			return nil, fmt.Errorf("failed to extract table from CREATE TABLE: %w", err)
		}
		s.AddTable(table)
	}

	return s, nil
}

// LoadFromDDLFile reads a file at the given path and loads schema from the
// DDL statements contained within it.
func LoadFromDDLFile(path string) (*Schema, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read DDL file %q: %w", path, err)
	}
	return LoadFromDDL(string(data))
}

// extractTable converts a CreateTableStatement AST node into a schema Table.
func extractTable(ct *ast.CreateTableStatement) (*Table, error) {
	table := NewTable(ct.Name)

	// Extract columns
	for _, colDef := range ct.Columns {
		col := &Column{
			Name:     colDef.Name,
			DataType: colDef.Type,
			Nullable: true, // default to nullable
		}

		// Process column constraints
		for _, constraint := range colDef.Constraints {
			constraintType := strings.ToUpper(constraint.Type)
			switch constraintType {
			case "NOT NULL":
				col.Nullable = false
			case "PRIMARY KEY":
				col.Nullable = false
				table.PrimaryKey = append(table.PrimaryKey, colDef.Name)
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
					// Also record as a table-level foreign key
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
