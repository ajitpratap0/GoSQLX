package schema

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// validateConstraints performs constraint-level validation on a statement.
// This includes NOT NULL checking for INSERT/UPDATE and basic type compatibility.
func (v *Validator) validateConstraints(stmt ast.Statement) []ValidationError {
	var errors []ValidationError

	switch s := stmt.(type) {
	case *ast.InsertStatement:
		errors = append(errors, v.validateInsertNotNull(s)...)
		errors = append(errors, v.validateInsertTypes(s)...)
	case *ast.UpdateStatement:
		errors = append(errors, v.validateUpdateNotNull(s)...)
	}

	return errors
}

// ValidateForeignKeys checks that all foreign key references in the schema
// point to valid tables and columns. This is a schema-level check that can
// be called independently of query validation.
func (v *Validator) ValidateForeignKeys() []ValidationError {
	return v.validateForeignKeyIntegrity()
}

// ---------------------------------------------------------------------------
// NOT NULL Constraint Checking
// ---------------------------------------------------------------------------

// validateInsertNotNull checks that INSERT statements don't insert NULL
// values into NOT NULL columns (when columns are explicitly listed).
func (v *Validator) validateInsertNotNull(s *ast.InsertStatement) []ValidationError {
	var errors []ValidationError

	table, ok := v.Schema.GetTable(s.TableName)
	if !ok {
		return nil // table doesn't exist — already caught by basic validation
	}

	// If no explicit columns, we can't check individual column assignments
	if len(s.Columns) == 0 {
		return nil
	}

	// Map column positions
	type colPos struct {
		name string
		col  *Column
	}
	var colMap []colPos
	for _, colExpr := range s.Columns {
		name := extractColumnName(colExpr)
		if name == "" {
			continue
		}
		col, _ := table.GetColumn(name)
		colMap = append(colMap, colPos{name: name, col: col})
	}

	// Check each row for NULL values in NOT NULL columns
	for rowIdx, row := range s.Values {
		for colIdx, val := range row {
			if colIdx >= len(colMap) {
				break
			}
			cp := colMap[colIdx]
			if cp.col == nil || cp.col.Nullable {
				continue
			}
			if isNullLiteral(val) {
				errors = append(errors, ValidationError{
					Message:    fmt.Sprintf("INSERT into NOT NULL column %q (row %d) with NULL value", cp.name, rowIdx+1),
					Severity:   "error",
					Suggestion: fmt.Sprintf("column %q does not allow NULL values; provide a non-NULL value or set a DEFAULT", cp.name),
				})
			}
		}
	}

	// Check: NOT NULL columns without DEFAULT that are missing from INSERT column list
	for _, col := range table.Columns {
		if col.Nullable || col.Default != "" {
			continue
		}
		found := false
		for _, cp := range colMap {
			if strings.EqualFold(cp.name, col.Name) {
				found = true
				break
			}
		}
		if !found {
			// Skip primary key columns (often auto-increment)
			isPK := false
			for _, pk := range table.PrimaryKey {
				if strings.EqualFold(pk, col.Name) {
					isPK = true
					break
				}
			}
			if !isPK {
				errors = append(errors, ValidationError{
					Message:    fmt.Sprintf("NOT NULL column %q in table %q is missing from INSERT and has no DEFAULT", col.Name, s.TableName),
					Severity:   "warning",
					Suggestion: fmt.Sprintf("include column %q in the INSERT or add a DEFAULT value", col.Name),
				})
			}
		}
	}

	return errors
}

// validateUpdateNotNull checks that UPDATE SET clauses don't set NOT NULL columns to NULL.
func (v *Validator) validateUpdateNotNull(s *ast.UpdateStatement) []ValidationError {
	var errors []ValidationError

	table, ok := v.Schema.GetTable(s.TableName)
	if !ok {
		return nil
	}

	checkAssignment := func(colExpr ast.Expression, valExpr ast.Expression) {
		name := extractColumnName(colExpr)
		if name == "" {
			return
		}
		col, ok := table.GetColumn(name)
		if !ok || col.Nullable {
			return
		}
		if isNullLiteral(valExpr) {
			errors = append(errors, ValidationError{
				Message:    fmt.Sprintf("UPDATE sets NOT NULL column %q to NULL", name),
				Severity:   "error",
				Suggestion: fmt.Sprintf("column %q does not allow NULL values", name),
			})
		}
	}

	for _, upd := range s.Assignments {
		checkAssignment(upd.Column, upd.Value)
	}
	for _, upd := range s.Assignments {
		checkAssignment(upd.Column, upd.Value)
	}

	return errors
}

// isNullLiteral checks if an expression is a NULL literal.
func isNullLiteral(expr ast.Expression) bool {
	if lit, ok := expr.(*ast.LiteralValue); ok {
		if lit.Value == nil {
			return true
		}
		if s, ok := lit.Value.(string); ok {
			return strings.EqualFold(s, "NULL")
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Foreign Key Validation
// ---------------------------------------------------------------------------

// validateForeignKeyIntegrity checks that all foreign key references in the schema
// point to valid tables and columns.
func (v *Validator) validateForeignKeyIntegrity() []ValidationError {
	var errors []ValidationError

	for _, table := range v.Schema.Tables {
		// Check table-level foreign keys
		for _, fk := range table.ForeignKeys {
			refTable, ok := v.Schema.GetTable(fk.RefTable)
			if !ok {
				errors = append(errors, ValidationError{
					Message:  fmt.Sprintf("foreign key %q on table %q references non-existent table %q", fk.Name, table.Name, fk.RefTable),
					Severity: "error",
				})
				continue
			}

			for _, refCol := range fk.RefColumns {
				if _, ok := refTable.GetColumn(refCol); !ok {
					errors = append(errors, ValidationError{
						Message:  fmt.Sprintf("foreign key %q references non-existent column %q in table %q", fk.Name, refCol, fk.RefTable),
						Severity: "error",
					})
				}
			}

			for _, srcCol := range fk.Columns {
				if _, ok := table.GetColumn(srcCol); !ok {
					errors = append(errors, ValidationError{
						Message:  fmt.Sprintf("foreign key %q uses non-existent column %q in table %q", fk.Name, srcCol, table.Name),
						Severity: "error",
					})
				}
			}
		}

		// Check column-level FK references
		for _, col := range table.Columns {
			if col.References == nil {
				continue
			}
			refTable, ok := v.Schema.GetTable(col.References.Table)
			if !ok {
				errors = append(errors, ValidationError{
					Message:  fmt.Sprintf("column %q.%q references non-existent table %q", table.Name, col.Name, col.References.Table),
					Severity: "error",
				})
				continue
			}
			if col.References.Column != "" {
				if _, ok := refTable.GetColumn(col.References.Column); !ok {
					errors = append(errors, ValidationError{
						Message:  fmt.Sprintf("column %q.%q references non-existent column %q in table %q", table.Name, col.Name, col.References.Column, col.References.Table),
						Severity: "error",
					})
				}
			}
		}
	}

	return errors
}

// ---------------------------------------------------------------------------
// Type Compatibility Checking
// ---------------------------------------------------------------------------

// TypeCategory represents a broad category of SQL data types for compatibility checking.
type TypeCategory int

const (
	TypeCategoryUnknown TypeCategory = iota
	TypeCategoryNumeric
	TypeCategoryString
	TypeCategoryDateTime
	TypeCategoryBoolean
)

// categorizeType maps a SQL data type string to a TypeCategory.
func categorizeType(dataType string) TypeCategory {
	upper := strings.ToUpper(dataType)

	// Strip size specifications: VARCHAR(100) -> VARCHAR
	if idx := strings.Index(upper, "("); idx != -1 {
		upper = upper[:idx]
	}
	upper = strings.TrimSpace(upper)

	switch upper {
	case "INT", "INTEGER", "BIGINT", "SMALLINT", "TINYINT",
		"DECIMAL", "NUMERIC", "FLOAT", "DOUBLE", "REAL",
		"SERIAL", "BIGSERIAL":
		return TypeCategoryNumeric
	case "VARCHAR", "CHAR", "TEXT", "NVARCHAR", "NCHAR", "CLOB",
		"CHARACTER", "VARYING":
		return TypeCategoryString
	case "DATE", "TIME", "TIMESTAMP", "DATETIME", "INTERVAL":
		return TypeCategoryDateTime
	case "BOOLEAN", "BOOL", "BIT":
		return TypeCategoryBoolean
	default:
		return TypeCategoryUnknown
	}
}

// validateInsertTypes performs basic type compatibility checking for INSERT values.
func (v *Validator) validateInsertTypes(s *ast.InsertStatement) []ValidationError {
	var errors []ValidationError

	table, ok := v.Schema.GetTable(s.TableName)
	if !ok || len(s.Columns) == 0 || len(s.Values) == 0 {
		return nil
	}

	for rowIdx, row := range s.Values {
		for colIdx, val := range row {
			if colIdx >= len(s.Columns) {
				break
			}
			colName := extractColumnName(s.Columns[colIdx])
			if colName == "" {
				continue
			}
			col, ok := table.GetColumn(colName)
			if !ok {
				continue
			}

			valCat := inferLiteralType(val)
			colCat := categorizeType(col.DataType)

			if valCat == TypeCategoryUnknown || colCat == TypeCategoryUnknown {
				continue
			}

			if valCat != colCat {
				// String-to-anything is commonly allowed via implicit cast
				if valCat == TypeCategoryString {
					continue
				}
				errors = append(errors, ValidationError{
					Message: fmt.Sprintf("type mismatch in row %d: column %q expects %s but got %s value",
						rowIdx+1, colName, typeCategoryName(colCat), typeCategoryName(valCat)),
					Severity:   "warning",
					Suggestion: fmt.Sprintf("ensure the value is compatible with %s", col.DataType),
				})
			}
		}
	}

	return errors
}

// inferLiteralType tries to determine the type category of a literal value.
func inferLiteralType(expr ast.Expression) TypeCategory {
	lit, ok := expr.(*ast.LiteralValue)
	if !ok {
		return TypeCategoryUnknown
	}

	if lit.Value == nil {
		return TypeCategoryUnknown
	}

	switch lit.Value.(type) {
	case int, int64, float64:
		return TypeCategoryNumeric
	case bool:
		return TypeCategoryBoolean
	case string:
		return TypeCategoryString
	default:
		return TypeCategoryUnknown
	}
}

// typeCategoryName returns a human-readable name for a TypeCategory.
func typeCategoryName(cat TypeCategory) string {
	switch cat {
	case TypeCategoryNumeric:
		return "numeric"
	case TypeCategoryString:
		return "string"
	case TypeCategoryDateTime:
		return "datetime"
	case TypeCategoryBoolean:
		return "boolean"
	default:
		return "unknown"
	}
}
