package transform

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func getSelect(stmt ast.Statement, transform string) (*ast.SelectStatement, error) {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return nil, &ErrUnsupportedStatement{Transform: transform, Got: stmtTypeName(stmt)}
	}
	return sel, nil
}

// AddColumn returns a Rule that adds a column expression to a SELECT statement.
func AddColumn(expr ast.Expression) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "AddColumn")
		if err != nil {
			return err
		}
		sel.Columns = append(sel.Columns, expr)
		return nil
	})
}

// RemoveColumn returns a Rule that removes a column by name or alias from a SELECT statement.
func RemoveColumn(name string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "RemoveColumn")
		if err != nil {
			return err
		}
		filtered := make([]ast.Expression, 0, len(sel.Columns))
		found := false
		for _, col := range sel.Columns {
			if columnMatches(col, name) {
				found = true
			} else {
				filtered = append(filtered, col)
			}
		}
		if !found {
			return fmt.Errorf("column %q not found", name)
		}
		sel.Columns = filtered
		return nil
	})
}

// ReplaceColumn returns a Rule that replaces a column identified by oldName
// with a new column identified by newName.
func ReplaceColumn(oldName, newName string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "ReplaceColumn")
		if err != nil {
			return err
		}
		for i, col := range sel.Columns {
			if columnMatches(col, oldName) {
				sel.Columns[i] = &ast.Identifier{Name: newName}
			}
		}
		return nil
	})
}

// AddSelectStar returns a Rule that adds * to the SELECT columns.
func AddSelectStar() Rule {
	return AddColumn(&ast.Identifier{Name: "*"})
}

// columnMatches checks if a column expression matches the given name.
func columnMatches(expr ast.Expression, name string) bool {
	lower := strings.ToLower(name)
	switch e := expr.(type) {
	case *ast.Identifier:
		return strings.ToLower(e.Name) == lower
	case *ast.AliasedExpression:
		if strings.ToLower(e.Alias) == lower {
			return true
		}
		return columnMatches(e.Expr, name)
	default:
		return false
	}
}
