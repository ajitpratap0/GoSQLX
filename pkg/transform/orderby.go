package transform

import (
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// AddOrderBy returns a Rule that adds an ORDER BY expression to a SELECT statement.
// If desc is true, the order is descending; otherwise ascending.
func AddOrderBy(column string, desc bool) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "AddOrderBy")
		if err != nil {
			return err
		}
		sel.OrderBy = append(sel.OrderBy, ast.OrderByExpression{
			Expression: &ast.Identifier{Name: column},
			Ascending:  !desc,
		})
		return nil
	})
}

// RemoveOrderBy returns a Rule that removes the ORDER BY clause entirely from a SELECT statement.
func RemoveOrderBy() Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "RemoveOrderBy")
		if err != nil {
			return err
		}
		sel.OrderBy = nil
		return nil
	})
}
