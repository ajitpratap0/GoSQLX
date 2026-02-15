package transform

import (
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// getWhere returns a pointer to the WHERE field for supported statements.
func getWhere(stmt ast.Statement) (*ast.Expression, error) {
	switch s := stmt.(type) {
	case *ast.SelectStatement:
		return &s.Where, nil
	case *ast.UpdateStatement:
		return &s.Where, nil
	case *ast.DeleteStatement:
		return &s.Where, nil
	default:
		return nil, &ErrUnsupportedStatement{Transform: "WHERE", Got: stmtTypeName(stmt)}
	}
}

// AddWhere returns a Rule that adds an AND condition to the existing WHERE clause.
// If no WHERE clause exists, the condition becomes the WHERE clause.
func AddWhere(condition ast.Expression) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		where, err := getWhere(stmt)
		if err != nil {
			return err
		}
		if *where == nil {
			*where = condition
		} else {
			*where = &ast.BinaryExpression{
				Left:     *where,
				Operator: "AND",
				Right:    condition,
			}
		}
		return nil
	})
}

// RemoveWhere returns a Rule that removes the WHERE clause entirely.
func RemoveWhere() Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		where, err := getWhere(stmt)
		if err != nil {
			return err
		}
		*where = nil
		return nil
	})
}

// ReplaceWhere returns a Rule that replaces the WHERE clause with the given condition.
func ReplaceWhere(condition ast.Expression) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		where, err := getWhere(stmt)
		if err != nil {
			return err
		}
		*where = condition
		return nil
	})
}

// AddWhereFromSQL returns a Rule that parses a SQL condition string and adds it
// as an AND condition to the existing WHERE clause.
//
// WARNING: sql parameter must not contain untrusted user input.
// This function parses raw SQL — passing unsanitized input could
// produce unintended query modifications. Use parameterized queries
// or construct AST nodes directly for untrusted input.
func AddWhereFromSQL(sql string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		condition, err := parseCondition(sql)
		if err != nil {
			return err
		}
		return AddWhere(condition).Apply(stmt)
	})
}
