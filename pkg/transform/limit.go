package transform

import (
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// SetLimit returns a Rule that sets or replaces the LIMIT clause on a SELECT statement.
func SetLimit(n int) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "SetLimit")
		if err != nil {
			return err
		}
		sel.Limit = &n
		return nil
	})
}

// SetOffset returns a Rule that sets or replaces the OFFSET clause on a SELECT statement.
func SetOffset(n int) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "SetOffset")
		if err != nil {
			return err
		}
		sel.Offset = &n
		return nil
	})
}

// RemoveLimit returns a Rule that removes the LIMIT clause from a SELECT statement.
func RemoveLimit() Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "RemoveLimit")
		if err != nil {
			return err
		}
		sel.Limit = nil
		return nil
	})
}

// RemoveOffset returns a Rule that removes the OFFSET clause from a SELECT statement.
func RemoveOffset() Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "RemoveOffset")
		if err != nil {
			return err
		}
		sel.Offset = nil
		return nil
	})
}
