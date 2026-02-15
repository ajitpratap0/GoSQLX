package transform

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// AddJoin returns a Rule that adds a JOIN clause to a SELECT statement.
// joinType should be "INNER", "LEFT", "RIGHT", "FULL", or "CROSS".
func AddJoin(joinType string, table string, condition ast.Expression) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "AddJoin")
		if err != nil {
			return err
		}
		sel.Joins = append(sel.Joins, ast.JoinClause{
			Type:      strings.ToUpper(joinType),
			Right:     ast.TableReference{Name: table},
			Condition: condition,
		})
		return nil
	})
}

// RemoveJoin returns a Rule that removes a JOIN by table name from a SELECT statement.
func RemoveJoin(tableName string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "RemoveJoin")
		if err != nil {
			return err
		}
		lower := strings.ToLower(tableName)
		filtered := make([]ast.JoinClause, 0, len(sel.Joins))
		for _, j := range sel.Joins {
			if strings.ToLower(j.Right.Name) != lower && strings.ToLower(j.Right.Alias) != lower {
				filtered = append(filtered, j)
			}
		}
		sel.Joins = filtered
		return nil
	})
}

// AddJoinFromSQL returns a Rule that parses a JOIN clause from SQL and adds it
// to a SELECT statement. The sql parameter should be a complete JOIN clause,
// e.g. "LEFT JOIN orders ON orders.user_id = users.id".
func AddJoinFromSQL(sql string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		join, err := parseJoinClause(sql)
		if err != nil {
			return err
		}
		sel, err := getSelect(stmt, "AddJoinFromSQL")
		if err != nil {
			return err
		}
		sel.Joins = append(sel.Joins, *join)
		return nil
	})
}
