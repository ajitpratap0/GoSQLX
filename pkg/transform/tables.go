package transform

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// ReplaceTable returns a Rule that replaces a table name everywhere it appears
// (FROM, JOIN, WHERE column qualifiers) in a SELECT, UPDATE, or DELETE statement.
func ReplaceTable(oldName, newName string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		switch s := stmt.(type) {
		case *ast.SelectStatement:
			replaceTableInFrom(s.From, oldName, newName)
			replaceTableInJoins(s.Joins, oldName, newName)
			for i, col := range s.Columns {
				s.Columns[i] = replaceTableInExpr(col, oldName, newName)
			}
			s.Where = replaceTableInExpr(s.Where, oldName, newName)
			for i, ob := range s.OrderBy {
				s.OrderBy[i].Expression = replaceTableInExpr(ob.Expression, oldName, newName)
			}
			return nil
		case *ast.UpdateStatement:
			if strings.EqualFold(s.TableName, oldName) {
				s.TableName = newName
			}
			s.Where = replaceTableInExpr(s.Where, oldName, newName)
			return nil
		case *ast.DeleteStatement:
			if strings.EqualFold(s.TableName, oldName) {
				s.TableName = newName
			}
			s.Where = replaceTableInExpr(s.Where, oldName, newName)
			return nil
		default:
			return &ErrUnsupportedStatement{Transform: "ReplaceTable", Got: stmtTypeName(stmt)}
		}
	})
}

// AddTableAlias returns a Rule that adds an alias to a table in the FROM clause.
func AddTableAlias(tableName, alias string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		switch s := stmt.(type) {
		case *ast.SelectStatement:
			for i := range s.From {
				if strings.EqualFold(s.From[i].Name, tableName) {
					s.From[i].Alias = alias
				}
			}
			return nil
		case *ast.UpdateStatement:
			if strings.EqualFold(s.TableName, tableName) {
				s.Alias = alias
			}
			return nil
		case *ast.DeleteStatement:
			if strings.EqualFold(s.TableName, tableName) {
				s.Alias = alias
			}
			return nil
		default:
			return &ErrUnsupportedStatement{Transform: "AddTableAlias", Got: stmtTypeName(stmt)}
		}
	})
}

// QualifyColumns returns a Rule that prefixes unqualified column references
// with the given table name in a SELECT statement.
func QualifyColumns(tableName string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "QualifyColumns")
		if err != nil {
			return err
		}
		for i, col := range sel.Columns {
			sel.Columns[i] = qualifyExpr(col, tableName)
		}
		if sel.Where != nil {
			sel.Where = qualifyExpr(sel.Where, tableName)
		}
		return nil
	})
}

func replaceTableInFrom(from []ast.TableReference, old, new string) {
	for i := range from {
		if strings.EqualFold(from[i].Name, old) {
			from[i].Name = new
		}
	}
}

func replaceTableInJoins(joins []ast.JoinClause, old, new string) {
	for i := range joins {
		if strings.EqualFold(joins[i].Right.Name, old) {
			joins[i].Right.Name = new
		}
		if strings.EqualFold(joins[i].Left.Name, old) {
			joins[i].Left.Name = new
		}
		joins[i].Condition = replaceTableInExpr(joins[i].Condition, old, new)
	}
}

func replaceTableInExpr(expr ast.Expression, old, new string) ast.Expression {
	if expr == nil {
		return nil
	}
	switch e := expr.(type) {
	case *ast.Identifier:
		if strings.EqualFold(e.Table, old) {
			e.Table = new
		}
		return e
	case *ast.BinaryExpression:
		e.Left = replaceTableInExpr(e.Left, old, new)
		e.Right = replaceTableInExpr(e.Right, old, new)
		return e
	case *ast.AliasedExpression:
		e.Expr = replaceTableInExpr(e.Expr, old, new)
		return e
	default:
		return expr
	}
}

func qualifyExpr(expr ast.Expression, table string) ast.Expression {
	if expr == nil {
		return nil
	}
	switch e := expr.(type) {
	case *ast.Identifier:
		if e.Table == "" && e.Name != "*" {
			e.Table = table
		}
		return e
	case *ast.BinaryExpression:
		e.Left = qualifyExpr(e.Left, table)
		e.Right = qualifyExpr(e.Right, table)
		return e
	case *ast.AliasedExpression:
		e.Expr = qualifyExpr(e.Expr, table)
		return e
	default:
		return expr
	}
}
