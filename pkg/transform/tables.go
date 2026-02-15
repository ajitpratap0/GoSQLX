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

// walkExpr recursively walks all expression types and applies fn to each expression.
// It handles all known AST expression types that can contain sub-expressions,
// and recurses into subqueries (SelectStatements) where applicable.
func walkExpr(expr ast.Expression, fn func(ast.Expression) ast.Expression) ast.Expression {
	if expr == nil {
		return nil
	}
	// Apply fn first (pre-order), then recurse into children.
	expr = fn(expr)
	switch e := expr.(type) {
	case *ast.BinaryExpression:
		e.Left = walkExpr(e.Left, fn)
		e.Right = walkExpr(e.Right, fn)
	case *ast.AliasedExpression:
		e.Expr = walkExpr(e.Expr, fn)
	case *ast.UnaryExpression:
		e.Expr = walkExpr(e.Expr, fn)
	case *ast.CastExpression:
		e.Expr = walkExpr(e.Expr, fn)
	case *ast.BetweenExpression:
		e.Expr = walkExpr(e.Expr, fn)
		e.Lower = walkExpr(e.Lower, fn)
		e.Upper = walkExpr(e.Upper, fn)
	case *ast.InExpression:
		e.Expr = walkExpr(e.Expr, fn)
		for i := range e.List {
			e.List[i] = walkExpr(e.List[i], fn)
		}
		if e.Subquery != nil {
			walkStmtExprs(e.Subquery, fn)
		}
	case *ast.SubqueryExpression:
		if e.Subquery != nil {
			walkStmtExprs(e.Subquery, fn)
		}
	case *ast.ExistsExpression:
		if e.Subquery != nil {
			walkStmtExprs(e.Subquery, fn)
		}
	case *ast.AnyExpression:
		e.Expr = walkExpr(e.Expr, fn)
		if e.Subquery != nil {
			walkStmtExprs(e.Subquery, fn)
		}
	case *ast.AllExpression:
		e.Expr = walkExpr(e.Expr, fn)
		if e.Subquery != nil {
			walkStmtExprs(e.Subquery, fn)
		}
	case *ast.CaseExpression:
		e.Value = walkExpr(e.Value, fn)
		for i := range e.WhenClauses {
			e.WhenClauses[i].Condition = walkExpr(e.WhenClauses[i].Condition, fn)
			e.WhenClauses[i].Result = walkExpr(e.WhenClauses[i].Result, fn)
		}
		e.ElseClause = walkExpr(e.ElseClause, fn)
	case *ast.FunctionCall:
		for i := range e.Arguments {
			e.Arguments[i] = walkExpr(e.Arguments[i], fn)
		}
		e.Filter = walkExpr(e.Filter, fn)
	case *ast.ListExpression:
		for i := range e.Values {
			e.Values[i] = walkExpr(e.Values[i], fn)
		}
	case *ast.TupleExpression:
		for i := range e.Expressions {
			e.Expressions[i] = walkExpr(e.Expressions[i], fn)
		}
	case *ast.ExtractExpression:
		e.Source = walkExpr(e.Source, fn)
	case *ast.PositionExpression:
		e.Substr = walkExpr(e.Substr, fn)
		e.Str = walkExpr(e.Str, fn)
	case *ast.SubstringExpression:
		e.Str = walkExpr(e.Str, fn)
		e.Start = walkExpr(e.Start, fn)
		e.Length = walkExpr(e.Length, fn)
	case *ast.ArrayConstructorExpression:
		for i := range e.Elements {
			e.Elements[i] = walkExpr(e.Elements[i], fn)
		}
		if e.Subquery != nil {
			walkStmtExprs(e.Subquery, fn)
		}
	case *ast.ArraySubscriptExpression:
		e.Array = walkExpr(e.Array, fn)
		for i := range e.Indices {
			e.Indices[i] = walkExpr(e.Indices[i], fn)
		}
	case *ast.ArraySliceExpression:
		e.Array = walkExpr(e.Array, fn)
		e.Start = walkExpr(e.Start, fn)
		e.End = walkExpr(e.End, fn)
		// Leaf nodes: *ast.Identifier, *ast.LiteralValue, *ast.IntervalExpression — no children
	}
	return expr
}

// walkStmtExprs walks all expressions inside a statement (if it's a SelectStatement).
func walkStmtExprs(stmt ast.Statement, fn func(ast.Expression) ast.Expression) {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok || sel == nil {
		return
	}
	for i := range sel.Columns {
		sel.Columns[i] = walkExpr(sel.Columns[i], fn)
	}
	sel.Where = walkExpr(sel.Where, fn)
	for i := range sel.OrderBy {
		sel.OrderBy[i].Expression = walkExpr(sel.OrderBy[i].Expression, fn)
	}
	for i := range sel.Joins {
		sel.Joins[i].Condition = walkExpr(sel.Joins[i].Condition, fn)
	}
}

// replaceTableInStmt recursively replaces table names in all parts of a statement,
// including FROM, JOINs, and all expressions (with subquery recursion).
func replaceTableInStmt(stmt ast.Statement, old, new string) {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok || sel == nil {
		return
	}
	replaceTableInFrom(sel.From, old, new)
	replaceTableInJoins(sel.Joins, old, new)
	for i := range sel.Columns {
		sel.Columns[i] = replaceTableInExpr(sel.Columns[i], old, new)
	}
	sel.Where = replaceTableInExpr(sel.Where, old, new)
	for i := range sel.OrderBy {
		sel.OrderBy[i].Expression = replaceTableInExpr(sel.OrderBy[i].Expression, old, new)
	}
}

func replaceTableInExpr(expr ast.Expression, old, new string) ast.Expression {
	if expr == nil {
		return nil
	}
	// For subquery-containing expressions, recurse into the full statement
	// so that FROM/JOIN table names are also replaced.
	switch e := expr.(type) {
	case *ast.SubqueryExpression:
		replaceTableInStmt(e.Subquery, old, new)
		return e
	case *ast.ExistsExpression:
		replaceTableInStmt(e.Subquery, old, new)
		return e
	case *ast.InExpression:
		e.Expr = replaceTableInExpr(e.Expr, old, new)
		for i := range e.List {
			e.List[i] = replaceTableInExpr(e.List[i], old, new)
		}
		if e.Subquery != nil {
			replaceTableInStmt(e.Subquery, old, new)
		}
		return e
	case *ast.AnyExpression:
		e.Expr = replaceTableInExpr(e.Expr, old, new)
		replaceTableInStmt(e.Subquery, old, new)
		return e
	case *ast.AllExpression:
		e.Expr = replaceTableInExpr(e.Expr, old, new)
		replaceTableInStmt(e.Subquery, old, new)
		return e
	}
	return walkExpr(expr, func(e ast.Expression) ast.Expression {
		if id, ok := e.(*ast.Identifier); ok {
			if strings.EqualFold(id.Table, old) {
				id.Table = new
			}
		}
		return e
	})
}

func qualifyExpr(expr ast.Expression, table string) ast.Expression {
	return walkExpr(expr, func(e ast.Expression) ast.Expression {
		if id, ok := e.(*ast.Identifier); ok {
			if id.Table == "" && id.Name != "*" {
				id.Table = table
			}
		}
		return e
	})
}
