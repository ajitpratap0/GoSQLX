// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"

// Scan common expression paths without materializing Children slices. Uncommon
// nodes use their authoritative Children method, including dialect extensions.
func childrenNeedDialectRewrite(n ast.Node, target string) bool {
	switch x := n.(type) {
	case *ast.AST:
		for _, s := range x.Statements {
			if needsDialectRewrite(s, target) {
				return true
			}
		}
		return false
	case *ast.Identifier, *ast.Ident, *ast.LiteralValue, *ast.UnicodeEscapeExpression:
		return false
	case *ast.BinaryExpression:
		return nodesNeedDialectRewrite(target, x.Left, x.Right, x.DialectExtras().Escape)
	case *ast.UnaryExpression:
		return needsDialectRewrite(x.Expr, target)
	case *ast.CastExpression:
		return needsDialectRewrite(x.Expr, target)
	case *ast.AliasedExpression:
		return needsDialectRewrite(x.Expr, target)
	case *ast.ParenthesizedExpression:
		return needsDialectRewrite(x.Expr, target)
	case *ast.FunctionCall:
		if expressionsNeedDialectRewrite(x.Arguments, target) || expressionsNeedDialectRewrite(x.Parameters, target) ||
			nodesNeedDialectRewrite(target, x.Filter, x.Over) {
			return true
		}
		for i := range x.OrderBy {
			if needsDialectRewrite(&x.OrderBy[i], target) {
				return true
			}
		}
		for i := range x.WithinGroup {
			if needsDialectRewrite(&x.WithinGroup[i], target) {
				return true
			}
		}
		return x.Extras != nil && nodesNeedDialectRewrite(target, x.Extras.Separator, x.Extras.Keep)
	case *ast.SelectStatement:
		// Dialect extensions retain the shared visitor's traversal.
		if x.Extras == nil && x.ArrayJoin == nil {
			if nodesNeedDialectRewrite(target, x.With, x.Top, x.Sample, x.PrewhereClause,
				x.Where, x.Having, x.Qualify, x.StartWith, x.ConnectBy, x.Fetch, x.For) ||
				expressionsNeedDialectRewrite(x.DistinctOnColumns, target) ||
				expressionsNeedDialectRewrite(x.Columns, target) || expressionsNeedDialectRewrite(x.GroupBy, target) {
				return true
			}
			for i := range x.From {
				if needsDialectRewrite(&x.From[i], target) {
					return true
				}
			}
			for i := range x.Joins {
				if needsDialectRewrite(&x.Joins[i], target) {
					return true
				}
			}
			for i := range x.OrderBy {
				if needsDialectRewrite(&x.OrderBy[i], target) {
					return true
				}
			}
			for i := range x.Windows {
				if needsDialectRewrite(&x.Windows[i], target) {
					return true
				}
			}
			for _, setting := range x.Settings {
				if needsDialectRewrite(setting.Value, target) {
					return true
				}
			}
			return false
		}
	case *ast.JoinClause:
		return nodesNeedDialectRewrite(target, &x.Left, &x.Right, x.Condition, x.MatchCondition) || expressionsNeedDialectRewrite(x.Using, target)
	case *ast.OrderByExpression:
		return nodesNeedDialectRewrite(target, x.Expression, x.WithFill)
	case *ast.WithClause:
		for _, cte := range x.CTEs {
			if needsDialectRewrite(cte, target) {
				return true
			}
		}
		return false
	case *ast.CommonTableExpr:
		return nodesNeedDialectRewrite(target, x.Statement, x.ScalarExpr, x.Cycle)
	case *ast.WindowSpec:
		if expressionsNeedDialectRewrite(x.PartitionBy, target) || needsDialectRewrite(x.FrameClause, target) {
			return true
		}
		for i := range x.OrderBy {
			if needsDialectRewrite(&x.OrderBy[i], target) {
				return true
			}
		}
		return false
	case *ast.WindowFrame:
		return needsDialectRewrite(x.Start.Value, target) || x.End != nil && needsDialectRewrite(x.End.Value, target)
	case *ast.CaseExpression:
		if nodesNeedDialectRewrite(target, x.Value, x.ElseClause) {
			return true
		}
		for _, when := range x.WhenClauses {
			if nodesNeedDialectRewrite(target, when.Condition, when.Result) {
				return true
			}
		}
		return false
	}
	for _, child := range n.Children() {
		if needsDialectRewrite(child, target) {
			return true
		}
	}
	return false
}

func nodesNeedDialectRewrite(target string, nodes ...ast.Node) bool {
	for _, node := range nodes {
		if needsDialectRewrite(node, target) {
			return true
		}
	}
	return false
}

func expressionsNeedDialectRewrite(exprs []ast.Expression, target string) bool {
	for _, e := range exprs {
		if needsDialectRewrite(e, target) {
			return true
		}
	}
	return false
}
