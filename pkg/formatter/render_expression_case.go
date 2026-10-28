// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package formatter

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func (f *nodeFormatter) exprSQL(e ast.Expression) string {
	if e == nil {
		return ""
	}
	if f.opts.KeywordCase != ast.KeywordLower {
		return exprSQL(e)
	}
	if f.expressionCase == nil {
		opts := f.opts
		opts.NewlinePerClause = false
		return formatLowerExpression(e, opts)
	}
	c := f.expressionCase
	switch v := e.(type) {
	case *ast.CaseExpression, *ast.BetweenExpression, *ast.InExpression,
		*ast.ExistsExpression, *ast.SubqueryExpression:
		scoped := *f
		scoped.opts.NewlinePerClause = false
		return c.formatWith(&scoped, e)
	case *ast.Identifier, *ast.Ident:
		return exprSQL(e)
	case *ast.LiteralValue:
		if v.Value == nil || strings.EqualFold(v.Type, "NULL") || strings.EqualFold(v.Type, "BOOLEAN") || strings.EqualFold(v.Type, "BOOL") {
			return lowerSyntax(v.SQL())
		}
		return v.SQL()
	case *ast.BinaryExpression:
		copy := *v
		copy.Left = c.expr(v.Left)
		copy.Right = c.expr(v.Right)
		if v.Extras != nil {
			x := *v.Extras
			x.Escape = c.expr(x.Escape)
			copy.Extras = &x
		}
		sql := lowerSyntax(copy.SQL())
		if v.CustomOp != nil {
			op := v.CustomOp.String()
			// OPERATOR is syntax; its schema and operator parts are names.
			cased := "operator" + strings.TrimPrefix(op, "OPERATOR")
			sql = strings.ReplaceAll(sql, lowerSyntax(op), cased)
		}
		return sql
	case *ast.UnaryExpression:
		copy := *v
		copy.Expr = c.expr(v.Expr)
		return c.result(&copy)
	case *ast.AliasedExpression:
		copy := *v
		copy.Expr = c.expr(v.Expr)
		copy.Alias = c.slot(ast.QuoteNameWith(v.Alias, v.AliasQuote))
		copy.AliasQuote = 0
		return c.result(&copy)
	case *ast.CastExpression:
		copy := *v
		copy.Expr = c.expr(v.Expr)
		if !v.TypeAsString {
			copy.Type = c.slot(lowerDataType(v.Type))
		}
		return c.result(&copy)
	case *ast.ParenthesizedExpression:
		copy := *v
		copy.Expr = c.expr(v.Expr)
		return c.result(&copy)
	case *ast.FunctionCall:
		copy := *v
		nameSQL := (&ast.FunctionCall{Name: v.Name, NameQuote: v.NameQuote}).SQL()
		nameSQL = strings.TrimSuffix(nameSQL, "()")
		if v.NameQuote == 0 && (expressionKeywords.IsKeyword(v.Name) || builtinFunctionName(v.Name)) {
			nameSQL = strings.ToLower(nameSQL)
		}
		copy.Name = c.slot(nameSQL)
		copy.NameQuote = 0
		copy.Arguments = make([]ast.Expression, len(v.Arguments))
		// KeywordArgument affects argument separators, so retain its node type.
		for i, arg := range v.Arguments {
			if k, ok := arg.(*ast.KeywordArgument); ok {
				item := *k
				item.Value = c.expr(k.Value)
				if k.TypeName != "" {
					item.TypeName = c.slot(lowerDataType(k.TypeName))
				}
				copy.Arguments[i] = &item
			} else {
				copy.Arguments[i] = c.expr(arg)
			}
		}
		copy.Parameters = c.exprs(v.Parameters)
		copy.Filter = c.expr(v.Filter)
		copy.OrderBy = c.orders(v.OrderBy)
		copy.WithinGroup = c.orders(v.WithinGroup)
		if v.Extras != nil {
			x := *v.Extras
			if x.Keep != nil {
				keep := *x.Keep
				keep.OrderBy = c.orders(keep.OrderBy)
				x.Keep = &keep
			}
			copy.Extras = &x
		}
		if v.Over != nil {
			w := *v.Over
			if w.Name != "" && w.BaseWindow == "" && len(w.PartitionBy) == 0 && len(w.OrderBy) == 0 && w.FrameClause == nil {
				copy.Over = &ast.WindowSpec{Name: c.slot(ast.QuoteNameWith(w.Name, w.NameQuote))}
			} else {
				if w.BaseWindow == "" {
					w.BaseWindow, w.BaseWindowQuote = w.Name, w.NameQuote
				}
				copy.Over = &ast.WindowSpec{Name: c.slot("(" + f.windowSpecSQL(&w) + ")")}
			}
		}
		return c.result(&copy)
	case *ast.NamedArgument:
		copy := *v
		copy.Name = c.slot(ast.QuoteName(v.Name))
		copy.Value = c.expr(v.Value)
		return c.result(&copy)
	case *ast.KeywordArgument:
		copy := *v
		copy.Value = c.expr(v.Value)
		if v.TypeName != "" {
			copy.TypeName = c.slot(lowerDataType(v.TypeName))
		}
		return c.result(&copy)
	case *ast.ListExpression:
		copy := *v
		copy.Values = c.exprs(v.Values)
		return c.result(&copy)
	case *ast.TupleExpression:
		copy := *v
		copy.Expressions = c.exprs(v.Expressions)
		return c.result(&copy)
	case *ast.ArrayConstructorExpression:
		if v.Subquery != nil {
			return "array(" + f.tableSubquerySQL(v.Subquery) + ")"
		}
		if v.Query != nil {
			return "array(" + f.tableSubquerySQL(v.Query) + ")"
		}
		copy := *v
		copy.Elements = c.exprs(v.Elements)
		return c.result(&copy)
	case *ast.ArraySubscriptExpression:
		copy := *v
		copy.Array = c.expr(v.Array)
		copy.Indices = c.exprs(v.Indices)
		return c.result(&copy)
	case *ast.ArraySliceExpression:
		copy := *v
		copy.Array = c.expr(v.Array)
		copy.Start = c.expr(v.Start)
		copy.End = c.expr(v.End)
		return c.result(&copy)
	case *ast.ExtractExpression:
		copy := *v
		copy.Source = c.expr(v.Source)
		return c.result(&copy)
	case *ast.PositionExpression:
		copy := *v
		copy.Substr = c.expr(v.Substr)
		copy.Str = c.expr(v.Str)
		return c.result(&copy)
	case *ast.SubstringExpression:
		copy := *v
		copy.Str = c.expr(v.Str)
		copy.Start = c.expr(v.Start)
		copy.Length = c.expr(v.Length)
		return c.result(&copy)
	case *ast.IntervalExpression:
		copy := *v
		copy.ValueExpr = c.expr(v.ValueExpr)
		return c.result(&copy)
	case *ast.TypedLiteral:
		copy := *v
		copy.TypeName = c.slot(lowerDataType(v.TypeName))
		return c.result(&copy)
	case *ast.AtTimeZoneExpression:
		copy := *v
		copy.Expr = c.postfixExpr(v.Expr)
		copy.Zone = c.postfixExpr(v.Zone)
		return c.result(&copy)
	case *ast.CollateExpression:
		// The suffix is a collation name or literal, not keyword syntax.
		copy := *v
		copy.Expr = c.postfixExpr(v.Expr)
		rendered := copy.SQL()
		return strings.Replace(rendered, " COLLATE ", " collate ", 1)
	case *ast.AnyAllExpression:
		copy := *v
		copy.Expr = c.expr(v.Expr)
		copy.Array = c.expr(v.Array)
		if sq, ok := v.Array.(*ast.SubqueryExpression); ok && sq != nil {
			copy.Array = &ast.SubqueryExpression{Subquery: &ast.UtilityStatement{Text: c.slot(f.tableSubquerySQL(sq.Subquery))}}
		}
		return c.result(&copy)
	case *ast.FieldAccessExpression:
		copy := *v
		copy.Args = c.exprs(v.Args)
		marker := c.slot("")
		copy.Expr = &ast.Identifier{Name: marker}
		suffix := strings.TrimPrefix(copy.SQL(), "("+marker+")")
		root := exprSQL(c.expr(v.Expr))
		switch v.Expr.(type) {
		case *ast.ParenthesizedExpression, *ast.SubqueryExpression, *ast.TupleExpression,
			*ast.FieldAccessExpression, *ast.ArraySubscriptExpression, *ast.ArraySliceExpression:
		default:
			root = "(" + root + ")"
		}
		return root + suffix
	case *ast.AnyExpression:
		return exprSQL(c.expr(v.Expr)) + " " + lowerSyntax(v.Operator) + " any (" + f.tableSubquerySQL(v.Subquery) + ")"
	case *ast.AllExpression:
		return exprSQL(c.expr(v.Expr)) + " " + lowerSyntax(v.Operator) + " all (" + f.tableSubquerySQL(v.Subquery) + ")"
	case *ast.TernaryExpression:
		copy := *v
		copy.Cond = c.expr(v.Cond)
		copy.Then = c.expr(v.Then)
		copy.Else = c.expr(v.Else)
		return c.result(&copy)
	case *ast.RollupExpression:
		copy := *v
		copy.Expressions = c.exprs(v.Expressions)
		return c.result(&copy)
	case *ast.CubeExpression:
		copy := *v
		copy.Expressions = c.exprs(v.Expressions)
		return c.result(&copy)
	case *ast.GroupingSetsExpression:
		// Rendered here rather than through slots: SQL() leaves a set that is
		// a lone ROLLUP, CUBE or GROUPING SETS unparenthesised, and a slot
		// would hide that element's type from it.
		var b strings.Builder
		b.WriteString("grouping sets(")
		for i, set := range v.Sets {
			if i > 0 {
				b.WriteString(", ")
			}
			if len(set) == 1 {
				switch set[0].(type) {
				case *ast.RollupExpression, *ast.CubeExpression, *ast.GroupingSetsExpression:
					b.WriteString(f.exprSQL(set[0]))
					continue
				}
			}
			b.WriteByte('(')
			for j, e := range set {
				if j > 0 {
					b.WriteString(", ")
				}
				b.WriteString(f.exprSQL(e))
			}
			b.WriteByte(')')
		}
		b.WriteByte(')')
		return b.String()
	case *ast.OuterJoinMarker:
		copy := *v
		copy.Expr = c.expr(v.Expr)
		return c.result(&copy)
	case *ast.MatchAgainstExpression:
		copy := *v
		copy.Columns = c.exprs(v.Columns)
		copy.Query = c.expr(v.Query)
		return c.result(&copy)
	case *ast.NextValueForExpression:
		copy := *v
		copy.Sequence = c.slot(ast.QuoteQualifiedName(v.Sequence))
		return c.result(&copy)
	case *ast.AssignmentExpression:
		copy := *v
		copy.Target = c.expr(v.Target)
		copy.Value = c.expr(v.Value)
		return c.result(&copy)
	case *ast.ConnectByRootExpression:
		copy := *v
		copy.Expr = c.expr(v.Expr)
		return c.result(&copy)
	case *ast.VariantPath:
		copy := *v
		copy.Segments = append([]ast.VariantPathSegment(nil), v.Segments...)
		for i := range copy.Segments {
			copy.Segments[i].Index = c.expr(v.Segments[i].Index)
		}
		copy.Root = c.expr(v.Root)
		switch v.Root.(type) {
		case *ast.BinaryExpression, *ast.CastExpression, *ast.CaseExpression,
			*ast.BetweenExpression, *ast.InExpression:
			copy.Root = &ast.ParenthesizedExpression{Expr: copy.Root}
		}
		return copy.SQL()
	case *ast.ObjectLiteral:
		copy := *v
		copy.Entries = append([]ast.ObjectEntry(nil), v.Entries...)
		for i := range copy.Entries {
			copy.Entries[i].Key = c.expr(copy.Entries[i].Key)
			copy.Entries[i].Value = c.expr(copy.Entries[i].Value)
		}
		return c.result(&copy)
	case *ast.JSONObjectEntry:
		copy := *v
		copy.Key = c.expr(v.Key)
		copy.Value = c.expr(v.Value)
		return c.result(&copy)
	case *ast.ClauseArgument:
		copy := *v
		copy.Head = c.expr(v.Head)
		// The parser retains this clause as raw text, including names.
		return copy.SQL()
	case *ast.DefaultExpr:
		return "default"
	case *ast.StarExpression:
		copy := *v
		copy.Star = c.expr(v.Star)
		copy.Ilike = c.expr(v.Ilike)
		copy.Apply = c.exprs(v.Apply)
		copy.Exclude = make([]string, len(v.Exclude))
		for i, name := range v.Exclude {
			copy.Exclude[i] = c.slot(ast.QuoteQualifiedName(name))
		}
		copy.Replace = make([]*ast.AliasedExpression, len(v.Replace))
		for i, item := range v.Replace {
			if item != nil {
				copy.Replace[i] = &ast.AliasedExpression{Expr: c.expr(item.Expr), Alias: c.slot(ast.QuoteName(item.Alias))}
			}
		}
		copy.Rename = append([]ast.StarRename(nil), v.Rename...)
		for i := range copy.Rename {
			copy.Rename[i].Column = c.slot(ast.QuoteName(copy.Rename[i].Column))
			copy.Rename[i].Alias = c.slot(ast.QuoteName(copy.Rename[i].Alias))
		}
		return c.result(&copy)
	default:
		return exprSQL(e)
	}
}
