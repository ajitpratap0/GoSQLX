// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func formatLowerExpression(e ast.Expression, opts ast.FormatOptions) string {
	var out strings.Builder
	out.Grow(128)
	f := nodeFormatter{opts: opts}
	f.writeLowerExpression(&out, e)
	return out.String()
}

// writeLowerExpression streams common expression trees into one builder. Names
// and values are written verbatim, so they need neither marker slots nor a
// second scan. Less common syntax retains the SQL()-based compatibility path.
func (f *nodeFormatter) writeLowerExpression(out *strings.Builder, e ast.Expression) {
	if e == nil {
		return
	}
	switch v := e.(type) {
	case *ast.Identifier, *ast.Ident:
		out.WriteString(exprSQL(e))
	case *ast.LiteralValue:
		if v == nil {
			return
		}
		if v.Value == nil || strings.EqualFold(v.Type, "NULL") || strings.EqualFold(v.Type, "BOOLEAN") || strings.EqualFold(v.Type, "BOOL") {
			writeLowerText(out, v.SQL())
		} else {
			out.WriteString(v.SQL())
		}
	case *ast.ParenthesizedExpression:
		if v == nil {
			return
		}
		out.WriteByte('(')
		f.writeLowerChild(out, v.Expr)
		out.WriteByte(')')
	case *ast.BinaryExpression:
		if v == nil {
			return
		}
		if v.Not || v.CustomOp != nil || !directBinaryOperator(v.Operator) {
			f.writeLowerFallback(out, e)
			return
		}
		if v.Right == nil && strings.EqualFold(v.Operator, "NOT") {
			out.WriteString("not ")
			f.writeLowerOperand(out, v, v.Left, false)
			return
		}
		f.writeLowerOperand(out, v, v.Left, false)
		out.WriteByte(' ')
		if v.PipesOr && strings.EqualFold(v.Operator, "OR") {
			out.WriteString("||")
		} else {
			writeLowerText(out, v.Operator)
		}
		if !strings.EqualFold(v.Operator, "IS NULL") {
			out.WriteByte(' ')
			f.writeLowerOperand(out, v, v.Right, true)
		}
		if v.Extras != nil && v.Extras.Escape != nil {
			out.WriteString(" escape ")
			f.writeLowerExpression(out, v.Extras.Escape)
		}
	case *ast.UnaryExpression:
		if v == nil {
			return
		}
		// Other unary spellings retain SQL()'s adjacent-symbol separation rules.
		if v.Operator != ast.Not {
			f.writeLowerFallback(out, e)
			return
		}
		out.WriteString("not ")
		parent := ast.BinaryExpression{Operator: "NOT", Pos: v.Pos}
		f.writeLowerOperand(out, &parent, v.Expr, false)
	case *ast.ExistsExpression:
		if v == nil {
			return
		}
		out.WriteString("exists (")
		out.WriteString(formatStatement(v.Subquery, nestedOpts(f.opts)))
		out.WriteByte(')')
	case *ast.SubqueryExpression:
		if v == nil {
			return
		}
		if !v.Bare {
			out.WriteByte('(')
		}
		out.WriteString(formatStatement(v.Subquery, nestedOpts(f.opts)))
		if !v.Bare {
			out.WriteByte(')')
		}
	case *ast.AliasedExpression:
		if v == nil {
			return
		}
		f.writeLowerChild(out, v.Expr)
		out.WriteString(" as ")
		out.WriteString(ast.QuoteNameWith(v.Alias, v.AliasQuote))
	case *ast.CaseExpression:
		if v == nil {
			return
		}
		out.WriteString("case")
		if v.Value != nil {
			out.WriteByte(' ')
			f.writeLowerExpression(out, v.Value)
		}
		for _, w := range v.WhenClauses {
			out.WriteString(" when ")
			f.writeLowerExpression(out, w.Condition)
			out.WriteString(" then ")
			f.writeLowerExpression(out, w.Result)
		}
		if v.ElseClause != nil {
			out.WriteString(" else ")
			f.writeLowerExpression(out, v.ElseClause)
		}
		out.WriteString(" end")
	case *ast.BetweenExpression:
		if v == nil {
			return
		}
		f.writeLowerExpression(out, v.Expr)
		if v.Not {
			out.WriteString(" not")
		}
		out.WriteString(" between ")
		f.writeLowerExpression(out, v.Lower)
		out.WriteString(" and ")
		f.writeLowerExpression(out, v.Upper)
	case *ast.InExpression:
		if v == nil {
			return
		}
		f.writeLowerExpression(out, v.Expr)
		if v.Global {
			out.WriteString(" global")
		}
		if v.Not {
			out.WriteString(" not")
		}
		out.WriteString(" in ")
		if !v.Bare || v.Subquery != nil {
			out.WriteByte('(')
		}
		if v.Subquery != nil {
			opts := nestedOpts(f.opts)
			out.WriteString(formatStatement(v.Subquery, opts))
		} else {
			f.writeLowerList(out, v.List)
		}
		if !v.Bare || v.Subquery != nil {
			out.WriteByte(')')
		}
	case *ast.FunctionCall:
		if v == nil {
			return
		}
		// SQL() renders function operands compactly, even when the containing
		// statement has one clause per line.
		scoped := *f
		scoped.opts.NewlinePerClause = false
		f = &scoped
		if v.Extras != nil || len(v.OrderBy) > 0 || len(v.WithinGroup) > 0 || v.NullTreatment != "" {
			f.writeLowerFallback(out, e)
			return
		}
		for _, arg := range v.Arguments {
			if _, ok := arg.(*ast.KeywordArgument); ok {
				f.writeLowerFallback(out, e)
				return
			}
		}
		f.writeLowerFunctionName(out, v)
		if len(v.Parameters) > 0 {
			out.WriteByte('(')
			f.writeLowerList(out, v.Parameters)
			out.WriteByte(')')
		}
		out.WriteByte('(')
		if v.Distinct {
			out.WriteString("distinct ")
		}
		f.writeLowerList(out, v.Arguments)
		out.WriteByte(')')
		if v.Filter != nil {
			out.WriteString(" filter (where ")
			f.writeLowerExpression(out, v.Filter)
			out.WriteByte(')')
		}
		if w := v.Over; w != nil {
			out.WriteString(" over ")
			if w.Name != "" && w.BaseWindow == "" && len(w.PartitionBy) == 0 && len(w.OrderBy) == 0 && w.FrameClause == nil {
				out.WriteString(ast.QuoteNameWith(w.Name, w.NameQuote))
			} else {
				out.WriteByte('(')
				copy := *w
				if copy.BaseWindow == "" {
					copy.BaseWindow, copy.BaseWindowQuote = copy.Name, copy.NameQuote
				}
				out.WriteString(f.windowSpecSQL(&copy))
				out.WriteByte(')')
			}
		}
	default:
		f.writeLowerFallback(out, e)
	}
}

func (f *nodeFormatter) writeLowerFunctionName(out *strings.Builder, v *ast.FunctionCall) {
	if v.NameQuote == 0 {
		// These builtins always have bare SQL() names. Write them directly
		// instead of allocating a temporary function call just for its name.
		switch strings.ToUpper(v.Name) {
		case "ABS", "AVG", "COUNT", "SUM", "MIN", "MAX", "COALESCE", "NULLIF", "ROW_NUMBER":
			writeLowerText(out, v.Name)
			return
		}
	}
	name := strings.TrimSuffix((&ast.FunctionCall{Name: v.Name, NameQuote: v.NameQuote}).SQL(), "()")
	if v.NameQuote == 0 && (expressionKeywords.IsKeyword(v.Name) || builtinFunctionName(v.Name)) {
		writeLowerText(out, name)
	} else {
		out.WriteString(name)
	}
}

func (f *nodeFormatter) writeLowerFallback(out *strings.Builder, e ast.Expression) {
	scoped := *f
	scoped.opts.NewlinePerClause = false
	c := newExpressionCase(&scoped, exprSQL(e))
	scoped.expressionCase = c
	out.WriteString(c.restore(c.formatWith(&scoped, e)))
}

func (f *nodeFormatter) writeLowerList(out *strings.Builder, exprs []ast.Expression) {
	for i, e := range exprs {
		if i > 0 {
			out.WriteString(", ")
		}
		f.writeLowerExpression(out, e)
	}
}

func (f *nodeFormatter) writeLowerOperand(out *strings.Builder, parent *ast.BinaryExpression, child ast.Expression, right bool) {
	parens := ast.BinaryOperandNeedsParens(parent, child, right)
	if parens {
		out.WriteByte('(')
	}
	f.writeLowerChild(out, child)
	if parens {
		out.WriteByte(')')
	}
}

func (f *nodeFormatter) writeLowerChild(out *strings.Builder, e ast.Expression) {
	scoped := *f
	scoped.opts.NewlinePerClause = false
	scoped.writeLowerExpression(out, e)
}

func writeLowerText(out *strings.Builder, text string) {
	for i := 0; i < len(text); i++ {
		ch := text[i]
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		out.WriteByte(ch)
	}
}

// Only operators whose spelling is already safe SQL use the streaming path;
// SQL() remains responsible for validating custom and hand-built operators.
func directBinaryOperator(op string) bool {
	switch strings.ToUpper(op) {
	case "+", "-", "*", "/", "%", "^", "=", "!=", "<>", "<", ">", "<=", ">=", "==", "AND", "OR", "XOR", "NOT", "IS", "IS NOT", "IS NULL", "IS DISTINCT FROM", "IS NOT DISTINCT FROM", "LIKE", "ILIKE", "SIMILAR TO", "REGEXP", "RLIKE", "GLOB", "MATCH", "SOUNDS LIKE", "DIV", "MOD", "||", "&", "|", "#", "<<", ">>":
		return true
	}
	return false
}

func (f *nodeFormatter) writeLowerOrders(out *strings.Builder, orders []ast.OrderByExpression) {
	for i, o := range orders {
		if i > 0 {
			out.WriteString(", ")
		}
		f.writeLowerExpression(out, o.Expression)
		if op := ast.OrderUsingOperatorText(o.UsingOperator); op != "" {
			out.WriteString(" using ")
			out.WriteString(op)
		} else if !o.Ascending {
			out.WriteString(" desc")
		}
		if o.NullsFirst != nil {
			if *o.NullsFirst {
				out.WriteString(" nulls first")
			} else {
				out.WriteString(" nulls last")
			}
		}
		if w := o.WithFill; w != nil {
			out.WriteString(" with fill")
			if w.From != nil {
				out.WriteString(" from ")
				f.writeLowerExpression(out, w.From)
			}
			if w.To != nil {
				out.WriteString(" to ")
				f.writeLowerExpression(out, w.To)
			}
			if w.Step != nil {
				out.WriteString(" step ")
				f.writeLowerExpression(out, w.Step)
			}
		}
	}
}

func (f *nodeFormatter) writeLowerWindow(out *strings.Builder, w *ast.WindowSpec) {
	sep := ""
	if w.BaseWindow != "" {
		out.WriteString(ast.QuoteNameWith(w.BaseWindow, w.BaseWindowQuote))
		sep = " "
	}
	if len(w.PartitionBy) > 0 {
		out.WriteString(sep)
		out.WriteString("partition by ")
		f.writeLowerList(out, w.PartitionBy)
		sep = " "
	}
	if len(w.OrderBy) > 0 {
		out.WriteString(sep)
		out.WriteString("order by ")
		f.writeLowerOrders(out, w.OrderBy)
		sep = " "
	}
	if frame := w.FrameClause; frame != nil {
		out.WriteString(sep)
		writeLowerText(out, ast.FrameUnitText(frame.Type))
		out.WriteByte(' ')
		if frame.End != nil {
			out.WriteString("between ")
		}
		f.writeLowerFrameBound(out, &frame.Start)
		if frame.End != nil {
			out.WriteString(" and ")
			f.writeLowerFrameBound(out, frame.End)
		}
		if ex := ast.FrameExcludeText(frame.Exclude); ex != "" {
			out.WriteString(" exclude ")
			writeLowerText(out, ex)
		}
	}
}

func (f *nodeFormatter) writeLowerFrameBound(out *strings.Builder, b *ast.WindowFrameBound) {
	if b.Value != nil {
		f.writeLowerExpression(out, b.Value)
		out.WriteByte(' ')
	}
	writeLowerText(out, ast.FrameBoundText(b.Type))
}
