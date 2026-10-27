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
	"strconv"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// expressionCase preserves SQL()'s operator spelling and parentheses while
// casing syntax separately from operands. Slots contain names or expression
// fragments referencing earlier slots. Only the outermost call expands them.
type expressionCase struct {
	f      *nodeFormatter
	prefix string
	slots  []string
}

func newExpressionCase(f *nodeFormatter, source string) *expressionCase {
	const base = "gosqlx_case_slot_"
	// Inspect the source once per root, including quoted names and literals.
	// A numeric suffix keeps the marker short even for hostile identifiers
	// containing very long runs of underscores or existing slot-like names.
	used := make(map[int]bool)
	for {
		i := strings.Index(source, base)
		if i < 0 {
			break
		}
		source = source[i+len(base):]
		end := 0
		for end < len(source) && source[end] >= '0' && source[end] <= '9' {
			end++
		}
		if end < len(source) && source[end] == '_' {
			if id, err := strconv.Atoi(source[:end]); err == nil {
				used[id] = true
			}
		}
		source = source[end:]
	}
	id := 0
	for used[id] {
		id++
	}
	return &expressionCase{f: f, prefix: base + strconv.Itoa(id) + "_"}
}

func (c *expressionCase) slot(sql string) string {
	name := c.prefix + strconv.Itoa(len(c.slots)) + "_"
	c.slots = append(c.slots, sql)
	return name
}

func (c *expressionCase) expr(e ast.Expression) ast.Expression {
	if e == nil {
		return nil
	}
	opts := c.f.opts
	opts.NewlinePerClause = false
	f := *c.f
	f.opts = opts
	sql := c.formatWith(&f, e)
	prefix := ""
	// SQL() separates adjacent symbolic operators using the operand's first
	// byte. Keep that byte visible while hiding the remainder from casing.
	if len(sql) > 0 && strings.ContainsRune("+-*/<>=~!@#%^&|?`", rune(sql[0])) {
		prefix, sql = sql[:1], sql[1:]
	}
	return &ast.LiteralValue{Type: "placeholder", Value: prefix + c.slot(sql)}
}

func (c *expressionCase) exprs(exprs []ast.Expression) []ast.Expression {
	out := make([]ast.Expression, len(exprs))
	for i, e := range exprs {
		out[i] = c.expr(e)
	}
	return out
}

func (c *expressionCase) orders(orders []ast.OrderByExpression) []ast.OrderByExpression {
	out := append([]ast.OrderByExpression(nil), orders...)
	for i := range out {
		out[i].Expression = c.expr(out[i].Expression)
		if fill := out[i].WithFill; fill != nil {
			copy := *fill
			copy.From = c.expr(fill.From)
			copy.To = c.expr(fill.To)
			copy.Step = c.expr(fill.Step)
			out[i].WithFill = &copy
		}
	}
	return out
}

func (c *expressionCase) restore(sql string) string {
	var out strings.Builder
	var pending []string
	for {
		i := strings.Index(sql, c.prefix)
		if i < 0 {
			out.WriteString(sql)
			if len(pending) == 0 {
				return out.String()
			}
			sql = pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			continue
		}
		out.WriteString(sql[:i])
		tail := sql[i+len(c.prefix):]
		end := 0
		for end < len(tail) && tail[end] >= '0' && tail[end] <= '9' {
			end++
		}
		id, err := strconv.Atoi(tail[:end])
		if err != nil || end == len(tail) || tail[end] != '_' || id >= len(c.slots) {
			out.WriteString(c.prefix)
			sql = tail
			continue
		}
		pending = append(pending, tail[end+1:])
		sql = c.slots[id]
	}
}

func (c *expressionCase) result(e ast.Expression) string {
	return lowerSyntax(exprSQL(e))
}

func (c *expressionCase) formatWith(f *nodeFormatter, e ast.Expression) string {
	switch v := e.(type) {
	case *ast.CaseExpression:
		return renderCase(v, f.opts, c)
	case *ast.BetweenExpression:
		return renderBetween(v, f.opts, c)
	case *ast.InExpression:
		return renderIn(v, f.opts, c)
	case *ast.ExistsExpression:
		return renderExists(v, f.opts)
	case *ast.SubqueryExpression:
		return renderSubquery(v, f.opts)
	default:
		return f.exprSQL(e)
	}
}

func formatExpressionChild(e ast.Expression, opts ast.FormatOptions, context ...*expressionCase) string {
	if len(context) == 0 {
		return FormatExpression(e, opts)
	}
	f := *context[0].f
	f.opts = opts
	return context[0].slot(context[0].formatWith(&f, e))
}

// lowerSyntax operates on AST-rendered syntax whose operands and names have
// been replaced by slots. Delimited names and string literals stay intact.
func lowerSyntax(sql string) string {
	var out strings.Builder
	for i := 0; i < len(sql); {
		ch := sql[i]
		if ch == '\'' || ch == '"' || ch == '`' || ch == '[' {
			end := ch
			if ch == '[' {
				end = ']'
			}
			start := i
			i++
			for i < len(sql) {
				if sql[i] == end {
					i++
					if i < len(sql) && sql[i] == end {
						i++
						continue
					}
					break
				}
				if sql[i] == '\\' && ch == '\'' && i+1 < len(sql) {
					i += 2
				} else {
					i++
				}
			}
			out.WriteString(sql[start:i])
			continue
		}
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		out.WriteByte(ch)
		i++
	}
	return out.String()
}

var expressionKeywords = keywords.New(keywords.DialectGeneric, true)

func (f *nodeFormatter) exprListSQL(exprs []ast.Expression) string {
	if f.opts.KeywordCase != ast.KeywordLower {
		return exprListSQL(exprs)
	}
	parts := make([]string, len(exprs))
	opts := f.opts
	opts.NewlinePerClause = false
	for i, e := range exprs {
		if f.expressionCase != nil {
			parts[i] = formatExpressionChild(e, opts, f.expressionCase)
		} else {
			parts[i] = FormatExpression(e, opts)
		}
	}
	return strings.Join(parts, ", ")
}

func (f *nodeFormatter) orderBySQL(orders []ast.OrderByExpression) string {
	if f.opts.KeywordCase != ast.KeywordLower {
		return orderBySQL(orders)
	}
	if f.expressionCase == nil {
		scoped := *f
		c := newExpressionCase(&scoped, orderBySQL(orders))
		scoped.expressionCase = c
		return c.restore(scoped.orderBySQL(orders))
	}
	return lowerSyntax(orderBySQL(f.expressionCase.orders(orders)))
}

func (f *nodeFormatter) windowSpecSQL(w *ast.WindowSpec) string {
	if f.opts.KeywordCase != ast.KeywordLower {
		return windowSpecSQL(w)
	}
	if f.expressionCase == nil {
		scoped := *f
		c := newExpressionCase(&scoped, windowSpecSQL(w))
		scoped.expressionCase = c
		return c.restore(scoped.windowSpecSQL(w))
	}
	var parts []string
	if w.BaseWindow != "" {
		parts = append(parts, ast.QuoteNameWith(w.BaseWindow, w.BaseWindowQuote))
	}
	if len(w.PartitionBy) > 0 {
		parts = append(parts, "partition by "+f.exprListSQL(w.PartitionBy))
	}
	if len(w.OrderBy) > 0 {
		parts = append(parts, "order by "+f.orderBySQL(w.OrderBy))
	}
	if w.FrameClause != nil {
		c := f.expressionCase
		copy := *w.FrameClause
		copy.Start.Value = c.expr(copy.Start.Value)
		if copy.End != nil {
			end := *copy.End
			end.Value = c.expr(end.Value)
			copy.End = &end
		}
		parts = append(parts, lowerSyntax(windowFrameSQL(&copy)))
	}
	return strings.Join(parts, " ")
}

func (f *nodeFormatter) tableSubquerySQL(s ast.Statement) string {
	if f.opts.KeywordCase != ast.KeywordLower {
		return stmtSQL(s)
	}
	opts := nestedOpts(f.opts)
	opts.NewlinePerClause = false
	return FormatStatement(s, opts)
}

func lowerDataType(typ string) string {
	// A qualified type names a user-defined binding even when its last
	// component happens to have the spelling of a built-in type.
	name := typ
	if i := strings.IndexAny(name, "([< "); i >= 0 {
		name = name[:i]
	}
	if strings.Contains(name, ".") {
		return typ
	}
	var out strings.Builder
	for i := 0; i < len(typ); {
		start := i
		for i < len(typ) && (typ[i] >= 'a' && typ[i] <= 'z' || typ[i] >= 'A' && typ[i] <= 'Z' || typ[i] == '_' || typ[i] >= '0' && typ[i] <= '9') {
			i++
		}
		if i > start {
			word := typ[start:i]
			if expressionKeywords.IsKeyword(word) || builtinTypeWord(word) {
				word = strings.ToLower(word)
			}
			out.WriteString(word)
		} else if typ[i] == '\'' || typ[i] == '"' || typ[i] == '`' {
			end := typ[i]
			i++
			for i < len(typ) {
				if typ[i] == end {
					i++
					if i < len(typ) && typ[i] == end {
						i++
						continue
					}
					break
				}
				i++
			}
			out.WriteString(typ[start:i])
		} else {
			out.WriteByte(typ[i])
			i++
		}
	}
	return out.String()
}

func builtinTypeWord(word string) bool {
	switch strings.ToUpper(word) {
	case "INT", "INTEGER", "BIGINT", "SMALLINT", "TINYINT", "MEDIUMINT", "INT2", "INT4", "INT8", "SERIAL", "BIGSERIAL", "SMALLSERIAL", "NUMERIC", "DECIMAL", "DEC", "NUMBER", "FLOAT", "REAL", "DOUBLE", "PRECISION", "MONEY", "SMALLMONEY", "BOOLEAN", "BOOL", "BIT", "CHAR", "CHARACTER", "NCHAR", "VARCHAR", "NVARCHAR", "VARCHAR2", "NVARCHAR2", "VARYING", "TEXT", "NTEXT", "CLOB", "NCLOB", "BLOB", "BINARY", "VARBINARY", "BYTEA", "DATE", "TIME", "DATETIME", "DATETIME2", "SMALLDATETIME", "DATETIMEOFFSET", "TIMESTAMP", "TIMESTAMPTZ", "INTERVAL", "JSON", "JSONB", "XML", "UUID", "UNSIGNED", "SIGNED", "ZONE", "WITH", "WITHOUT":
		return true
	}
	return false
}

func builtinFunctionName(name string) bool {
	switch strings.ToUpper(name) {
	case "ABS", "AVG", "COUNT", "SUM", "MIN", "MAX", "COALESCE", "NULLIF", "LOWER", "UPPER", "LENGTH", "CHAR_LENGTH", "CHARACTER_LENGTH", "OCTET_LENGTH", "SUBSTR", "SUBSTRING", "POSITION", "TRIM", "LTRIM", "RTRIM", "CONCAT", "ROUND", "CEIL", "CEILING", "FLOOR", "MOD", "POWER", "SQRT", "EXTRACT", "GROUP_CONCAT", "STRING_AGG", "ARRAY_AGG", "MULTISET":
		return true
	}
	return false
}

func (c *expressionCase) postfixExpr(e ast.Expression) ast.Expression {
	slotted := c.expr(e)
	switch e.(type) {
	case *ast.BinaryExpression, *ast.BetweenExpression, *ast.InExpression,
		*ast.AnyExpression, *ast.AllExpression, *ast.AnyAllExpression, *ast.TernaryExpression:
		return &ast.ParenthesizedExpression{Expr: slotted}
	default:
		return slotted
	}
}
