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

// render.go - visitor-based SQL rendering for AST nodes.
// All formatting logic lives here; AST nodes are pure data (no Format methods).
// This follows the go/ast + go/printer separation pattern.

package formatter

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// nodeFormatter holds state during a single rendering pass.
type nodeFormatter struct {
	opts           ast.FormatOptions
	sb             *strings.Builder
	depth          int
	expressionCase *expressionCase
}

func newNodeFormatter(opts ast.FormatOptions) *nodeFormatter {
	return &nodeFormatter{
		opts: opts,
		sb:   &strings.Builder{},
	}
}

// kw applies keyword casing to a keyword string.
func (f *nodeFormatter) kw(keyword string) string {
	switch f.opts.KeywordCase {
	case ast.KeywordUpper:
		return strings.ToUpper(keyword)
	case ast.KeywordLower:
		return strings.ToLower(keyword)
	default:
		return keyword
	}
}

// indentStr returns the current indentation string.
func (f *nodeFormatter) indentStr() string {
	if f.opts.IndentWidth == 0 {
		return ""
	}
	ch := " "
	if f.opts.IndentStyle == ast.IndentTabs {
		ch = "\t"
	}
	return strings.Repeat(ch, f.opts.IndentWidth*f.depth)
}

// clauseSep returns the separator between SQL clauses.
func (f *nodeFormatter) clauseSep() string {
	if f.opts.NewlinePerClause {
		return "\n" + f.indentStr()
	}
	return " "
}

func (f *nodeFormatter) result() string {
	return f.sb.String()
}

// ─── public rendering API ────────────────────────────────────────────────────

// FormatAST renders an AST. An unsupported target operator returns an empty
// string; use FormatASTChecked to receive the diagnostic.
func FormatAST(a *ast.AST, opts ast.FormatOptions) string {
	out, _ := FormatASTChecked(a, opts)
	return out
}

// FormatStatement renders a statement. If a target-dialect conversion is
// unsupported, it returns an empty string and discards the error. Use
// FormatStatementChecked whenever the result can carry a target dialect.
func FormatStatement(s ast.Statement, opts ast.FormatOptions) string {
	out, _ := FormatStatementChecked(s, opts)
	return out
}

// EnsureStatementTerminator applies the full-AST termination rule to a rendered
// statement. Batch separators and empty statements never receive a semicolon.
func EnsureStatementTerminator(stmt ast.Statement, part string, addSemicolon bool) string {
	_, isBatch := stmt.(*ast.BatchSeparator)
	if addSemicolon && !isBatch && part != "" && !strings.HasSuffix(part, ";") {
		return part + ";"
	}
	return part
}

// ExecuteSlashStatement appends an Oracle execute command without adding a
// SQL statement terminator. PL/SQL blocks retain their required END semicolon.
func ExecuteSlashStatement(stmt ast.Statement, part string) string {
	if utility, ok := stmt.(*ast.UtilityStatement); ok && !strings.HasSuffix(part, ";") {
		text := strings.ToUpper(utility.Text)
		if utility.Kind == "BEGIN" || utility.Kind == "DECLARE" ||
			utility.Kind == "CREATE PACKAGE" || utility.Kind == "CREATE PACKAGE BODY" ||
			(strings.HasPrefix(text, "CREATE ") && strings.Contains(text, " BEGIN ")) {
			part += ";"
		}
	}
	return part + "\n/"
}

// FormatExpression renders an expression. If a target-dialect conversion is
// unsupported, it returns an empty string and discards the error. Use
// FormatExpressionChecked whenever the result can carry a target dialect.
func FormatExpression(e ast.Expression, opts ast.FormatOptions) string {
	out, _ := FormatExpressionChecked(e, opts)
	return out
}

// FormatAST renders a full *ast.AST with the given options.
func formatAST(a *ast.AST, opts ast.FormatOptions) string {
	if a == nil {
		return ""
	}
	// A compact single statement needs neither the parts slice nor the join.
	// Keep source-spelling restoration and termination on the shared path.
	if len(a.Statements) == 1 && !opts.NewlinePerClause && len(a.Comments) == 0 &&
		(len(a.ExecuteSlash) == 0 || !a.ExecuteSlash[0]) {
		stmt := a.Statements[0]
		part := RestoreUnicodeIdentifiers(a, 0, formatStatement(stmt, opts), opts.Dialect)
		return EnsureStatementTerminator(stmt, part, opts.AddSemicolon)
	}
	parts := make([]string, 0, len(a.Statements))
	hasBatch := false
	for i, stmt := range a.Statements {
		statementOpts := opts
		if i < len(a.ExecuteSlash) && a.ExecuteSlash[i] {
			statementOpts.AddSemicolon = false
		}
		part := RestoreUnicodeIdentifiers(a, i, formatStatement(stmt, statementOpts), statementOpts.Dialect)
		// Renderers that keep a statement as written (UtilityStatement and
		// the stmtSQL fallback) do not add the ";" themselves; without it the
		// next statement would be read back as part of their text.
		_, isBatch := stmt.(*ast.BatchSeparator)
		hasBatch = hasBatch || isBatch
		if i < len(a.ExecuteSlash) && a.ExecuteSlash[i] {
			part = ExecuteSlashStatement(stmt, part)
			hasBatch = true // execute commands also separate statements without a semicolon
		} else {
			part = EnsureStatementTerminator(stmt, part, opts.AddSemicolon)
		}
		parts = append(parts, part)
	}
	sep := ";\n"
	if opts.AddSemicolon {
		// Each statement now ends with ";"
		sep = "\n"
	}
	var result string
	if !hasBatch {
		result = strings.Join(parts, sep)
	} else {
		var joined strings.Builder
		for i, part := range parts {
			if i > 0 {
				_, prevBatch := a.Statements[i-1].(*ast.BatchSeparator)
				_, curBatch := a.Statements[i].(*ast.BatchSeparator)
				if prevBatch || curBatch || (i-1 < len(a.ExecuteSlash) && a.ExecuteSlash[i-1]) {
					joined.WriteByte('\n')
				} else {
					joined.WriteString(sep)
				}
			}
			joined.WriteString(part)
		}
		result = joined.String()
	}

	// Emit preserved comments
	if len(a.Comments) > 0 {
		var leading, trailing []string
		for _, c := range a.Comments {
			if c.Inline {
				trailing = append(trailing, c.Text)
			} else {
				leading = append(leading, c.Text)
			}
		}
		var sb strings.Builder
		for _, lc := range leading {
			sb.WriteString(lc)
			sb.WriteString("\n")
		}
		sb.WriteString(result)
		for _, tc := range trailing {
			sb.WriteString(" ")
			sb.WriteString(tc)
		}
		result = sb.String()
	}

	return result
}

// FormatStatement renders a single AST statement with the given options.
// Returns "" for nil.
func formatStatement(s ast.Statement, opts ast.FormatOptions) string {
	// SQL() has the same compact spelling for these statements. Indentation
	// is irrelevant without clause newlines. Lowercase keywords, terminators,
	// and target-dialect rewrites still require the visitor renderer.
	if !opts.NewlinePerClause && !opts.AddSemicolon && opts.LineWidth == 0 &&
		opts.Dialect == "" && (opts.KeywordCase == ast.KeywordPreserve || opts.KeywordCase == ast.KeywordUpper) {
		switch s.(type) {
		case *ast.SelectStatement, *ast.InsertStatement, *ast.UpdateStatement, *ast.DeleteStatement:
			return stmtSQL(s)
		}
	}
	// SetOperation deliberately remains on the visitor path: its SQL() method
	// differs for nil operands.
	return formatStatementSlow(s, opts)
}

// formatStatementSlow is the visitor renderer, retained as the compact-path oracle.
func formatStatementSlow(s ast.Statement, opts ast.FormatOptions) string {
	if s == nil {
		return ""
	}
	switch v := s.(type) {
	case *ast.SelectStatement:
		return renderSelect(v, opts)
	case *ast.InsertStatement:
		return renderInsert(v, opts)
	case *ast.UpdateStatement:
		return renderUpdate(v, opts)
	case *ast.DeleteStatement:
		return renderDelete(v, opts)
	case *ast.CreateTableStatement:
		return renderCreateTable(v, opts)
	case *ast.SetOperation:
		return renderSetOperation(v, opts)
	case *ast.AlterTableStatement: //nolint:staticcheck // AlterTableStatement kept for backward compatibility
		return renderAlterTable(v, opts)
	case *ast.AlterStatement:
		return renderAlterStatement(v, opts)
	case *ast.CreateIndexStatement:
		return renderCreateIndex(v, opts)
	case *ast.CreateViewStatement:
		return renderCreateView(v, opts)
	case *ast.CreateMaterializedViewStatement:
		return renderCreateMaterializedView(v, opts)
	case *ast.RefreshMaterializedViewStatement:
		return renderRefreshMaterializedView(v, opts)
	case *ast.DropStatement:
		return renderDrop(v, opts)
	case *ast.TruncateStatement:
		return renderTruncate(v, opts)
	case *ast.MergeStatement:
		return renderMerge(v, opts)
	case *ast.CreateSequenceStatement:
		return renderCreateSequence(v, opts)
	case *ast.AlterSequenceStatement:
		return renderAlterSequence(v, opts)
	case *ast.DropSequenceStatement:
		return renderDropSequence(v, opts)
	case *ast.ShowStatement:
		return renderShow(v, opts)
	case *ast.DescribeStatement:
		return renderDescribe(v, opts)
	case *ast.ExplainStatement:
		return renderExplain(v, opts)
	case *ast.UnsupportedStatement:
		return renderUnsupported(v, opts)
	default:
		// Fallback to SQL() for unrecognized statement types
		return stmtSQL(s)
	}
}

// FormatExpression renders an AST expression with the given options.
// Returns "" for nil.
func formatExpression(e ast.Expression, opts ast.FormatOptions) string {
	if e == nil {
		return ""
	}
	if opts.KeywordCase == ast.KeywordLower {
		return formatLowerExpression(e, opts)
	}
	switch v := e.(type) {
	case *ast.CaseExpression:
		return renderCase(v, opts)
	case *ast.BetweenExpression:
		return renderBetween(v, opts)
	case *ast.InExpression:
		return renderIn(v, opts)
	case *ast.ExistsExpression:
		return renderExists(v, opts)
	case *ast.SubqueryExpression:
		return renderSubquery(v, opts)
	default:
		if opts.KeywordCase == ast.KeywordLower {
			return newNodeFormatter(opts).exprSQL(e)
		}
		return exprSQL(e)
	}
}

// ─── statement renderers ─────────────────────────────────────────────────────

func renderSelect(s *ast.SelectStatement, opts ast.FormatOptions) string {
	if s == nil {
		return ""
	}

	// Dialect normalization: work on a shallow copy so the original AST is not mutated.
	stmt := *s
	s = &stmt
	normalizeSelectForDialect(s, opts.Dialect)

	f := newNodeFormatter(opts)
	sb := f.sb
	// Most rendered SELECTs are under 128 bytes; one up-front allocation
	// replaces the builder's 8-16-32-64-128 growth steps.
	sb.Grow(128)

	if s.With != nil {
		sb.WriteString(renderWith(s.With, f))
		sb.WriteString(f.clauseSep())
	}

	sb.WriteString(f.kw("SELECT"))
	sb.WriteString(" ")

	if len(s.DistinctOnColumns) > 0 {
		sb.WriteString(f.kw("DISTINCT ON"))
		sb.WriteString(" (")
		sb.WriteString(f.exprListSQL(s.DistinctOnColumns))
		sb.WriteString(") ")
	} else if s.Distinct {
		sb.WriteString(f.kw("DISTINCT"))
		sb.WriteString(" ")
	}

	// MySQL select modifiers and TOP, between SELECT [DISTINCT] and columns.
	writeSelectPrologue(sb, s, f)

	sb.WriteString(selectColumnsForDialect(s.Columns, f))

	if into := selectExtras(s).Into; into != nil && !into.Trailing {
		sb.WriteString(" ")
		sb.WriteString(selectIntoSQL(into, f))
	}

	if len(s.From) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("FROM"))
		sb.WriteString(" ")
		froms := make([]string, len(s.From))
		for i := range s.From {
			froms[i] = tableRefSQL(&s.From[i], f)
		}
		sb.WriteString(strings.Join(froms, ", "))
	}

	for _, j := range s.Joins {
		j := j
		if !j.Comma {
			sb.WriteString(f.clauseSep())
		}
		sb.WriteString(joinSQL(&j, f))
	}

	// ClickHouse writes SAMPLE with the table expression, before ARRAY JOIN.
	if sample := ast.SampleExpressionSQL(s.Sample, f.kw); sample != "" {
		sb.WriteString(f.clauseSep())
		sb.WriteString(sample)
	}

	if s.ArrayJoin != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(arrayJoinSQL(s.ArrayJoin, f))
	}

	if s.PrewhereClause != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("PREWHERE"))
		sb.WriteString(" ")
		sb.WriteString(formatExpression(s.PrewhereClause, opts))
	}

	if s.Where != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("WHERE"))
		sb.WriteString(" ")
		sb.WriteString(formatExpression(s.Where, opts))
	}

	if gb := groupBySQL(s, f); gb != "" {
		sb.WriteString(f.clauseSep())
		sb.WriteString(gb)
	}

	if s.Having != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("HAVING"))
		sb.WriteString(" ")
		sb.WriteString(formatExpression(s.Having, opts))
	}

	// QUALIFY, START WITH, CONNECT BY
	writeHierarchical(sb, s, f)

	if len(s.Windows) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("WINDOW"))
		sb.WriteString(" ")
		wins := make([]string, len(s.Windows))
		for i := range s.Windows {
			wins[i] = ast.QuoteNameWith(s.Windows[i].Name, f.nq(s.Windows[i].NameQuote)) + " " + f.kw("AS") + " (" + f.windowSpecSQL(&s.Windows[i]) + ")"
		}
		sb.WriteString(strings.Join(wins, ", "))
	}

	if len(s.OrderBy) > 0 {
		sb.WriteString(f.clauseSep())
		if s.DialectExtras().OrderSiblings {
			sb.WriteString(f.kw("ORDER SIBLINGS BY"))
		} else {
			sb.WriteString(f.kw("ORDER BY"))
		}
		sb.WriteString(" ")
		sb.WriteString(f.orderBySQL(s.OrderBy))
	}
	if interp := selectExtras(s).Interpolate; interp != nil {
		sb.WriteString(interpolateSQL(interp, f))
	}

	// LIMIT BY, LIMIT, OFFSET
	writeLimitOffsetClauses(sb, s, f)

	if s.Fetch != nil {
		sb.WriteString(fetchSQL(s.Fetch, f))
	}

	if into := selectExtras(s).Into; into != nil && into.Trailing {
		sb.WriteString(f.clauseSep())
		sb.WriteString(selectIntoSQL(into, f))
	}

	if s.For != nil {
		sb.WriteString(forSQL(s.For, f))
	}

	// FOR JSON/XML, SETTINGS, OPTION (...), FORMAT
	writeSelectEpilogue(sb, s, f)

	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
}

// normalizeSelectForDialect converts generic LIMIT/OFFSET fields into
// dialect-specific AST fields (TOP for SQL Server, FETCH for Oracle) on a
// shallow copy of the statement. This keeps the rendering code simple —
// each clause renderer only handles its own field.
func normalizeSelectForDialect(s *ast.SelectStatement, dialect string) {
	normalizeLimitForDialect(s, dialect)
}

func renderInsert(i *ast.InsertStatement, opts ast.FormatOptions) string {
	if i == nil {
		return ""
	}
	if i.DialectExtras().MultiTable != nil {
		// Oracle INSERT ALL / FIRST: rendered on one line by the AST.
		if opts.AddSemicolon {
			return i.SQL() + ";"
		}
		return i.SQL()
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	if i.With != nil {
		sb.WriteString(renderWith(i.With, f))
		sb.WriteString(f.clauseSep())
	}

	writeInsertHead(sb, f, i)

	// MySQL INSERT ... SET form: Columns[k] = Values[0][k].
	setForm := i.SetSyntax && i.Query == nil && len(i.Columns) > 0 &&
		len(i.Values) == 1 && len(i.Values[0]) == len(i.Columns)

	if len(i.Columns) > 0 && !setForm {
		sb.WriteString(" (")
		sb.WriteString(ast.ColumnRefListSQL(i.Columns))
		sb.WriteString(")")
	}

	if !setForm {
		writeDMLOutput(sb, f, i.Output, i.DialectExtras().OutputInto)
		writeInsertBeforeSource(sb, f, i)
	}

	if setForm {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("SET"))
		sb.WriteString(" ")
		sets := make([]string, len(i.Columns))
		for k, col := range i.Columns {
			sets[k] = ast.ColumnRefSQL(col) + " = " + f.exprSQL(i.Values[0][k])
		}
		sb.WriteString(strings.Join(sets, ", "))
	} else if i.Query != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(formatStatement(i.Query, nestedOpts(opts)))
	} else if len(i.Values) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("VALUES"))
		sb.WriteString(" ")
		rows := make([]string, len(i.Values))
		for idx, row := range i.Values {
			vals := make([]string, len(row))
			for j, v := range row {
				vals[j] = f.exprSQL(v)
			}
			rows[idx] = "(" + strings.Join(vals, ", ") + ")"
		}
		sb.WriteString(strings.Join(rows, ", "))
	} else if i.DefaultValues {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("DEFAULT VALUES"))
	}
	writeInsertAfterSource(sb, f, i)

	if i.OnConflict != nil {
		sb.WriteString(onConflictSQL(i.OnConflict, f))
	}

	if i.OnDuplicateKey != nil && len(i.OnDuplicateKey.Updates) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("ON DUPLICATE KEY UPDATE"))
		sb.WriteString(" ")
		upds := make([]string, len(i.OnDuplicateKey.Updates))
		for k, u := range i.OnDuplicateKey.Updates {
			upds[k] = ast.ColumnRefSQL(u.Column) + " = " + f.exprSQL(u.Value)
		}
		sb.WriteString(strings.Join(upds, ", "))
	}

	writeInsertTail(sb, f, i)

	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
}

func renderUpdate(u *ast.UpdateStatement, opts ast.FormatOptions) string {
	if u == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	if u.With != nil {
		sb.WriteString(renderWith(u.With, f))
		sb.WriteString(f.clauseSep())
	}

	x := u.DialectExtras()
	sb.WriteString(f.kw("UPDATE"))
	sb.WriteString(" ")
	writeDMLModifiers(sb, f, x.Modifiers)
	writeDMLTop(sb, f, x.Top)
	writeDMLTargets(sb, f, x, u.TableName, u.TableNameQuote, u.Alias, u.AliasQuote)
	if len(u.From) == 0 {
		writeDMLJoins(sb, f, x.Joins)
	}

	sb.WriteString(f.clauseSep())
	sb.WriteString(f.kw("SET"))
	sb.WriteString(" ")
	upds := make([]string, len(u.Assignments))
	for i, upd := range u.Assignments {
		upds[i] = ast.ColumnRefSQL(upd.Column) + " = " + f.exprSQL(upd.Value)
	}
	sb.WriteString(strings.Join(upds, ", "))
	writeDMLOutput(sb, f, x.Output, x.OutputInto)

	if len(u.From) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("FROM"))
		sb.WriteString(" ")
		froms := make([]string, len(u.From))
		for i := range u.From {
			froms[i] = tableRefSQL(&u.From[i], f)
		}
		sb.WriteString(strings.Join(froms, ", "))
		writeDMLJoins(sb, f, x.Joins)
	}

	if u.Where != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("WHERE"))
		sb.WriteString(" ")
		sb.WriteString(formatExpression(u.Where, opts))
	}
	writeDMLOrderLimit(sb, f, x)
	writeReturning(sb, f, u.Returning, x.ReturningInto)

	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
}

func renderDelete(d *ast.DeleteStatement, opts ast.FormatOptions) string {
	if d == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	if d.With != nil {
		sb.WriteString(renderWith(d.With, f))
		sb.WriteString(f.clauseSep())
	}

	x := d.DialectExtras()
	sb.WriteString(f.kw("DELETE"))
	sb.WriteString(" ")
	writeDMLModifiers(sb, f, x.Modifiers)
	writeDMLTop(sb, f, x.Top)
	if len(d.From) == 0 {
		sb.WriteString(f.kw("FROM"))
		sb.WriteString(" ")
	}
	writeDMLTargets(sb, f, x, d.TableName, d.TableNameQuote, d.Alias, d.AliasQuote)
	var history ast.DeleteHistoryOptions
	if x.History != nil {
		history = *x.History
	}
	if len(history.Partitions) > 0 {
		sb.WriteString(" ")
		sb.WriteString(f.kw("PARTITION"))
		sb.WriteString(" (")
		for i, partition := range history.Partitions {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(f.exprSQL(partition))
		}
		sb.WriteByte(')')
	}
	if d.BeforeSystemTime != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("BEFORE SYSTEM_TIME"))
		sb.WriteString(" ")
		if history.BeforeSystemTimeUnit != "" {
			sb.WriteString(f.kw(history.BeforeSystemTimeUnit))
			sb.WriteString(" ")
		}
		sb.WriteString(f.exprSQL(d.BeforeSystemTime))
	}
	writeDMLOutput(sb, f, x.Output, x.OutputInto)

	if len(d.From) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("FROM"))
		sb.WriteString(" ")
		froms := make([]string, len(d.From))
		for i := range d.From {
			froms[i] = tableRefSQL(&d.From[i], f)
		}
		sb.WriteString(strings.Join(froms, ", "))
	}

	if len(d.Using) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("USING"))
		sb.WriteString(" ")
		usings := make([]string, len(d.Using))
		for i := range d.Using {
			usings[i] = tableRefSQL(&d.Using[i], f)
		}
		sb.WriteString(strings.Join(usings, ", "))
	}
	writeDMLJoins(sb, f, x.Joins)

	if d.Where != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("WHERE"))
		sb.WriteString(" ")
		sb.WriteString(formatExpression(d.Where, opts))
	}
	writeDMLOrderLimit(sb, f, x)
	writeReturning(sb, f, d.Returning, x.ReturningInto)

	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
}

func renderCreateTable(c *ast.CreateTableStatement, opts ast.FormatOptions) string {
	return renderCreateTableStmt(c, opts)
}

func renderSetOperation(s *ast.SetOperation, opts ast.FormatOptions) string {
	if s == nil {
		return ""
	}
	// A WITH clause that scopes over the whole operation but would end up
	// inside the parentheses of a left operand is written before the chain.
	if with, body := ast.HoistLeadingWith(s, opts.Dialect); with != nil {
		f := newNodeFormatter(opts)
		f.sb.WriteString(renderWith(with, f))
		f.sb.WriteString(f.clauseSep())
		f.sb.WriteString(renderSetOperationBody(body, opts))
		return f.result()
	}
	return renderSetOperationBody(s, opts)
}

func renderSetOperationBody(s *ast.SetOperation, opts ast.FormatOptions) string {
	f := newNodeFormatter(opts)
	sb := f.sb
	inner := nestedOpts(opts)

	// A chain such as a UNION b UNION c parses into a left-deep tree. Walk
	// down the left spine and render the levels innermost first into one
	// builder, so the output is produced in time linear in its length
	// rather than re-copying the rendered left side at every level. The
	// result is identical to rendering each level as
	// render(Left) + sep + op + sep + render(Right), with operands rendered
	// without ";" and a single ";" after the whole chain when AddSemicolon
	// is set.
	spine := []*ast.SetOperation{s}
	for {
		last := spine[len(spine)-1]
		if ast.SetOperandNeedsParens(last, false, opts.Dialect) {
			// A parenthesized left operand is rendered whole, in parentheses.
			break
		}
		left, ok := last.Left.(*ast.SetOperation)
		if !ok || left == nil {
			break
		}
		spine = append(spine, left)
	}

	if innermost := spine[len(spine)-1]; innermost.Left != nil {
		if ast.SetOperandNeedsParens(innermost, false, opts.Dialect) {
			sb.WriteString("(")
			sb.WriteString(formatStatement(innermost.Left, inner))
			sb.WriteString(")")
		} else {
			sb.WriteString(formatStatement(innermost.Left, inner))
		}
	}
	for i := len(spine) - 1; i >= 0; i-- {
		level := spine[i]
		sb.WriteString(f.clauseSep())
		// The operator is UNION, EXCEPT or INTERSECT; anything else can only
		// come from a hand-built AST and is written as UNION followed by the
		// double-quoted text, which fails to parse (see ast.SetOperatorSQL).
		op, known := ast.SetOperationKeyword(level, opts.Dialect)
		if known {
			op = f.kw(op)
		}
		sb.WriteString(op)
		sb.WriteString(f.clauseSep())
		if level.Right != nil {
			if ast.SetOperandNeedsParens(level, true, opts.Dialect) {
				sb.WriteString("(")
				sb.WriteString(formatStatement(level.Right, inner))
				sb.WriteString(")")
			} else {
				sb.WriteString(formatStatement(level.Right, inner))
			}
		}
	}
	if t := s.Tail; t != nil {
		// ORDER BY / LIMIT / OFFSET / FETCH of the whole operation.
		view := t.Select()
		// A set tail cannot use TOP, and SQL Server OFFSET/FETCH needs
		// ORDER BY. Keep unsupported LIMIT visible for direct formatting;
		// Transpile rejects this case before rendering.
		if opts.Dialect != "sqlserver" || len(view.OrderBy) > 0 {
			normalizeSelectForDialect(view, opts.Dialect)
		}
		if len(view.OrderBy) > 0 {
			sb.WriteString(f.clauseSep())
			sb.WriteString(f.kw("ORDER BY"))
			sb.WriteString(" ")
			sb.WriteString(f.orderBySQL(view.OrderBy))
		}
		writeLimitOffsetClauses(sb, view, f)
		if view.Fetch != nil {
			sb.WriteString(fetchSQL(view.Fetch, f))
		}
	}
	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
}

func renderAlterTable(a *ast.AlterTableStatement, opts ast.FormatOptions) string { //nolint:staticcheck // AlterTableStatement kept for backward compatibility
	if a == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("ALTER TABLE"))
	sb.WriteString(" ")
	sb.WriteString(ast.QuoteQualifiedName(a.Table))

	for i, action := range a.Actions {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw(ast.AlterTableActionText(action.Type)))
		if action.ColumnDef != nil {
			sb.WriteString(" ")
			sb.WriteString(columnDefSQL(action.ColumnDef))
		} else if action.Constraint != nil {
			sb.WriteString(" ")
			sb.WriteString(tableConstraintSQL(action.Constraint))
		} else if action.ColumnName != "" {
			sb.WriteString(" ")
			sb.WriteString(ast.QuoteColumnName(action.ColumnName))
		}
	}

	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
}

func renderCreateIndex(c *ast.CreateIndexStatement, opts ast.FormatOptions) string {
	return renderCreateIndexStmt(c, opts)
}

func renderCreateView(c *ast.CreateViewStatement, opts ast.FormatOptions) string {
	return renderCreateViewStmt(c, opts)
}

func renderCreateMaterializedView(c *ast.CreateMaterializedViewStatement, opts ast.FormatOptions) string {
	return renderCreateMaterializedViewStmt(c, opts)
}

func renderRefreshMaterializedView(r *ast.RefreshMaterializedViewStatement, opts ast.FormatOptions) string {
	if r == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("REFRESH MATERIALIZED VIEW"))
	sb.WriteString(" ")
	if r.Concurrently {
		sb.WriteString(f.kw("CONCURRENTLY"))
		sb.WriteString(" ")
	}
	sb.WriteString(ast.QuoteQualifiedName(r.Name))

	if r.WithData != nil {
		sb.WriteString(f.clauseSep())
		if *r.WithData {
			sb.WriteString(f.kw("WITH DATA"))
		} else {
			sb.WriteString(f.kw("WITH NO DATA"))
		}
	}

	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
}

func renderDrop(d *ast.DropStatement, opts ast.FormatOptions) string {
	return renderDropStmt(d, opts)
}

func renderTruncate(t *ast.TruncateStatement, opts ast.FormatOptions) string {
	return renderTruncateStmt(t, opts)
}

func renderMerge(m *ast.MergeStatement, opts ast.FormatOptions) string {
	if m == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("MERGE INTO"))
	sb.WriteString(" ")
	sb.WriteString(tableRefSQL(&m.TargetTable, f))
	if m.TargetAlias != "" {
		sb.WriteString(" ")
		sb.WriteString(ast.QuoteTableAliasWith(m.TargetAlias, f.nq(m.TargetAliasQuote)))
	}

	sb.WriteString(f.clauseSep())
	sb.WriteString(f.kw("USING"))
	sb.WriteString(" ")
	sb.WriteString(tableRefSQL(&m.SourceTable, f))
	if m.SourceAlias != "" {
		sb.WriteString(" ")
		sb.WriteString(ast.QuoteTableAliasWith(m.SourceAlias, f.nq(m.SourceAliasQuote)))
		sb.WriteString(ast.TableColumnAliasesSQLWith(&m.SourceTable, f.nq))
	}

	sb.WriteString(f.clauseSep())
	sb.WriteString(f.kw("ON"))
	sb.WriteString(" ")
	sb.WriteString(f.exprSQL(m.OnCondition))

	for _, when := range m.WhenClauses {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("WHEN"))
		sb.WriteString(" ")
		switch when.Type {
		case "MATCHED":
			sb.WriteString(f.kw("MATCHED"))
		case "NOT_MATCHED":
			sb.WriteString(f.kw("NOT MATCHED"))
		case "NOT_MATCHED_BY_SOURCE":
			sb.WriteString(f.kw("NOT MATCHED BY SOURCE"))
		case "NOT_MATCHED_BY_TARGET":
			sb.WriteString(f.kw("NOT MATCHED BY TARGET"))
		default:
			// An unknown kind is left out: "WHEN  THEN" does not parse.
			sb.WriteString(f.kw(ast.MergeWhenText(when.Type)))
		}
		if when.Condition != nil {
			sb.WriteString(" ")
			sb.WriteString(f.kw("AND"))
			sb.WriteString(" ")
			sb.WriteString(f.exprSQL(when.Condition))
		}
		sb.WriteString(" ")
		sb.WriteString(f.kw("THEN"))

		if when.Action != nil {
			sb.WriteString(" ")
			switch when.Action.ActionType {
			case "UPDATE":
				sb.WriteString(f.kw("UPDATE"))
				sb.WriteString(" ")
				sb.WriteString(f.kw("SET"))
				sb.WriteString(" ")
				sets := make([]string, len(when.Action.SetClauses))
				for i, sc := range when.Action.SetClauses {
					sets[i] = ast.QuoteQualifiedNameWith(sc.Column, f.nq(sc.ColumnQuote)) + " = " + f.exprSQL(sc.Value)
				}
				sb.WriteString(strings.Join(sets, ", "))
			case "DELETE":
				sb.WriteString(f.kw("DELETE"))
			case "INSERT":
				sb.WriteString(f.kw("INSERT"))
				if when.Action.DefaultValues {
					sb.WriteString(" ")
					sb.WriteString(f.kw("DEFAULT VALUES"))
				} else {
					if len(when.Action.Columns) > 0 {
						sb.WriteString(" (")
						sb.WriteString(f.quoteColumnNamesWith(when.Action.Columns, when.Action.ColumnQuotes))
						sb.WriteString(")")
					}
					if len(when.Action.Values) > 0 {
						sb.WriteString(" ")
						sb.WriteString(f.kw("VALUES"))
						sb.WriteString(" (")
						vals := make([]string, len(when.Action.Values))
						for i, v := range when.Action.Values {
							vals[i] = f.exprSQL(v)
						}
						sb.WriteString(strings.Join(vals, ", "))
						sb.WriteString(")")
					}
				}
			default:
				sb.WriteString(f.kw(ast.MergeActionText(when.Action.ActionType)))
			}
			writeMergeActionWhere(sb, f, when.Action)
		}
	}
	writeMergeTail(sb, f, m)

	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
}

// ─── expression renderers ─────────────────────────────────────────────────────

func renderCase(c *ast.CaseExpression, opts ast.FormatOptions, context ...*expressionCase) string {
	if c == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("CASE"))
	if c.Value != nil {
		sb.WriteString(" ")
		sb.WriteString(formatExpressionChild(c.Value, opts, context...))
	}
	for _, when := range c.WhenClauses {
		sb.WriteString(" ")
		sb.WriteString(f.kw("WHEN"))
		sb.WriteString(" ")
		sb.WriteString(formatExpressionChild(when.Condition, opts, context...))
		sb.WriteString(" ")
		sb.WriteString(f.kw("THEN"))
		sb.WriteString(" ")
		sb.WriteString(formatExpressionChild(when.Result, opts, context...))
	}
	if c.ElseClause != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("ELSE"))
		sb.WriteString(" ")
		sb.WriteString(formatExpressionChild(c.ElseClause, opts, context...))
	}
	sb.WriteString(" ")
	sb.WriteString(f.kw("END"))

	return f.result()
}

func renderBetween(b *ast.BetweenExpression, opts ast.FormatOptions, context ...*expressionCase) string {
	if b == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(formatExpressionChild(b.Expr, opts, context...))
	sb.WriteString(" ")
	if b.Not {
		sb.WriteString(f.kw("NOT"))
		sb.WriteString(" ")
	}
	sb.WriteString(f.kw("BETWEEN"))
	sb.WriteString(" ")
	sb.WriteString(formatExpressionChild(b.Lower, opts, context...))
	sb.WriteString(" ")
	sb.WriteString(f.kw("AND"))
	sb.WriteString(" ")
	sb.WriteString(formatExpressionChild(b.Upper, opts, context...))

	return f.result()
}

func renderIn(i *ast.InExpression, opts ast.FormatOptions, context ...*expressionCase) string {
	if i == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(formatExpressionChild(i.Expr, opts, context...))
	sb.WriteString(" ")
	if i.Global {
		sb.WriteString(f.kw("GLOBAL"))
		sb.WriteString(" ")
	}
	if i.Not {
		sb.WriteString(f.kw("NOT"))
		sb.WriteString(" ")
	}
	sb.WriteString(f.kw("IN"))
	if i.Bare && i.Subquery == nil {
		// SQLite "a IN tbl": no parentheses around the table reference.
		sb.WriteString(" ")
		if len(context) == 0 {
			sb.WriteString(f.exprListSQL(i.List))
		} else {
			for idx, e := range i.List {
				if idx > 0 {
					sb.WriteString(", ")
				}
				sb.WriteString(formatExpressionChild(e, opts, context...))
			}
		}
		return f.result()
	}
	sb.WriteString(" (")
	if i.Subquery != nil {
		sb.WriteString(formatStatement(i.Subquery, nestedOpts(opts)))
	} else {
		parts := make([]string, len(i.List))
		for idx, e := range i.List {
			parts[idx] = formatExpressionChild(e, opts, context...)
		}
		sb.WriteString(strings.Join(parts, ", "))
	}
	sb.WriteString(")")

	return f.result()
}

func renderExists(e *ast.ExistsExpression, opts ast.FormatOptions) string {
	if e == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("EXISTS"))
	sb.WriteString(" (")
	sb.WriteString(formatStatement(e.Subquery, nestedOpts(opts)))
	sb.WriteString(")")

	return f.result()
}

func renderSubquery(s *ast.SubqueryExpression, opts ast.FormatOptions) string {
	if s == nil {
		return ""
	}
	if opts.KeywordCase == ast.KeywordLower && s.Bare {
		return formatStatement(s.Subquery, nestedOpts(opts))
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString("(")
	sb.WriteString(formatStatement(s.Subquery, nestedOpts(opts)))
	sb.WriteString(")")

	return f.result()
}

// ─── internal helpers ─────────────────────────────────────────────────────────

// nestedOpts returns opts for rendering a statement nested inside another
// one (CTE body, IN/EXISTS/scalar subquery, set-operation operand, or the
// query of INSERT ... SELECT / CREATE [MATERIALIZED] VIEW). Only the
// outermost statement is terminated, so AddSemicolon is cleared (#602).
func nestedOpts(opts ast.FormatOptions) ast.FormatOptions {
	opts.AddSemicolon = false
	return opts
}

// renderWith renders a WITH clause using the given nodeFormatter context.
func renderWith(w *ast.WithClause, f *nodeFormatter) string {
	if w == nil {
		return ""
	}
	sb := &strings.Builder{}
	sb.WriteString(f.kw("WITH"))
	sb.WriteString(" ")
	if w.Recursive {
		sb.WriteString(f.kw("RECURSIVE"))
		sb.WriteString(" ")
	}
	ctes := make([]string, len(w.CTEs))
	for i, cte := range w.CTEs {
		ctes[i] = cteSQL(cte, f)
	}
	sb.WriteString(strings.Join(ctes, ", "))
	return sb.String()
}

// exprSQL returns the SQL() output for an expression, or its token literal.
func exprSQL(e ast.Expression) string {
	if e == nil {
		return ""
	}
	if s, ok := e.(interface{ SQL() string }); ok {
		return s.SQL()
	}
	return e.TokenLiteral()
}

// stmtSQL returns the SQL() output for a statement, or its token literal.
func stmtSQL(s ast.Statement) string {
	if s == nil {
		return ""
	}
	if sq, ok := s.(interface{ SQL() string }); ok {
		return sq.SQL()
	}
	return s.TokenLiteral()
}

// exprListSQL renders a comma-separated list of expressions.
func exprListSQL(exprs []ast.Expression) string {
	parts := make([]string, len(exprs))
	for i, e := range exprs {
		parts[i] = exprSQL(e)
	}
	return strings.Join(parts, ", ")
}

// orderBySQL renders ORDER BY expressions.
func orderBySQL(orders []ast.OrderByExpression) string {
	parts := make([]string, len(orders))
	for i, o := range orders {
		s := exprSQL(o.Expression)
		if op := ast.OrderUsingOperatorText(o.UsingOperator); op != "" {
			s += " USING " + op
		} else if !o.Ascending {
			s += " DESC"
		}
		if o.NullsFirst != nil {
			if *o.NullsFirst {
				s += " NULLS FIRST"
			} else {
				s += " NULLS LAST"
			}
		}
		if w := o.WithFill; w != nil {
			s += " WITH FILL"
			if w.From != nil {
				s += " FROM " + exprSQL(w.From)
			}
			if w.To != nil {
				s += " TO " + exprSQL(w.To)
			}
			if w.Step != nil {
				s += " STEP " + exprSQL(w.Step)
			}
		}
		parts[i] = s
	}
	return strings.Join(parts, ", ")
}

// tableRefSQL renders a TableReference. The formatter is threaded through
// so PIVOT/UNPIVOT/FOR/IN/AS/LATERAL keywords honor the caller's case policy.
func tableRefSQL(t *ast.TableReference, f *nodeFormatter) string {
	var sb strings.Builder
	if g := ast.TableRefJoinGroup(t); g != nil {
		sb.WriteString("(")
		for i := range g.Tables {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(tableRefSQL(&g.Tables[i], f))
		}
		for i := range g.Joins {
			if !g.Joins[i].Comma {
				sb.WriteString(" ")
			}
			sb.WriteString(joinSQL(&g.Joins[i], f))
		}
		sb.WriteString(")")
		return sb.String()
	}
	if t.Lateral {
		sb.WriteString(f.kw("LATERAL"))
		sb.WriteString(" ")
	}
	if t.Subquery != nil {
		sb.WriteString("(")
		sb.WriteString(tableSubqueryForDialect(t.Subquery, f))
		sb.WriteString(")")
	} else if rows := ast.RowsFromSQL(t, f.kw); rows != "" {
		sb.WriteString(rows)
	} else if t.TableFunc != nil {
		sb.WriteString(f.exprSQL(t.TableFunc))
		if t.WithOrdinality {
			sb.WriteString(" ")
			sb.WriteString(f.kw("WITH ORDINALITY"))
		}
	} else if t.SetSubquery != nil {
		sb.WriteString("(")
		sb.WriteString(tableSubqueryForDialect(t.SetSubquery, f))
		sb.WriteString(")")
	} else if t.DialectModifiers().Values != nil {
		sb.WriteString("(")
		sb.WriteString(f.kw("VALUES"))
		sb.WriteString(strings.TrimPrefix(t.DialectModifiers().Values.SQL(), "VALUES"))
		sb.WriteString(")")
	} else {
		if t.Only {
			sb.WriteString(f.kw("ONLY"))
			sb.WriteString(" ")
		}
		sb.WriteString(ast.QuoteQualifiedNameWith(t.Name, f.nq(t.NameQuote)))
		sb.WriteString(ast.TableRefNameSuffixSQL(t))
	}
	sb.WriteString(ast.TableRefPreAliasSQL(t, f.kw))
	if t.Alias != "" && !ast.TableAliasFollowsClause(t) {
		sb.WriteString(" ")
		sb.WriteString(ast.QuoteTableAliasWith(t.Alias, f.nq(t.AliasQuote)))
		sb.WriteString(ast.TableColumnAliasesSQLWith(t, f.nq))
	} else {
		sb.WriteString(ast.TableRefSourceAliasSQLWith(t, f.nq))
	}
	sb.WriteString(ast.TableRefPostAliasSQL(t, f.kw))
	// SQL Server table hints follow the alias and precede PIVOT/UNPIVOT (#604).
	if len(t.TableHints) > 0 {
		sb.WriteString(" ")
		sb.WriteString(f.kw("WITH"))
		sb.WriteString(" (")
		for i, h := range t.TableHints {
			if i > 0 {
				sb.WriteString(", ")
			}
			// Hint keywords honor the keyword case policy; anything else
			// (only possible in a hand-built AST) is double-quoted.
			sb.WriteString(ast.TableHintSQL(h, f.kw))
		}
		sb.WriteString(")")
	}
	sb.WriteString(ast.PivotSQL(t.Pivot, f.kw))
	sb.WriteString(ast.UnpivotSQL(t.Unpivot, f.kw))
	sb.WriteString(ast.MatchRecognizeSQL(t.MatchRecognize, f.kw))
	if t.Alias != "" && ast.TableAliasFollowsClause(t) {
		// PIVOT/UNPIVOT aliases conventionally use AS to avoid ambiguity
		// with the closing paren of the clause.
		sb.WriteString(" ")
		sb.WriteString(f.kw("AS"))
		sb.WriteString(" ")
		sb.WriteString(ast.QuoteTableAliasWith(t.Alias, f.nq(t.AliasQuote)))
		sb.WriteString(ast.TableColumnAliasesSQLWith(t, f.nq))
	}
	return sb.String()
}

// joinSQL renders a JOIN clause.
func joinSQL(j *ast.JoinClause, f *nodeFormatter) string {
	var sb strings.Builder
	if j.Comma {
		sb.WriteString(", ")
		sb.WriteString(tableRefSQL(&j.Right, f))
		return sb.String()
	}
	// An unknown join type is dropped, leaving a plain JOIN.
	sb.WriteString(joinKeywordsSQL(j, f))
	sb.WriteString(" ")
	sb.WriteString(tableRefSQL(&j.Right, f))
	if j.MatchCondition != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("MATCH_CONDITION"))
		sb.WriteString(" (")
		sb.WriteString(f.exprSQL(j.MatchCondition))
		sb.WriteString(")")
	}
	if len(j.Using) > 0 {
		sb.WriteString(" ")
		sb.WriteString(f.kw("USING"))
		sb.WriteString(" (")
		for i, u := range j.Using {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(f.exprSQL(u))
		}
		sb.WriteString(")")
	} else if j.Condition != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("ON"))
		sb.WriteString(" ")
		sb.WriteString(f.exprSQL(j.Condition))
	}
	return sb.String()
}

// windowSpecSQL renders the inside of a WINDOW definition's parentheses. The
// definition name (w.Name) is written by the caller as "name AS (...)"; only
// the base window it refines (w.BaseWindow) is written here.
func windowSpecSQL(w *ast.WindowSpec) string {
	var parts []string
	if w.BaseWindow != "" {
		parts = append(parts, ast.QuoteNameWith(w.BaseWindow, w.BaseWindowQuote))
	}
	if len(w.PartitionBy) > 0 {
		parts = append(parts, "PARTITION BY "+exprListSQL(w.PartitionBy))
	}
	if len(w.OrderBy) > 0 {
		parts = append(parts, "ORDER BY "+orderBySQL(w.OrderBy))
	}
	if w.FrameClause != nil {
		parts = append(parts, windowFrameSQL(w.FrameClause))
	}
	return strings.Join(parts, " ")
}

// windowFrameSQL renders a window frame clause.
func windowFrameSQL(f *ast.WindowFrame) string {
	var s string
	unit := ast.FrameUnitText(f.Type)
	if f.End != nil {
		s = fmt.Sprintf("%s BETWEEN %s AND %s", unit, frameBoundSQL(&f.Start), frameBoundSQL(f.End))
	} else {
		s = fmt.Sprintf("%s %s", unit, frameBoundSQL(&f.Start))
	}
	if ex := ast.FrameExcludeText(f.Exclude); ex != "" {
		s += " EXCLUDE " + ex
	}
	return s
}

// frameBoundSQL renders a window frame bound. A numeric bound keeps its offset
// in Value (e.g. Value=2, Type="PRECEDING"); CURRENT ROW and the UNBOUNDED
// forms carry no Value.
func frameBoundSQL(b *ast.WindowFrameBound) string {
	if b.Value != nil {
		return exprSQL(b.Value) + " " + ast.FrameBoundText(b.Type)
	}
	return ast.FrameBoundText(b.Type)
}

// fetchSQL renders a FETCH clause, respecting keyword casing from the nodeFormatter.
func fetchSQL(fc *ast.FetchClause, f *nodeFormatter) string {
	var sb strings.Builder
	if fc.OffsetValue != nil {
		fmt.Fprintf(&sb, " %s %d %s", f.kw("OFFSET"), *fc.OffsetValue, f.kw("ROWS"))
	}
	fetchType := ast.FetchTypeText(fc.FetchType)
	fmt.Fprintf(&sb, " %s %s", f.kw("FETCH"), f.kw(fetchType))
	if fc.FetchValue != nil {
		fmt.Fprintf(&sb, " %d", *fc.FetchValue)
	} else if fc.FetchExpr != nil {
		sb.WriteString(" ")
		sb.WriteString(exprSQL(fc.FetchExpr))
	}
	if fc.IsPercent {
		sb.WriteString(" ")
		sb.WriteString(f.kw("PERCENT"))
	}
	sb.WriteString(" ")
	sb.WriteString(f.kw(ast.FetchRowsKeyword(fc)))
	if fc.WithTies {
		sb.WriteString(" ")
		sb.WriteString(f.kw("WITH TIES"))
	} else {
		sb.WriteString(" ")
		sb.WriteString(f.kw("ONLY"))
	}
	return sb.String()
}

// forSQL renders a FOR UPDATE/SHARE clause.
func forSQL(lock *ast.ForClause, f *nodeFormatter) string {
	var sb strings.Builder
	if lock.LockInShareMode {
		sb.WriteString(f.kw(" LOCK IN SHARE MODE"))
		if lock.NoWait {
			sb.WriteString(f.kw(" NOWAIT"))
		}
		if lock.Wait != nil {
			sb.WriteString(f.kw(" WAIT "))
			sb.WriteString(f.exprSQL(lock.Wait))
		}
		return sb.String()
	}
	sb.WriteString(f.kw(" FOR "))
	sb.WriteString(f.kw(ast.LockTypeText(lock.LockType)))
	if len(lock.Tables) > 0 {
		sb.WriteString(f.kw(" OF "))
		sb.WriteString(quoteQualifiedNames(lock.Tables))
	}
	if lock.NoWait {
		sb.WriteString(f.kw(" NOWAIT"))
	}
	if lock.SkipLocked {
		sb.WriteString(f.kw(" SKIP LOCKED"))
	}
	if lock.Wait != nil {
		sb.WriteString(f.kw(" WAIT "))
		sb.WriteString(f.exprSQL(lock.Wait))
	}
	return sb.String()
}

// onConflictSQL renders an ON CONFLICT clause.
func onConflictSQL(oc *ast.OnConflict, f *nodeFormatter) string {
	var sb strings.Builder
	sb.WriteString(f.kw(" ON CONFLICT"))
	if len(oc.Target) > 0 {
		sb.WriteString(" (")
		sb.WriteString(ast.ColumnRefListSQL(oc.Target))
		sb.WriteString(")")
	}
	if oc.TargetWhere != nil {
		sb.WriteString(f.kw(" WHERE "))
		sb.WriteString(f.exprSQL(oc.TargetWhere))
	}
	if oc.Constraint != "" {
		sb.WriteString(f.kw(" ON CONSTRAINT "))
		sb.WriteString(ast.QuoteColumnName(oc.Constraint))
	}
	if oc.Action.DoNothing {
		sb.WriteString(f.kw(" DO NOTHING"))
	} else if len(oc.Action.DoUpdate) > 0 {
		sb.WriteString(f.kw(" DO UPDATE SET "))
		upds := make([]string, len(oc.Action.DoUpdate))
		for i, u := range oc.Action.DoUpdate {
			upds[i] = ast.ColumnRefSQL(u.Column) + " = " + f.exprSQL(u.Value)
		}
		sb.WriteString(strings.Join(upds, ", "))
		if oc.Action.Where != nil {
			sb.WriteString(f.kw(" WHERE "))
			sb.WriteString(f.exprSQL(oc.Action.Where))
		}
	}
	return sb.String()
}
