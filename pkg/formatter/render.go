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
	opts  ast.FormatOptions
	sb    *strings.Builder
	depth int
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

// FormatAST renders a full *ast.AST with the given options.
func FormatAST(a *ast.AST, opts ast.FormatOptions) string {
	if a == nil {
		return ""
	}
	parts := make([]string, 0, len(a.Statements))
	for _, stmt := range a.Statements {
		parts = append(parts, FormatStatement(stmt, opts))
	}
	sep := ";\n"
	if opts.AddSemicolon {
		// Each statement already ends with ";"
		sep = "\n"
	}
	result := strings.Join(parts, sep)

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
func FormatStatement(s ast.Statement, opts ast.FormatOptions) string {
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
	default:
		// Fallback to SQL() for unrecognized statement types
		return stmtSQL(s)
	}
}

// FormatExpression renders an AST expression with the given options.
// Returns "" for nil.
func FormatExpression(e ast.Expression, opts ast.FormatOptions) string {
	if e == nil {
		return ""
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

	if s.With != nil {
		sb.WriteString(renderWith(s.With, f))
		sb.WriteString(f.clauseSep())
	}

	sb.WriteString(f.kw("SELECT"))
	sb.WriteString(" ")

	if len(s.DistinctOnColumns) > 0 {
		sb.WriteString(f.kw("DISTINCT ON"))
		sb.WriteString(" (")
		sb.WriteString(exprListSQL(s.DistinctOnColumns))
		sb.WriteString(") ")
	} else if s.Distinct {
		sb.WriteString(f.kw("DISTINCT"))
		sb.WriteString(" ")
	}

	// Render TOP clause (SQL Server). Emitted between SELECT [DISTINCT] and columns.
	if s.Top != nil {
		sb.WriteString(f.kw("TOP"))
		sb.WriteString(" ")
		sb.WriteString(FormatExpression(s.Top.Count, opts))
		if s.Top.IsPercent {
			sb.WriteString(" ")
			sb.WriteString(f.kw("PERCENT"))
		}
		if s.Top.WithTies {
			sb.WriteString(" ")
			sb.WriteString(f.kw("WITH TIES"))
		}
		sb.WriteString(" ")
	}

	sb.WriteString(exprListSQL(s.Columns))

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
		sb.WriteString(f.clauseSep())
		sb.WriteString(joinSQL(&j, f))
	}

	if s.Sample != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(sampleSQL(s.Sample, f))
	}

	if s.Where != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("WHERE"))
		sb.WriteString(" ")
		sb.WriteString(FormatExpression(s.Where, opts))
	}

	if len(s.GroupBy) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("GROUP BY"))
		sb.WriteString(" ")
		sb.WriteString(exprListSQL(s.GroupBy))
	}

	if s.Having != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("HAVING"))
		sb.WriteString(" ")
		sb.WriteString(FormatExpression(s.Having, opts))
	}

	if len(s.Windows) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("WINDOW"))
		sb.WriteString(" ")
		wins := make([]string, len(s.Windows))
		for i := range s.Windows {
			wins[i] = s.Windows[i].Name + " AS (" + windowSpecSQL(&s.Windows[i]) + ")"
		}
		sb.WriteString(strings.Join(wins, ", "))
	}

	if len(s.OrderBy) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("ORDER BY"))
		sb.WriteString(" ")
		sb.WriteString(orderBySQL(s.OrderBy))
	}

	if s.Limit != nil {
		sb.WriteString(f.clauseSep())
		fmt.Fprintf(sb, "%s %d", f.kw("LIMIT"), *s.Limit)
	}

	if s.Offset != nil {
		sb.WriteString(f.clauseSep())
		fmt.Fprintf(sb, "%s %d", f.kw("OFFSET"), *s.Offset)
	}

	if s.Fetch != nil {
		sb.WriteString(fetchSQL(s.Fetch, f))
	}

	if s.For != nil {
		sb.WriteString(forSQL(s.For))
	}

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
	switch dialect {
	case "sqlserver":
		if s.Top == nil && s.Limit != nil {
			if s.Offset != nil || len(s.OrderBy) > 0 {
				// SQL Server 2012+ OFFSET/FETCH syntax (requires ORDER BY in practice,
				// but we emit it faithfully and let the database validate).
				fetchVal := int64(*s.Limit)
				s.Fetch = &ast.FetchClause{
					FetchValue: &fetchVal,
					FetchType:  "NEXT",
				}
				offsetVal := int64(0)
				if s.Offset != nil {
					offsetVal = int64(*s.Offset)
				}
				s.Fetch.OffsetValue = &offsetVal
				s.Limit = nil
				s.Offset = nil
			} else {
				// Simple TOP N
				s.Top = &ast.TopClause{
					Count: &ast.LiteralValue{Value: *s.Limit, Type: "int"},
				}
				s.Limit = nil
			}
		}

	case "oracle":
		if s.Fetch == nil && s.Limit != nil {
			fetchVal := int64(*s.Limit)
			s.Fetch = &ast.FetchClause{
				FetchValue: &fetchVal,
				FetchType:  "FIRST",
			}
			if s.Offset != nil {
				offsetVal := int64(*s.Offset)
				s.Fetch.OffsetValue = &offsetVal
				s.Offset = nil
			}
			s.Limit = nil
		}
	}
}

func renderInsert(i *ast.InsertStatement, opts ast.FormatOptions) string {
	if i == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	if i.With != nil {
		sb.WriteString(renderWith(i.With, f))
		sb.WriteString(f.clauseSep())
	}

	sb.WriteString(f.kw("INSERT INTO"))
	sb.WriteString(" ")
	sb.WriteString(i.TableName)

	if len(i.Columns) > 0 {
		sb.WriteString(" (")
		sb.WriteString(exprListSQL(i.Columns))
		sb.WriteString(")")
	}

	if i.Query != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(FormatStatement(i.Query, opts))
	} else if len(i.Values) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("VALUES"))
		sb.WriteString(" ")
		rows := make([]string, len(i.Values))
		for idx, row := range i.Values {
			vals := make([]string, len(row))
			for j, v := range row {
				vals[j] = exprSQL(v)
			}
			rows[idx] = "(" + strings.Join(vals, ", ") + ")"
		}
		sb.WriteString(strings.Join(rows, ", "))
	}

	if i.OnConflict != nil {
		sb.WriteString(onConflictSQL(i.OnConflict))
	}

	if len(i.Returning) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("RETURNING"))
		sb.WriteString(" ")
		sb.WriteString(exprListSQL(i.Returning))
	}

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

	sb.WriteString(f.kw("UPDATE"))
	sb.WriteString(" ")
	sb.WriteString(u.TableName)
	if u.Alias != "" {
		sb.WriteString(" ")
		sb.WriteString(u.Alias)
	}

	sb.WriteString(f.clauseSep())
	sb.WriteString(f.kw("SET"))
	sb.WriteString(" ")
	upds := make([]string, len(u.Assignments))
	for i, upd := range u.Assignments {
		upds[i] = exprSQL(upd.Column) + " = " + exprSQL(upd.Value)
	}
	sb.WriteString(strings.Join(upds, ", "))

	if len(u.From) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("FROM"))
		sb.WriteString(" ")
		froms := make([]string, len(u.From))
		for i := range u.From {
			froms[i] = tableRefSQL(&u.From[i], f)
		}
		sb.WriteString(strings.Join(froms, ", "))
	}

	if u.Where != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("WHERE"))
		sb.WriteString(" ")
		sb.WriteString(FormatExpression(u.Where, opts))
	}

	if len(u.Returning) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("RETURNING"))
		sb.WriteString(" ")
		sb.WriteString(exprListSQL(u.Returning))
	}

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

	sb.WriteString(f.kw("DELETE FROM"))
	sb.WriteString(" ")
	sb.WriteString(d.TableName)
	if d.Alias != "" {
		sb.WriteString(" ")
		sb.WriteString(d.Alias)
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

	if d.Where != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("WHERE"))
		sb.WriteString(" ")
		sb.WriteString(FormatExpression(d.Where, opts))
	}

	if len(d.Returning) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("RETURNING"))
		sb.WriteString(" ")
		sb.WriteString(exprListSQL(d.Returning))
	}

	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
}

func renderCreateTable(c *ast.CreateTableStatement, opts ast.FormatOptions) string {
	if c == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("CREATE"))
	sb.WriteString(" ")
	if c.Temporary {
		sb.WriteString(f.kw("TEMPORARY"))
		sb.WriteString(" ")
	}
	sb.WriteString(f.kw("TABLE"))
	sb.WriteString(" ")
	if c.IfNotExists {
		sb.WriteString(f.kw("IF NOT EXISTS"))
		sb.WriteString(" ")
	}
	sb.WriteString(c.Name)

	if opts.NewlinePerClause {
		sb.WriteString(" (\n")
		f.depth++
		parts := make([]string, 0, len(c.Columns)+len(c.Constraints))
		for _, col := range c.Columns {
			col := col
			parts = append(parts, f.indentStr()+columnDefSQL(&col))
		}
		for _, con := range c.Constraints {
			con := con
			parts = append(parts, f.indentStr()+tableConstraintSQL(&con))
		}
		sb.WriteString(strings.Join(parts, ",\n"))
		f.depth--
		sb.WriteString("\n")
		sb.WriteString(f.indentStr())
		sb.WriteString(")")
	} else {
		sb.WriteString(" (")
		parts := make([]string, 0, len(c.Columns)+len(c.Constraints))
		for _, col := range c.Columns {
			col := col
			parts = append(parts, columnDefSQL(&col))
		}
		for _, con := range c.Constraints {
			con := con
			parts = append(parts, tableConstraintSQL(&con))
		}
		sb.WriteString(strings.Join(parts, ", "))
		sb.WriteString(")")
	}

	if len(c.Inherits) > 0 {
		sb.WriteString(" ")
		sb.WriteString(f.kw("INHERITS"))
		sb.WriteString(" (")
		sb.WriteString(strings.Join(c.Inherits, ", "))
		sb.WriteString(")")
	}

	if c.PartitionBy != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("PARTITION BY"))
		fmt.Fprintf(sb, " %s (%s)", c.PartitionBy.Type, strings.Join(c.PartitionBy.Columns, ", "))
	}

	for _, opt := range c.Options {
		fmt.Fprintf(sb, " %s=%s", opt.Name, opt.Value)
	}

	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
}

func renderSetOperation(s *ast.SetOperation, opts ast.FormatOptions) string {
	if s == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	if s.Left != nil {
		sb.WriteString(FormatStatement(s.Left, opts))
	}
	sb.WriteString(f.clauseSep())
	op := s.Operator
	if s.All {
		op += " ALL"
	}
	sb.WriteString(f.kw(op))
	sb.WriteString(f.clauseSep())
	if s.Right != nil {
		sb.WriteString(FormatStatement(s.Right, opts))
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
	sb.WriteString(a.Table)

	for i, action := range a.Actions {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw(action.Type))
		if action.ColumnDef != nil {
			sb.WriteString(" ")
			sb.WriteString(columnDefSQL(action.ColumnDef))
		} else if action.Constraint != nil {
			sb.WriteString(" ")
			sb.WriteString(tableConstraintSQL(action.Constraint))
		} else if action.ColumnName != "" {
			sb.WriteString(" ")
			sb.WriteString(action.ColumnName)
		}
	}

	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
}

func renderCreateIndex(c *ast.CreateIndexStatement, opts ast.FormatOptions) string {
	if c == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("CREATE"))
	sb.WriteString(" ")
	if c.Unique {
		sb.WriteString(f.kw("UNIQUE"))
		sb.WriteString(" ")
	}
	sb.WriteString(f.kw("INDEX"))
	sb.WriteString(" ")
	if c.IfNotExists {
		sb.WriteString(f.kw("IF NOT EXISTS"))
		sb.WriteString(" ")
	}
	sb.WriteString(c.Name)
	sb.WriteString(" ")
	sb.WriteString(f.kw("ON"))
	sb.WriteString(" ")
	sb.WriteString(c.Table)

	if c.Using != "" {
		sb.WriteString(" ")
		sb.WriteString(f.kw("USING"))
		sb.WriteString(" ")
		sb.WriteString(c.Using)
	}

	sb.WriteString(" (")
	cols := make([]string, len(c.Columns))
	for i, col := range c.Columns {
		s := col.Column
		if col.Collate != "" {
			s += " " + f.kw("COLLATE") + " " + col.Collate
		}
		if col.Direction != "" {
			s += " " + f.kw(col.Direction)
		}
		if col.NullsLast {
			s += " " + f.kw("NULLS LAST")
		}
		cols[i] = s
	}
	sb.WriteString(strings.Join(cols, ", "))
	sb.WriteString(")")

	if c.Where != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("WHERE"))
		sb.WriteString(" ")
		sb.WriteString(FormatExpression(c.Where, opts))
	}

	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
}

func renderCreateView(c *ast.CreateViewStatement, opts ast.FormatOptions) string {
	if c == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("CREATE"))
	sb.WriteString(" ")
	if c.OrReplace {
		sb.WriteString(f.kw("OR REPLACE"))
		sb.WriteString(" ")
	}
	if c.Temporary {
		sb.WriteString(f.kw("TEMPORARY"))
		sb.WriteString(" ")
	}
	sb.WriteString(f.kw("VIEW"))
	sb.WriteString(" ")
	if c.IfNotExists {
		sb.WriteString(f.kw("IF NOT EXISTS"))
		sb.WriteString(" ")
	}
	sb.WriteString(c.Name)

	if len(c.Columns) > 0 {
		sb.WriteString(" (")
		sb.WriteString(strings.Join(c.Columns, ", "))
		sb.WriteString(")")
	}

	sb.WriteString(" ")
	sb.WriteString(f.kw("AS"))
	sb.WriteString(f.clauseSep())
	sb.WriteString(FormatStatement(c.Query, opts))

	if c.WithOption != "" {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw(c.WithOption))
	}

	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
}

func renderCreateMaterializedView(c *ast.CreateMaterializedViewStatement, opts ast.FormatOptions) string {
	if c == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("CREATE MATERIALIZED VIEW"))
	sb.WriteString(" ")
	if c.IfNotExists {
		sb.WriteString(f.kw("IF NOT EXISTS"))
		sb.WriteString(" ")
	}
	sb.WriteString(c.Name)

	if len(c.Columns) > 0 {
		sb.WriteString(" (")
		sb.WriteString(strings.Join(c.Columns, ", "))
		sb.WriteString(")")
	}

	if c.Tablespace != "" {
		sb.WriteString(" ")
		sb.WriteString(f.kw("TABLESPACE"))
		sb.WriteString(" ")
		sb.WriteString(c.Tablespace)
	}

	sb.WriteString(" ")
	sb.WriteString(f.kw("AS"))
	sb.WriteString(f.clauseSep())
	sb.WriteString(FormatStatement(c.Query, opts))

	if c.WithData != nil {
		sb.WriteString(f.clauseSep())
		if *c.WithData {
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
	sb.WriteString(r.Name)

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
	if d == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("DROP"))
	sb.WriteString(" ")
	sb.WriteString(f.kw(d.ObjectType))
	sb.WriteString(" ")
	if d.IfExists {
		sb.WriteString(f.kw("IF EXISTS"))
		sb.WriteString(" ")
	}
	sb.WriteString(strings.Join(d.Names, ", "))

	if d.CascadeType != "" {
		sb.WriteString(" ")
		sb.WriteString(f.kw(d.CascadeType))
	}

	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
}

func renderTruncate(t *ast.TruncateStatement, opts ast.FormatOptions) string {
	if t == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("TRUNCATE"))
	sb.WriteString(" ")
	sb.WriteString(f.kw("TABLE"))
	sb.WriteString(" ")
	sb.WriteString(strings.Join(t.Tables, ", "))

	if t.RestartIdentity {
		sb.WriteString(" ")
		sb.WriteString(f.kw("RESTART IDENTITY"))
	} else if t.ContinueIdentity {
		sb.WriteString(" ")
		sb.WriteString(f.kw("CONTINUE IDENTITY"))
	}

	if t.CascadeType != "" {
		sb.WriteString(" ")
		sb.WriteString(f.kw(t.CascadeType))
	}

	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
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
		sb.WriteString(m.TargetAlias)
	}

	sb.WriteString(f.clauseSep())
	sb.WriteString(f.kw("USING"))
	sb.WriteString(" ")
	sb.WriteString(tableRefSQL(&m.SourceTable, f))
	if m.SourceAlias != "" {
		sb.WriteString(" ")
		sb.WriteString(m.SourceAlias)
	}

	sb.WriteString(f.clauseSep())
	sb.WriteString(f.kw("ON"))
	sb.WriteString(" ")
	sb.WriteString(exprSQL(m.OnCondition))

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
		default:
			sb.WriteString(f.kw(when.Type))
		}
		if when.Condition != nil {
			sb.WriteString(" ")
			sb.WriteString(f.kw("AND"))
			sb.WriteString(" ")
			sb.WriteString(exprSQL(when.Condition))
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
					sets[i] = sc.Column + " = " + exprSQL(sc.Value)
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
						sb.WriteString(strings.Join(when.Action.Columns, ", "))
						sb.WriteString(")")
					}
					if len(when.Action.Values) > 0 {
						sb.WriteString(" ")
						sb.WriteString(f.kw("VALUES"))
						sb.WriteString(" (")
						vals := make([]string, len(when.Action.Values))
						for i, v := range when.Action.Values {
							vals[i] = exprSQL(v)
						}
						sb.WriteString(strings.Join(vals, ", "))
						sb.WriteString(")")
					}
				}
			}
		}
	}

	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
}

// ─── expression renderers ─────────────────────────────────────────────────────

func renderCase(c *ast.CaseExpression, opts ast.FormatOptions) string {
	if c == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("CASE"))
	if c.Value != nil {
		sb.WriteString(" ")
		sb.WriteString(FormatExpression(c.Value, opts))
	}
	for _, when := range c.WhenClauses {
		sb.WriteString(" ")
		sb.WriteString(f.kw("WHEN"))
		sb.WriteString(" ")
		sb.WriteString(FormatExpression(when.Condition, opts))
		sb.WriteString(" ")
		sb.WriteString(f.kw("THEN"))
		sb.WriteString(" ")
		sb.WriteString(FormatExpression(when.Result, opts))
	}
	if c.ElseClause != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("ELSE"))
		sb.WriteString(" ")
		sb.WriteString(FormatExpression(c.ElseClause, opts))
	}
	sb.WriteString(" ")
	sb.WriteString(f.kw("END"))

	return f.result()
}

func renderBetween(b *ast.BetweenExpression, opts ast.FormatOptions) string {
	if b == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(FormatExpression(b.Expr, opts))
	sb.WriteString(" ")
	if b.Not {
		sb.WriteString(f.kw("NOT"))
		sb.WriteString(" ")
	}
	sb.WriteString(f.kw("BETWEEN"))
	sb.WriteString(" ")
	sb.WriteString(FormatExpression(b.Lower, opts))
	sb.WriteString(" ")
	sb.WriteString(f.kw("AND"))
	sb.WriteString(" ")
	sb.WriteString(FormatExpression(b.Upper, opts))

	return f.result()
}

func renderIn(i *ast.InExpression, opts ast.FormatOptions) string {
	if i == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(FormatExpression(i.Expr, opts))
	sb.WriteString(" ")
	if i.Not {
		sb.WriteString(f.kw("NOT"))
		sb.WriteString(" ")
	}
	sb.WriteString(f.kw("IN"))
	sb.WriteString(" (")
	if i.Subquery != nil {
		sb.WriteString(FormatStatement(i.Subquery, opts))
	} else {
		parts := make([]string, len(i.List))
		for idx, e := range i.List {
			parts[idx] = FormatExpression(e, opts)
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
	sb.WriteString(FormatStatement(e.Subquery, opts))
	sb.WriteString(")")

	return f.result()
}

func renderSubquery(s *ast.SubqueryExpression, opts ast.FormatOptions) string {
	if s == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString("(")
	sb.WriteString(FormatStatement(s.Subquery, opts))
	sb.WriteString(")")

	return f.result()
}

// ─── internal helpers ─────────────────────────────────────────────────────────

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
		s := cte.Name + " "
		if len(cte.Columns) > 0 {
			s += "(" + strings.Join(cte.Columns, ", ") + ") "
		}
		s += f.kw("AS") + " ("
		s += FormatStatement(cte.Statement, f.opts)
		s += ")"
		ctes[i] = s
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
		if !o.Ascending {
			s += " DESC"
		}
		if o.NullsFirst != nil {
			if *o.NullsFirst {
				s += " NULLS FIRST"
			} else {
				s += " NULLS LAST"
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
	if t.Lateral {
		sb.WriteString(f.kw("LATERAL"))
		sb.WriteString(" ")
	}
	if t.Subquery != nil {
		sb.WriteString("(")
		sb.WriteString(stmtSQL(t.Subquery))
		sb.WriteString(")")
	} else {
		sb.WriteString(t.Name)
	}
	if t.Pivot != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("PIVOT"))
		sb.WriteString(" (")
		sb.WriteString(exprSQL(t.Pivot.AggregateFunction))
		sb.WriteString(" ")
		sb.WriteString(f.kw("FOR"))
		sb.WriteString(" ")
		sb.WriteString(t.Pivot.PivotColumn)
		sb.WriteString(" ")
		sb.WriteString(f.kw("IN"))
		sb.WriteString(" (")
		sb.WriteString(strings.Join(t.Pivot.InValues, ", "))
		sb.WriteString("))")
	}
	if t.Unpivot != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("UNPIVOT"))
		sb.WriteString(" (")
		sb.WriteString(t.Unpivot.ValueColumn)
		sb.WriteString(" ")
		sb.WriteString(f.kw("FOR"))
		sb.WriteString(" ")
		sb.WriteString(t.Unpivot.NameColumn)
		sb.WriteString(" ")
		sb.WriteString(f.kw("IN"))
		sb.WriteString(" (")
		sb.WriteString(strings.Join(t.Unpivot.InColumns, ", "))
		sb.WriteString("))")
	}
	if t.Alias != "" {
		// PIVOT/UNPIVOT aliases conventionally use AS to avoid ambiguity
		// with the closing paren of the clause.
		if t.Pivot != nil || t.Unpivot != nil {
			sb.WriteString(" ")
			sb.WriteString(f.kw("AS"))
			sb.WriteString(" ")
		} else {
			sb.WriteString(" ")
		}
		sb.WriteString(t.Alias)
	}
	return sb.String()
}

// sampleSQL renders a ClickHouse SAMPLE clause.
func sampleSQL(s *ast.SampleClause, f *nodeFormatter) string {
	var sb strings.Builder
	sb.WriteString(f.kw("SAMPLE"))
	sb.WriteString(" ")
	sb.WriteString(s.Value)
	if s.Denominator != "" {
		sb.WriteString("/")
		sb.WriteString(s.Denominator)
	}
	if s.Offset != "" {
		sb.WriteString(" ")
		sb.WriteString(f.kw("OFFSET"))
		sb.WriteString(" ")
		sb.WriteString(s.Offset)
		if s.OffsetDenominator != "" {
			sb.WriteString("/")
			sb.WriteString(s.OffsetDenominator)
		}
	}
	return sb.String()
}

// joinSQL renders a JOIN clause.
func joinSQL(j *ast.JoinClause, f *nodeFormatter) string {
	var sb strings.Builder
	sb.WriteString(f.kw(j.Type))
	sb.WriteString(" ")
	sb.WriteString(f.kw("JOIN"))
	sb.WriteString(" ")
	sb.WriteString(tableRefSQL(&j.Right, f))
	if j.Condition != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("ON"))
		sb.WriteString(" ")
		sb.WriteString(exprSQL(j.Condition))
	}
	return sb.String()
}

// windowSpecSQL renders a window specification.
func windowSpecSQL(w *ast.WindowSpec) string {
	var parts []string
	if w.Name != "" {
		parts = append(parts, w.Name)
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
	if f.End != nil {
		return fmt.Sprintf("%s BETWEEN %s AND %s", f.Type, f.Start.Type, f.End.Type)
	}
	return fmt.Sprintf("%s %s", f.Type, f.Start.Type)
}

// fetchSQL renders a FETCH clause, respecting keyword casing from the nodeFormatter.
func fetchSQL(fc *ast.FetchClause, f *nodeFormatter) string {
	var sb strings.Builder
	if fc.OffsetValue != nil {
		fmt.Fprintf(&sb, " %s %d %s", f.kw("OFFSET"), *fc.OffsetValue, f.kw("ROWS"))
	}
	fetchType := fc.FetchType
	if fetchType == "" {
		fetchType = "FIRST"
	}
	fmt.Fprintf(&sb, " %s %s", f.kw("FETCH"), f.kw(fetchType))
	if fc.FetchValue != nil {
		fmt.Fprintf(&sb, " %d", *fc.FetchValue)
	}
	if fc.IsPercent {
		sb.WriteString(" ")
		sb.WriteString(f.kw("PERCENT"))
	}
	sb.WriteString(" ")
	sb.WriteString(f.kw("ROWS"))
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
func forSQL(f *ast.ForClause) string {
	var sb strings.Builder
	sb.WriteString(" FOR ")
	sb.WriteString(f.LockType)
	if len(f.Tables) > 0 {
		sb.WriteString(" OF ")
		sb.WriteString(strings.Join(f.Tables, ", "))
	}
	if f.NoWait {
		sb.WriteString(" NOWAIT")
	}
	if f.SkipLocked {
		sb.WriteString(" SKIP LOCKED")
	}
	return sb.String()
}

// onConflictSQL renders an ON CONFLICT clause.
func onConflictSQL(oc *ast.OnConflict) string {
	var sb strings.Builder
	sb.WriteString(" ON CONFLICT")
	if len(oc.Target) > 0 {
		sb.WriteString(" (")
		sb.WriteString(exprListSQL(oc.Target))
		sb.WriteString(")")
	}
	if oc.Constraint != "" {
		sb.WriteString(" ON CONSTRAINT ")
		sb.WriteString(oc.Constraint)
	}
	if oc.Action.DoNothing {
		sb.WriteString(" DO NOTHING")
	} else if len(oc.Action.DoUpdate) > 0 {
		sb.WriteString(" DO UPDATE SET ")
		upds := make([]string, len(oc.Action.DoUpdate))
		for i, u := range oc.Action.DoUpdate {
			upds[i] = exprSQL(u.Column) + " = " + exprSQL(u.Value)
		}
		sb.WriteString(strings.Join(upds, ", "))
		if oc.Action.Where != nil {
			sb.WriteString(" WHERE ")
			sb.WriteString(exprSQL(oc.Action.Where))
		}
	}
	return sb.String()
}

// columnDefSQL renders a column definition.
func columnDefSQL(c *ast.ColumnDef) string {
	var sb strings.Builder
	sb.WriteString(c.Name)
	sb.WriteString(" ")
	sb.WriteString(c.Type)
	for _, con := range c.Constraints {
		con := con
		sb.WriteString(" ")
		sb.WriteString(columnConstraintSQL(&con))
	}
	return sb.String()
}

// columnConstraintSQL renders a column constraint.
func columnConstraintSQL(c *ast.ColumnConstraint) string {
	switch c.Type {
	case "NOT NULL", "UNIQUE", "PRIMARY KEY":
		return c.Type
	case "DEFAULT":
		return "DEFAULT " + exprSQL(c.Default)
	case "REFERENCES":
		if c.References != nil {
			return referenceSQL(c.References)
		}
		return "REFERENCES"
	case "CHECK":
		return "CHECK (" + exprSQL(c.Check) + ")"
	default:
		if c.AutoIncrement {
			return "AUTO_INCREMENT"
		}
		return c.Type
	}
}

// tableConstraintSQL renders a table-level constraint.
func tableConstraintSQL(tc *ast.TableConstraint) string {
	var sb strings.Builder
	if tc.Name != "" {
		sb.WriteString("CONSTRAINT ")
		sb.WriteString(tc.Name)
		sb.WriteString(" ")
	}
	switch tc.Type {
	case "PRIMARY KEY":
		sb.WriteString("PRIMARY KEY (")
		sb.WriteString(strings.Join(tc.Columns, ", "))
		sb.WriteString(")")
	case "UNIQUE":
		sb.WriteString("UNIQUE (")
		sb.WriteString(strings.Join(tc.Columns, ", "))
		sb.WriteString(")")
	case "FOREIGN KEY":
		sb.WriteString("FOREIGN KEY (")
		sb.WriteString(strings.Join(tc.Columns, ", "))
		sb.WriteString(") ")
		if tc.References != nil {
			sb.WriteString(referenceSQL(tc.References))
		}
	case "CHECK":
		sb.WriteString("CHECK (")
		sb.WriteString(exprSQL(tc.Check))
		sb.WriteString(")")
	default:
		sb.WriteString(tc.Type)
	}
	return sb.String()
}

// referenceSQL renders a REFERENCES clause.
func referenceSQL(r *ast.ReferenceDefinition) string {
	var sb strings.Builder
	sb.WriteString("REFERENCES ")
	sb.WriteString(r.Table)
	if len(r.Columns) > 0 {
		sb.WriteString(" (")
		sb.WriteString(strings.Join(r.Columns, ", "))
		sb.WriteString(")")
	}
	if r.OnDelete != "" {
		sb.WriteString(" ON DELETE ")
		sb.WriteString(r.OnDelete)
	}
	if r.OnUpdate != "" {
		sb.WriteString(" ON UPDATE ")
		sb.WriteString(r.OnUpdate)
	}
	return sb.String()
}
