// Package ast provides SQL formatting for AST nodes.
//
// This file implements Format(FormatOptions) string methods on AST node types,
// enabling configurable SQL output formatting (Issue #244).
package ast

import (
	"fmt"
	"strings"
)

// KeywordCase controls how SQL keywords are emitted.
type KeywordCase int

const (
	// KeywordUpper converts keywords to uppercase (SELECT, FROM, WHERE).
	KeywordUpper KeywordCase = iota
	// KeywordLower converts keywords to lowercase (select, from, where).
	KeywordLower
	// KeywordPreserve keeps keywords in their original case.
	KeywordPreserve
)

// IndentStyle controls the indentation character.
type IndentStyle int

const (
	// IndentSpaces uses spaces for indentation.
	IndentSpaces IndentStyle = iota
	// IndentTabs uses tabs for indentation.
	IndentTabs
)

// FormatOptions configures SQL formatting behavior.
type FormatOptions struct {
	// IndentStyle selects spaces or tabs.
	IndentStyle IndentStyle
	// IndentWidth is the number of spaces (or tabs) per indent level.
	IndentWidth int
	// KeywordCase controls keyword casing.
	KeywordCase KeywordCase
	// LineWidth is the target max line width. 0 means no limit (compact).
	LineWidth int
	// NewlinePerClause puts each major clause (FROM, WHERE, etc.) on its own line.
	NewlinePerClause bool
	// AddSemicolon appends a semicolon to each statement.
	AddSemicolon bool
}

// CompactStyle returns formatting options for minimal whitespace output.
func CompactStyle() FormatOptions {
	return FormatOptions{
		IndentStyle:      IndentSpaces,
		IndentWidth:      0,
		KeywordCase:      KeywordPreserve,
		LineWidth:        0,
		NewlinePerClause: false,
		AddSemicolon:     false,
	}
}

// ReadableStyle returns formatting options for human-readable output.
func ReadableStyle() FormatOptions {
	return FormatOptions{
		IndentStyle:      IndentSpaces,
		IndentWidth:      2,
		KeywordCase:      KeywordUpper,
		LineWidth:        80,
		NewlinePerClause: true,
		AddSemicolon:     true,
	}
}

// formatter holds formatting state during a Format call.
type formatter struct {
	opts  FormatOptions
	sb    *strings.Builder
	depth int
}

func newFormatter(opts FormatOptions) *formatter {
	return &formatter{
		opts: opts,
		sb:   &strings.Builder{},
	}
}

func (f *formatter) kw(keyword string) string {
	switch f.opts.KeywordCase {
	case KeywordUpper:
		return strings.ToUpper(keyword)
	case KeywordLower:
		return strings.ToLower(keyword)
	default:
		return keyword
	}
}

func (f *formatter) indentStr() string {
	if f.opts.IndentWidth == 0 {
		return ""
	}
	ch := " "
	if f.opts.IndentStyle == IndentTabs {
		ch = "\t"
	}
	return strings.Repeat(ch, f.opts.IndentWidth*f.depth)
}

func (f *formatter) clauseSep() string {
	if f.opts.NewlinePerClause {
		return "\n" + f.indentStr()
	}
	return " "
}

func (f *formatter) result() string {
	return f.sb.String()
}

// Format returns the formatted SQL for the full AST.
func (a AST) Format(opts FormatOptions) string {
	parts := make([]string, 0, len(a.Statements))
	for _, stmt := range a.Statements {
		if s, ok := stmt.(interface{ Format(FormatOptions) string }); ok {
			parts = append(parts, s.Format(opts))
		} else if s, ok := stmt.(interface{ SQL() string }); ok {
			parts = append(parts, s.SQL())
		}
	}
	sep := ";\n"
	if opts.AddSemicolon {
		// Each statement already gets semicolons from its own Format
		sep = "\n"
	}
	return strings.Join(parts, sep)
}

// Format returns formatted SQL for a SelectStatement.
func (s *SelectStatement) Format(opts FormatOptions) string {
	if s == nil {
		return ""
	}
	f := newFormatter(opts)
	sb := f.sb

	if s.With != nil {
		sb.WriteString(formatWith(s.With, f))
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

	sb.WriteString(exprListSQL(s.Columns))

	if len(s.From) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("FROM"))
		sb.WriteString(" ")
		froms := make([]string, len(s.From))
		for i := range s.From {
			froms[i] = tableRefSQL(&s.From[i])
		}
		sb.WriteString(strings.Join(froms, ", "))
	}

	for _, j := range s.Joins {
		j := j
		sb.WriteString(f.clauseSep())
		sb.WriteString(joinSQL(&j))
	}

	if s.Where != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("WHERE"))
		sb.WriteString(" ")
		sb.WriteString(exprSQL(s.Where))
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
		sb.WriteString(exprSQL(s.Having))
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
		sb.WriteString(fetchSQL(s.Fetch))
	}

	if s.For != nil {
		sb.WriteString(forSQL(s.For))
	}

	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
}

// Format returns formatted SQL for an InsertStatement.
func (i *InsertStatement) Format(opts FormatOptions) string {
	if i == nil {
		return ""
	}
	f := newFormatter(opts)
	sb := f.sb

	if i.With != nil {
		sb.WriteString(formatWith(i.With, f))
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
		if fq, ok := i.Query.(interface{ Format(FormatOptions) string }); ok {
			sb.WriteString(fq.Format(opts))
		} else {
			sb.WriteString(stmtSQL(i.Query))
		}
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

// Format returns formatted SQL for an UpdateStatement.
func (u *UpdateStatement) Format(opts FormatOptions) string {
	if u == nil {
		return ""
	}
	f := newFormatter(opts)
	sb := f.sb

	if u.With != nil {
		sb.WriteString(formatWith(u.With, f))
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
			froms[i] = tableRefSQL(&u.From[i])
		}
		sb.WriteString(strings.Join(froms, ", "))
	}

	if u.Where != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("WHERE"))
		sb.WriteString(" ")
		sb.WriteString(exprSQL(u.Where))
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

// Format returns formatted SQL for a DeleteStatement.
func (d *DeleteStatement) Format(opts FormatOptions) string {
	if d == nil {
		return ""
	}
	f := newFormatter(opts)
	sb := f.sb

	if d.With != nil {
		sb.WriteString(formatWith(d.With, f))
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
			usings[i] = tableRefSQL(&d.Using[i])
		}
		sb.WriteString(strings.Join(usings, ", "))
	}

	if d.Where != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("WHERE"))
		sb.WriteString(" ")
		sb.WriteString(exprSQL(d.Where))
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

// Format returns formatted SQL for a CreateTableStatement.
func (c *CreateTableStatement) Format(opts FormatOptions) string {
	if c == nil {
		return ""
	}
	f := newFormatter(opts)
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

// Format returns formatted SQL for a SetOperation (UNION, INTERSECT, EXCEPT).
func (s *SetOperation) Format(opts FormatOptions) string {
	if s == nil {
		return ""
	}
	f := newFormatter(opts)
	sb := f.sb

	if s.Left != nil {
		if ls, ok := s.Left.(interface{ Format(FormatOptions) string }); ok {
			sb.WriteString(ls.Format(opts))
		} else {
			sb.WriteString(stmtSQL(s.Left))
		}
	}
	sb.WriteString(f.clauseSep())
	op := s.Operator
	if s.All {
		op += " ALL"
	}
	sb.WriteString(f.kw(op))
	sb.WriteString(f.clauseSep())
	if s.Right != nil {
		if rs, ok := s.Right.(interface{ Format(FormatOptions) string }); ok {
			sb.WriteString(rs.Format(opts))
		} else {
			sb.WriteString(stmtSQL(s.Right))
		}
	}

	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
}

// Format returns formatted SQL for an AlterTableStatement.
func (a *AlterTableStatement) Format(opts FormatOptions) string {
	if a == nil {
		return ""
	}
	f := newFormatter(opts)
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

// Format returns formatted SQL for a CreateIndexStatement.
func (c *CreateIndexStatement) Format(opts FormatOptions) string {
	if c == nil {
		return ""
	}
	f := newFormatter(opts)
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
		sb.WriteString(exprSQL(c.Where))
	}

	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
}

// Format returns formatted SQL for a CreateViewStatement.
func (c *CreateViewStatement) Format(opts FormatOptions) string {
	if c == nil {
		return ""
	}
	f := newFormatter(opts)
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
	if qs, ok := c.Query.(interface{ Format(FormatOptions) string }); ok {
		sb.WriteString(qs.Format(opts))
	} else {
		sb.WriteString(stmtSQL(c.Query))
	}

	if c.WithOption != "" {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw(c.WithOption))
	}

	if opts.AddSemicolon {
		sb.WriteString(";")
	}

	return f.result()
}

// Format returns formatted SQL for a CreateMaterializedViewStatement.
func (c *CreateMaterializedViewStatement) Format(opts FormatOptions) string {
	if c == nil {
		return ""
	}
	f := newFormatter(opts)
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
	if qs, ok := c.Query.(interface{ Format(FormatOptions) string }); ok {
		sb.WriteString(qs.Format(opts))
	} else {
		sb.WriteString(stmtSQL(c.Query))
	}

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

// Format returns formatted SQL for a RefreshMaterializedViewStatement.
func (r *RefreshMaterializedViewStatement) Format(opts FormatOptions) string {
	if r == nil {
		return ""
	}
	f := newFormatter(opts)
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

// Format returns formatted SQL for a DropStatement.
func (d *DropStatement) Format(opts FormatOptions) string {
	if d == nil {
		return ""
	}
	f := newFormatter(opts)
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

// Format returns formatted SQL for a TruncateStatement.
func (t *TruncateStatement) Format(opts FormatOptions) string {
	if t == nil {
		return ""
	}
	f := newFormatter(opts)
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

// formatExpr formats an expression using Format if available, otherwise SQL().
func formatExpr(e Expression, opts FormatOptions) string {
	if e == nil {
		return ""
	}
	if fe, ok := e.(interface{ Format(FormatOptions) string }); ok {
		return fe.Format(opts)
	}
	return exprSQL(e)
}

// formatStmt formats a statement using Format if available, otherwise SQL().
func formatStmt(s Statement, opts FormatOptions) string {
	if s == nil {
		return ""
	}
	if fs, ok := s.(interface{ Format(FormatOptions) string }); ok {
		return fs.Format(opts)
	}
	return stmtSQL(s)
}

// Format returns formatted SQL for a MergeStatement.
func (m *MergeStatement) Format(opts FormatOptions) string {
	if m == nil {
		return ""
	}
	f := newFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("MERGE INTO"))
	sb.WriteString(" ")
	sb.WriteString(tableRefSQL(&m.TargetTable))
	if m.TargetAlias != "" {
		sb.WriteString(" ")
		sb.WriteString(m.TargetAlias)
	}

	sb.WriteString(f.clauseSep())
	sb.WriteString(f.kw("USING"))
	sb.WriteString(" ")
	sb.WriteString(tableRefSQL(&m.SourceTable))
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

// Format returns formatted SQL for a CaseExpression.
func (c *CaseExpression) Format(opts FormatOptions) string {
	if c == nil {
		return ""
	}
	f := newFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("CASE"))
	if c.Value != nil {
		sb.WriteString(" ")
		sb.WriteString(formatExpr(c.Value, opts))
	}
	for _, when := range c.WhenClauses {
		sb.WriteString(" ")
		sb.WriteString(f.kw("WHEN"))
		sb.WriteString(" ")
		sb.WriteString(formatExpr(when.Condition, opts))
		sb.WriteString(" ")
		sb.WriteString(f.kw("THEN"))
		sb.WriteString(" ")
		sb.WriteString(formatExpr(when.Result, opts))
	}
	if c.ElseClause != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("ELSE"))
		sb.WriteString(" ")
		sb.WriteString(formatExpr(c.ElseClause, opts))
	}
	sb.WriteString(" ")
	sb.WriteString(f.kw("END"))

	return f.result()
}

// Format returns formatted SQL for a BetweenExpression.
func (b *BetweenExpression) Format(opts FormatOptions) string {
	if b == nil {
		return ""
	}
	f := newFormatter(opts)
	sb := f.sb

	sb.WriteString(formatExpr(b.Expr, opts))
	sb.WriteString(" ")
	if b.Not {
		sb.WriteString(f.kw("NOT"))
		sb.WriteString(" ")
	}
	sb.WriteString(f.kw("BETWEEN"))
	sb.WriteString(" ")
	sb.WriteString(formatExpr(b.Lower, opts))
	sb.WriteString(" ")
	sb.WriteString(f.kw("AND"))
	sb.WriteString(" ")
	sb.WriteString(formatExpr(b.Upper, opts))

	return f.result()
}

// Format returns formatted SQL for an InExpression.
func (i *InExpression) Format(opts FormatOptions) string {
	if i == nil {
		return ""
	}
	f := newFormatter(opts)
	sb := f.sb

	sb.WriteString(formatExpr(i.Expr, opts))
	sb.WriteString(" ")
	if i.Not {
		sb.WriteString(f.kw("NOT"))
		sb.WriteString(" ")
	}
	sb.WriteString(f.kw("IN"))
	sb.WriteString(" (")
	if i.Subquery != nil {
		sb.WriteString(formatStmt(i.Subquery, opts))
	} else {
		parts := make([]string, len(i.List))
		for idx, e := range i.List {
			parts[idx] = formatExpr(e, opts)
		}
		sb.WriteString(strings.Join(parts, ", "))
	}
	sb.WriteString(")")

	return f.result()
}

// Format returns formatted SQL for an ExistsExpression.
func (e *ExistsExpression) Format(opts FormatOptions) string {
	if e == nil {
		return ""
	}
	f := newFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("EXISTS"))
	sb.WriteString(" (")
	sb.WriteString(formatStmt(e.Subquery, opts))
	sb.WriteString(")")

	return f.result()
}

// Format returns formatted SQL for a SubqueryExpression.
func (s *SubqueryExpression) Format(opts FormatOptions) string {
	if s == nil {
		return ""
	}
	f := newFormatter(opts)
	sb := f.sb

	sb.WriteString("(")
	sb.WriteString(formatStmt(s.Subquery, opts))
	sb.WriteString(")")

	return f.result()
}

// formatWith formats a WITH clause using the given formatter.
func formatWith(w *WithClause, f *formatter) string {
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
		if qs, ok := cte.Statement.(interface{ Format(FormatOptions) string }); ok {
			s += qs.Format(f.opts)
		} else {
			s += stmtSQL(cte.Statement)
		}
		s += ")"
		ctes[i] = s
	}
	sb.WriteString(strings.Join(ctes, ", "))
	return sb.String()
}
