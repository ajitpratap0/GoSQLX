// Package ast provides SQL serialization for AST nodes.
//
// This file implements SQL() string methods on all AST node types,
// enabling AST→SQL roundtrip support (Issue #221).
package ast

import (
	"fmt"
	"strings"
	"sync"
	"unicode"
)

// builderPool reuses strings.Builder instances for SQL serialization,
// following the project's existing pooling patterns (sync.Pool for tokenizer
// buffers, token objects, etc.) to reduce allocations in hot paths.
var builderPool = sync.Pool{
	New: func() interface{} {
		return &strings.Builder{}
	},
}

// getBuilder retrieves a strings.Builder from the pool, ready for use.
// Always pair with putBuilder to return it.
func getBuilder() *strings.Builder {
	sb := builderPool.Get().(*strings.Builder)
	sb.Reset()
	return sb
}

// putBuilder returns a strings.Builder to the pool.
func putBuilder(sb *strings.Builder) {
	if sb == nil {
		return
	}
	// Don't pool very large builders to avoid holding excess memory.
	if sb.Cap() > 64*1024 {
		return
	}
	builderPool.Put(sb)
}

// SQL returns the SQL string representation of the AST.
func (a AST) SQL() string {
	parts := make([]string, 0, len(a.Statements))
	for _, stmt := range a.Statements {
		if s, ok := stmt.(interface{ SQL() string }); ok {
			parts = append(parts, s.SQL())
		}
	}
	return strings.Join(parts, ";\n")
}

// ============================================================
// Expressions
// ============================================================

// SQL returns the SQL representation of the identifier.
// Identifiers are emitted unescaped because they have already been validated
// during parsing — the tokenizer and parser only accept syntactically valid
// identifiers (or quoted identifiers whose quotes are preserved in the AST).
// Re-escaping here would be redundant and could introduce double-quoting bugs.
func (i *Identifier) SQL() string {
	if i == nil {
		return ""
	}
	if i.Table != "" {
		return safeIdentifier(i.Table) + "." + safeIdentifier(i.Name)
	}
	return safeIdentifier(i.Name)
}

// safeIdentifier returns the identifier unchanged if it contains only safe
// characters (letters, digits, underscores, dots, *). Otherwise it double-
// quotes it with proper escaping to prevent SQL identifier injection.
func safeIdentifier(name string) string {
	if name == "" {
		return `""`
	}
	for _, r := range name {
		if r != '_' && r != '*' && r != '.' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
		}
	}
	return name
}

// escapeStringLiteral escapes a string for safe inclusion in a single-quoted
// SQL literal, handling characters that can lead to SQL injection.
func escapeStringLiteral(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\'':
			b.WriteString("''")
		case '\\':
			b.WriteString(`\\`)
		case '\x00':
			// Drop null bytes — invalid in SQL string literals.
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\x1a': // Ctrl-Z (EOF on Windows)
			b.WriteString(`\Z`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (l *LiteralValue) SQL() string {
	if l == nil {
		return ""
	}
	if l.Value == nil || strings.EqualFold(l.Type, "NULL") {
		return "NULL"
	}
	switch strings.ToUpper(l.Type) {
	case "STRING":
		return "'" + escapeStringLiteral(fmt.Sprintf("%v", l.Value)) + "'"
	case "BOOLEAN":
		return strings.ToUpper(fmt.Sprintf("%v", l.Value))
	default:
		return fmt.Sprintf("%v", l.Value)
	}
}

func (i *Ident) SQL() string {
	if i == nil {
		return ""
	}
	return i.Name
}

func (b *BinaryExpression) SQL() string {
	if b == nil {
		return ""
	}
	left := exprSQL(b.Left)
	right := exprSQL(b.Right)
	op := b.Operator
	if b.CustomOp != nil {
		op = b.CustomOp.String()
	}

	upperOp := strings.ToUpper(op)

	// Handle IS NULL / IS NOT NULL (right side is NULL literal)
	if upperOp == "IS NULL" || upperOp == "IS NOT NULL" {
		return fmt.Sprintf("%s %s", left, upperOp)
	}

	// Handle special operators like LIKE, ILIKE, SIMILAR TO
	if b.Not {
		switch upperOp {
		case "LIKE", "ILIKE", "SIMILAR TO":
			return fmt.Sprintf("%s NOT %s %s", left, upperOp, right)
		default:
			return fmt.Sprintf("NOT (%s %s %s)", left, op, right)
		}
	}

	return fmt.Sprintf("%s %s %s", left, op, right)
}

func (u *UnaryExpression) SQL() string {
	if u == nil {
		return ""
	}
	inner := exprSQL(u.Expr)
	switch u.Operator {
	case Not:
		return "NOT " + inner
	case PGPostfixFactorial:
		return inner + "!"
	case Plus:
		return "+" + inner
	case Minus:
		return "-" + inner
	default:
		return u.Operator.String() + inner
	}
}

func (a *AliasedExpression) SQL() string {
	if a == nil {
		return ""
	}
	return exprSQL(a.Expr) + " AS " + a.Alias
}

func (c *CastExpression) SQL() string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf("CAST(%s AS %s)", exprSQL(c.Expr), c.Type)
}

func (c *CaseExpression) SQL() string {
	if c == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)
	sb.WriteString("CASE")
	if c.Value != nil {
		sb.WriteString(" ")
		sb.WriteString(exprSQL(c.Value))
	}
	for _, w := range c.WhenClauses {
		sb.WriteString(" WHEN ")
		sb.WriteString(exprSQL(w.Condition))
		sb.WriteString(" THEN ")
		sb.WriteString(exprSQL(w.Result))
	}
	if c.ElseClause != nil {
		sb.WriteString(" ELSE ")
		sb.WriteString(exprSQL(c.ElseClause))
	}
	sb.WriteString(" END")
	return sb.String()
}

func (w *WhenClause) SQL() string {
	if w == nil {
		return ""
	}
	return fmt.Sprintf("WHEN %s THEN %s", exprSQL(w.Condition), exprSQL(w.Result))
}

func (b *BetweenExpression) SQL() string {
	if b == nil {
		return ""
	}
	not := ""
	if b.Not {
		not = "NOT "
	}
	return fmt.Sprintf("%s %sBETWEEN %s AND %s", exprSQL(b.Expr), not, exprSQL(b.Lower), exprSQL(b.Upper))
}

func (i *InExpression) SQL() string {
	if i == nil {
		return ""
	}
	not := ""
	if i.Not {
		not = "NOT "
	}
	if i.Subquery != nil {
		return fmt.Sprintf("%s %sIN (%s)", exprSQL(i.Expr), not, stmtSQL(i.Subquery))
	}
	vals := make([]string, len(i.List))
	for idx, v := range i.List {
		vals[idx] = exprSQL(v)
	}
	return fmt.Sprintf("%s %sIN (%s)", exprSQL(i.Expr), not, strings.Join(vals, ", "))
}

func (e *ExistsExpression) SQL() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("EXISTS (%s)", stmtSQL(e.Subquery))
}

func (s *SubqueryExpression) SQL() string {
	if s == nil {
		return ""
	}
	return fmt.Sprintf("(%s)", stmtSQL(s.Subquery))
}

func (a *AnyExpression) SQL() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("%s %s ANY (%s)", exprSQL(a.Expr), a.Operator, stmtSQL(a.Subquery))
}

func (a *AllExpression) SQL() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("%s %s ALL (%s)", exprSQL(a.Expr), a.Operator, stmtSQL(a.Subquery))
}

func (f *FunctionCall) SQL() string {
	if f == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)
	sb.WriteString(f.Name)
	sb.WriteString("(")
	if f.Distinct {
		sb.WriteString("DISTINCT ")
	}
	args := make([]string, len(f.Arguments))
	for i, arg := range f.Arguments {
		args[i] = exprSQL(arg)
	}
	sb.WriteString(strings.Join(args, ", "))
	if len(f.OrderBy) > 0 {
		sb.WriteString(" ORDER BY ")
		sb.WriteString(orderBySQL(f.OrderBy))
	}
	sb.WriteString(")")
	if len(f.WithinGroup) > 0 {
		sb.WriteString(" WITHIN GROUP (ORDER BY ")
		sb.WriteString(orderBySQL(f.WithinGroup))
		sb.WriteString(")")
	}
	if f.Filter != nil {
		sb.WriteString(" FILTER (WHERE ")
		sb.WriteString(exprSQL(f.Filter))
		sb.WriteString(")")
	}
	if f.Over != nil {
		sb.WriteString(" OVER (")
		sb.WriteString(windowSpecSQL(f.Over))
		sb.WriteString(")")
	}
	return sb.String()
}

func (e *ExtractExpression) SQL() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("EXTRACT(%s FROM %s)", e.Field, exprSQL(e.Source))
}

func (p *PositionExpression) SQL() string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("POSITION(%s IN %s)", exprSQL(p.Substr), exprSQL(p.Str))
}

func (s *SubstringExpression) SQL() string {
	if s == nil {
		return ""
	}
	if s.Length != nil {
		return fmt.Sprintf("SUBSTRING(%s FROM %s FOR %s)", exprSQL(s.Str), exprSQL(s.Start), exprSQL(s.Length))
	}
	return fmt.Sprintf("SUBSTRING(%s FROM %s)", exprSQL(s.Str), exprSQL(s.Start))
}

func (i *IntervalExpression) SQL() string {
	if i == nil {
		return ""
	}
	return fmt.Sprintf("INTERVAL '%s'", i.Value)
}

func (l *ListExpression) SQL() string {
	if l == nil {
		return ""
	}
	vals := make([]string, len(l.Values))
	for i, v := range l.Values {
		vals[i] = exprSQL(v)
	}
	return strings.Join(vals, ", ")
}

func (t *TupleExpression) SQL() string {
	if t == nil {
		return ""
	}
	vals := make([]string, len(t.Expressions))
	for i, e := range t.Expressions {
		vals[i] = exprSQL(e)
	}
	return "(" + strings.Join(vals, ", ") + ")"
}

func (a *ArrayConstructorExpression) SQL() string {
	if a == nil {
		return ""
	}
	if a.Subquery != nil {
		return fmt.Sprintf("ARRAY(%s)", stmtSQL(a.Subquery))
	}
	vals := make([]string, len(a.Elements))
	for i, e := range a.Elements {
		vals[i] = exprSQL(e)
	}
	return "ARRAY[" + strings.Join(vals, ", ") + "]"
}

func (a *ArraySubscriptExpression) SQL() string {
	if a == nil {
		return ""
	}
	s := exprSQL(a.Array)
	for _, idx := range a.Indices {
		s += "[" + exprSQL(idx) + "]"
	}
	return s
}

func (a *ArraySliceExpression) SQL() string {
	if a == nil {
		return ""
	}
	start := ""
	end := ""
	if a.Start != nil {
		start = exprSQL(a.Start)
	}
	if a.End != nil {
		end = exprSQL(a.End)
	}
	return fmt.Sprintf("%s[%s:%s]", exprSQL(a.Array), start, end)
}

// GROUP BY advanced expressions

func (r *RollupExpression) SQL() string {
	if r == nil {
		return ""
	}
	return "ROLLUP(" + exprListSQL(r.Expressions) + ")"
}

func (c *CubeExpression) SQL() string {
	if c == nil {
		return ""
	}
	return "CUBE(" + exprListSQL(c.Expressions) + ")"
}

func (g *GroupingSetsExpression) SQL() string {
	if g == nil {
		return ""
	}
	sets := make([]string, len(g.Sets))
	for i, set := range g.Sets {
		sets[i] = "(" + exprListSQL(set) + ")"
	}
	return "GROUPING SETS(" + strings.Join(sets, ", ") + ")"
}

// ============================================================
// Statements
// ============================================================

func (s *SelectStatement) SQL() string {
	if s == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)

	if s.With != nil {
		sb.WriteString(s.With.SQL())
		sb.WriteString(" ")
	}

	sb.WriteString("SELECT ")

	if len(s.DistinctOnColumns) > 0 {
		sb.WriteString("DISTINCT ON (")
		sb.WriteString(exprListSQL(s.DistinctOnColumns))
		sb.WriteString(") ")
	} else if s.Distinct {
		sb.WriteString("DISTINCT ")
	}

	sb.WriteString(exprListSQL(s.Columns))

	if len(s.From) > 0 {
		sb.WriteString(" FROM ")
		froms := make([]string, len(s.From))
		for i := range s.From {
			froms[i] = tableRefSQL(&s.From[i])
		}
		sb.WriteString(strings.Join(froms, ", "))
	}

	for _, j := range s.Joins {
		j := j // G601: Create local copy to avoid memory aliasing
		sb.WriteString(" ")
		sb.WriteString(joinSQL(&j))
	}

	if s.Where != nil {
		sb.WriteString(" WHERE ")
		sb.WriteString(exprSQL(s.Where))
	}

	if len(s.GroupBy) > 0 {
		sb.WriteString(" GROUP BY ")
		sb.WriteString(exprListSQL(s.GroupBy))
	}

	if s.Having != nil {
		sb.WriteString(" HAVING ")
		sb.WriteString(exprSQL(s.Having))
	}

	if len(s.Windows) > 0 {
		sb.WriteString(" WINDOW ")
		wins := make([]string, len(s.Windows))
		for i := range s.Windows {
			wins[i] = s.Windows[i].Name + " AS (" + windowSpecSQL(&s.Windows[i]) + ")"
		}
		sb.WriteString(strings.Join(wins, ", "))
	}

	if len(s.OrderBy) > 0 {
		sb.WriteString(" ORDER BY ")
		sb.WriteString(orderBySQL(s.OrderBy))
	}

	if s.Limit != nil {
		fmt.Fprintf(sb, " LIMIT %d", *s.Limit)
	}

	if s.Offset != nil {
		fmt.Fprintf(sb, " OFFSET %d", *s.Offset)
	}

	if s.Fetch != nil {
		sb.WriteString(fetchSQL(s.Fetch))
	}

	if s.For != nil {
		sb.WriteString(forSQL(s.For))
	}

	return sb.String()
}

func (i *InsertStatement) SQL() string {
	if i == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)

	if i.With != nil {
		sb.WriteString(i.With.SQL())
		sb.WriteString(" ")
	}

	sb.WriteString("INSERT INTO ")
	sb.WriteString(i.TableName)

	if len(i.Columns) > 0 {
		sb.WriteString(" (")
		sb.WriteString(exprListSQL(i.Columns))
		sb.WriteString(")")
	}

	if i.Query != nil {
		sb.WriteString(" ")
		sb.WriteString(i.Query.SQL())
	} else if len(i.Values) > 0 {
		sb.WriteString(" VALUES ")
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
		sb.WriteString(" RETURNING ")
		sb.WriteString(exprListSQL(i.Returning))
	}

	return sb.String()
}

func (u *UpdateStatement) SQL() string {
	if u == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)

	if u.With != nil {
		sb.WriteString(u.With.SQL())
		sb.WriteString(" ")
	}

	sb.WriteString("UPDATE ")
	sb.WriteString(u.TableName)
	if u.Alias != "" {
		sb.WriteString(" ")
		sb.WriteString(u.Alias)
	}

	sb.WriteString(" SET ")
	updates := u.Assignments
	upds := make([]string, len(updates))
	for i, upd := range updates {
		upds[i] = exprSQL(upd.Column) + " = " + exprSQL(upd.Value)
	}
	sb.WriteString(strings.Join(upds, ", "))

	if len(u.From) > 0 {
		sb.WriteString(" FROM ")
		froms := make([]string, len(u.From))
		for i := range u.From {
			froms[i] = tableRefSQL(&u.From[i])
		}
		sb.WriteString(strings.Join(froms, ", "))
	}

	if u.Where != nil {
		sb.WriteString(" WHERE ")
		sb.WriteString(exprSQL(u.Where))
	}

	if len(u.Returning) > 0 {
		sb.WriteString(" RETURNING ")
		sb.WriteString(exprListSQL(u.Returning))
	}

	return sb.String()
}

func (d *DeleteStatement) SQL() string {
	if d == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)

	if d.With != nil {
		sb.WriteString(d.With.SQL())
		sb.WriteString(" ")
	}

	sb.WriteString("DELETE FROM ")
	sb.WriteString(d.TableName)
	if d.Alias != "" {
		sb.WriteString(" ")
		sb.WriteString(d.Alias)
	}

	if len(d.Using) > 0 {
		sb.WriteString(" USING ")
		usings := make([]string, len(d.Using))
		for i := range d.Using {
			usings[i] = tableRefSQL(&d.Using[i])
		}
		sb.WriteString(strings.Join(usings, ", "))
	}

	if d.Where != nil {
		sb.WriteString(" WHERE ")
		sb.WriteString(exprSQL(d.Where))
	}

	if len(d.Returning) > 0 {
		sb.WriteString(" RETURNING ")
		sb.WriteString(exprListSQL(d.Returning))
	}

	return sb.String()
}

func (c *CreateTableStatement) SQL() string {
	if c == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)
	sb.WriteString("CREATE ")
	if c.Temporary {
		sb.WriteString("TEMPORARY ")
	}
	sb.WriteString("TABLE ")
	if c.IfNotExists {
		sb.WriteString("IF NOT EXISTS ")
	}
	sb.WriteString(c.Name)
	sb.WriteString(" (")

	parts := make([]string, 0, len(c.Columns)+len(c.Constraints))
	for _, col := range c.Columns {
		col := col // G601: Create local copy to avoid memory aliasing
		parts = append(parts, columnDefSQL(&col))
	}
	for _, con := range c.Constraints {
		con := con // G601: Create local copy to avoid memory aliasing
		parts = append(parts, tableConstraintSQL(&con))
	}
	sb.WriteString(strings.Join(parts, ", "))
	sb.WriteString(")")

	if len(c.Inherits) > 0 {
		sb.WriteString(" INHERITS (")
		sb.WriteString(strings.Join(c.Inherits, ", "))
		sb.WriteString(")")
	}

	if c.PartitionBy != nil {
		fmt.Fprintf(sb, " PARTITION BY %s (%s)", c.PartitionBy.Type, strings.Join(c.PartitionBy.Columns, ", "))
	}

	for _, opt := range c.Options {
		fmt.Fprintf(sb, " %s=%s", opt.Name, opt.Value)
	}

	return sb.String()
}

func (c *CreateIndexStatement) SQL() string {
	if c == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)
	sb.WriteString("CREATE ")
	if c.Unique {
		sb.WriteString("UNIQUE ")
	}
	sb.WriteString("INDEX ")
	if c.IfNotExists {
		sb.WriteString("IF NOT EXISTS ")
	}
	sb.WriteString(c.Name)
	sb.WriteString(" ON ")
	sb.WriteString(c.Table)

	if c.Using != "" {
		sb.WriteString(" USING ")
		sb.WriteString(c.Using)
	}

	sb.WriteString(" (")
	cols := make([]string, len(c.Columns))
	for i, col := range c.Columns {
		s := col.Column
		if col.Direction != "" {
			s += " " + col.Direction
		}
		cols[i] = s
	}
	sb.WriteString(strings.Join(cols, ", "))
	sb.WriteString(")")

	if c.Where != nil {
		sb.WriteString(" WHERE ")
		sb.WriteString(exprSQL(c.Where))
	}

	return sb.String()
}

func (a *AlterTableStatement) SQL() string {
	if a == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)
	sb.WriteString("ALTER TABLE ")
	sb.WriteString(a.Table)
	for _, action := range a.Actions {
		action := action // G601: Create local copy to avoid memory aliasing
		sb.WriteString(" ")
		sb.WriteString(alterActionSQL(&action))
	}
	return sb.String()
}

func (d *DropStatement) SQL() string {
	if d == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)
	sb.WriteString("DROP ")
	sb.WriteString(d.ObjectType)
	sb.WriteString(" ")
	if d.IfExists {
		sb.WriteString("IF EXISTS ")
	}
	sb.WriteString(strings.Join(d.Names, ", "))
	if d.CascadeType != "" {
		sb.WriteString(" ")
		sb.WriteString(d.CascadeType)
	}
	return sb.String()
}

func (t *TruncateStatement) SQL() string {
	if t == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)
	sb.WriteString("TRUNCATE TABLE ")
	sb.WriteString(strings.Join(t.Tables, ", "))
	if t.RestartIdentity {
		sb.WriteString(" RESTART IDENTITY")
	} else if t.ContinueIdentity {
		sb.WriteString(" CONTINUE IDENTITY")
	}
	if t.CascadeType != "" {
		sb.WriteString(" ")
		sb.WriteString(t.CascadeType)
	}
	return sb.String()
}

func (w *WithClause) SQL() string {
	if w == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)
	sb.WriteString("WITH ")
	if w.Recursive {
		sb.WriteString("RECURSIVE ")
	}
	ctes := make([]string, len(w.CTEs))
	for i, cte := range w.CTEs {
		ctes[i] = cteSQL(cte)
	}
	sb.WriteString(strings.Join(ctes, ", "))
	return sb.String()
}

func (s *SetOperation) SQL() string {
	if s == nil {
		return ""
	}
	left := stmtSQL(s.Left)
	right := stmtSQL(s.Right)
	op := s.Operator
	if s.All {
		op += " ALL"
	}
	return fmt.Sprintf("%s %s %s", left, op, right)
}

func (v *Values) SQL() string {
	if v == nil {
		return ""
	}
	rows := make([]string, len(v.Rows))
	for i, row := range v.Rows {
		vals := make([]string, len(row))
		for j, val := range row {
			vals[j] = exprSQL(val)
		}
		rows[i] = "(" + strings.Join(vals, ", ") + ")"
	}
	return "VALUES " + strings.Join(rows, ", ")
}

func (c *CreateViewStatement) SQL() string {
	if c == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)
	sb.WriteString("CREATE ")
	if c.OrReplace {
		sb.WriteString("OR REPLACE ")
	}
	if c.Temporary {
		sb.WriteString("TEMPORARY ")
	}
	sb.WriteString("VIEW ")
	if c.IfNotExists {
		sb.WriteString("IF NOT EXISTS ")
	}
	sb.WriteString(c.Name)
	if len(c.Columns) > 0 {
		sb.WriteString(" (")
		sb.WriteString(strings.Join(c.Columns, ", "))
		sb.WriteString(")")
	}
	sb.WriteString(" AS ")
	sb.WriteString(stmtSQL(c.Query))
	if c.WithOption != "" {
		sb.WriteString(" WITH ")
		sb.WriteString(c.WithOption)
	}
	return sb.String()
}

func (c *CreateMaterializedViewStatement) SQL() string {
	if c == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)
	sb.WriteString("CREATE MATERIALIZED VIEW ")
	if c.IfNotExists {
		sb.WriteString("IF NOT EXISTS ")
	}
	sb.WriteString(c.Name)
	if len(c.Columns) > 0 {
		sb.WriteString(" (")
		sb.WriteString(strings.Join(c.Columns, ", "))
		sb.WriteString(")")
	}
	sb.WriteString(" AS ")
	sb.WriteString(stmtSQL(c.Query))
	if c.WithData != nil {
		if *c.WithData {
			sb.WriteString(" WITH DATA")
		} else {
			sb.WriteString(" WITH NO DATA")
		}
	}
	return sb.String()
}

func (r *RefreshMaterializedViewStatement) SQL() string {
	if r == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)
	sb.WriteString("REFRESH MATERIALIZED VIEW ")
	if r.Concurrently {
		sb.WriteString("CONCURRENTLY ")
	}
	sb.WriteString(r.Name)
	if r.WithData != nil {
		if *r.WithData {
			sb.WriteString(" WITH DATA")
		} else {
			sb.WriteString(" WITH NO DATA")
		}
	}
	return sb.String()
}

func (m *MergeStatement) SQL() string {
	if m == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)
	sb.WriteString("MERGE INTO ")
	sb.WriteString(tableRefSQL(&m.TargetTable))
	if m.TargetAlias != "" {
		sb.WriteString(" ")
		sb.WriteString(m.TargetAlias)
	}
	sb.WriteString(" USING ")
	sb.WriteString(tableRefSQL(&m.SourceTable))
	if m.SourceAlias != "" {
		sb.WriteString(" ")
		sb.WriteString(m.SourceAlias)
	}
	sb.WriteString(" ON ")
	sb.WriteString(exprSQL(m.OnCondition))

	for _, when := range m.WhenClauses {
		sb.WriteString(" WHEN ")
		switch when.Type {
		case "MATCHED":
			sb.WriteString("MATCHED")
		case "NOT_MATCHED":
			sb.WriteString("NOT MATCHED")
		case "NOT_MATCHED_BY_SOURCE":
			sb.WriteString("NOT MATCHED BY SOURCE")
		default:
			sb.WriteString(when.Type)
		}
		if when.Condition != nil {
			sb.WriteString(" AND ")
			sb.WriteString(exprSQL(when.Condition))
		}
		sb.WriteString(" THEN ")
		if when.Action != nil {
			sb.WriteString(mergeActionSQL(when.Action))
		}
	}

	return sb.String()
}

// DML types from dml.go

func (s *Select) SQL() string {
	if s == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)
	sb.WriteString("SELECT ")
	if s.Distinct {
		sb.WriteString("DISTINCT ")
	}
	sb.WriteString(exprListSQL(s.Columns))
	if len(s.From) > 0 {
		sb.WriteString(" FROM ")
		froms := make([]string, len(s.From))
		for i := range s.From {
			froms[i] = tableRefSQL(&s.From[i])
		}
		sb.WriteString(strings.Join(froms, ", "))
	}
	if s.Where != nil {
		sb.WriteString(" WHERE ")
		sb.WriteString(exprSQL(s.Where))
	}
	if len(s.GroupBy) > 0 {
		sb.WriteString(" GROUP BY ")
		sb.WriteString(exprListSQL(s.GroupBy))
	}
	if s.Having != nil {
		sb.WriteString(" HAVING ")
		sb.WriteString(exprSQL(s.Having))
	}
	if len(s.OrderBy) > 0 {
		sb.WriteString(" ORDER BY ")
		sb.WriteString(orderBySQL(s.OrderBy))
	}
	if s.Limit != nil {
		fmt.Fprintf(sb, " LIMIT %d", *s.Limit)
	}
	if s.Offset != nil {
		fmt.Fprintf(sb, " OFFSET %d", *s.Offset)
	}
	return sb.String()
}

func (i *Insert) SQL() string {
	if i == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)
	sb.WriteString("INSERT INTO ")
	sb.WriteString(tableRefSQL(&i.Table))
	if len(i.Columns) > 0 {
		sb.WriteString(" (")
		sb.WriteString(exprListSQL(i.Columns))
		sb.WriteString(")")
	}
	if len(i.Values) > 0 {
		sb.WriteString(" VALUES ")
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
	if len(i.ReturningClause) > 0 {
		sb.WriteString(" RETURNING ")
		sb.WriteString(exprListSQL(i.ReturningClause))
	}
	return sb.String()
}

func (u *Update) SQL() string {
	if u == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)
	sb.WriteString("UPDATE ")
	sb.WriteString(tableRefSQL(&u.Table))
	sb.WriteString(" SET ")
	upds := make([]string, len(u.Updates))
	for i, upd := range u.Updates {
		upds[i] = exprSQL(upd.Column) + " = " + exprSQL(upd.Value)
	}
	sb.WriteString(strings.Join(upds, ", "))
	if u.Where != nil {
		sb.WriteString(" WHERE ")
		sb.WriteString(exprSQL(u.Where))
	}
	if len(u.ReturningClause) > 0 {
		sb.WriteString(" RETURNING ")
		sb.WriteString(exprListSQL(u.ReturningClause))
	}
	return sb.String()
}

func (d *Delete) SQL() string {
	if d == nil {
		return ""
	}
	sb := getBuilder()
	defer putBuilder(sb)
	sb.WriteString("DELETE FROM ")
	sb.WriteString(tableRefSQL(&d.Table))
	if d.Where != nil {
		sb.WriteString(" WHERE ")
		sb.WriteString(exprSQL(d.Where))
	}
	if len(d.ReturningClause) > 0 {
		sb.WriteString(" RETURNING ")
		sb.WriteString(exprListSQL(d.ReturningClause))
	}
	return sb.String()
}

// ============================================================
// Helper functions
// ============================================================

// exprSQL dispatches to the SQL() method of any expression
func exprSQL(e Expression) string {
	if e == nil {
		return ""
	}
	if s, ok := e.(interface{ SQL() string }); ok {
		return s.SQL()
	}
	return e.TokenLiteral()
}

// stmtSQL dispatches to the SQL() method of any statement
func stmtSQL(s Statement) string {
	if s == nil {
		return ""
	}
	if sq, ok := s.(interface{ SQL() string }); ok {
		return sq.SQL()
	}
	return s.TokenLiteral()
}

func exprListSQL(exprs []Expression) string {
	parts := make([]string, len(exprs))
	for i, e := range exprs {
		parts[i] = exprSQL(e)
	}
	return strings.Join(parts, ", ")
}

func orderBySQL(orders []OrderByExpression) string {
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

func tableRefSQL(t *TableReference) string {
	sb := getBuilder()
	defer putBuilder(sb)
	if t.Lateral {
		sb.WriteString("LATERAL ")
	}
	if t.Subquery != nil {
		sb.WriteString("(")
		sb.WriteString(t.Subquery.SQL())
		sb.WriteString(")")
	} else {
		sb.WriteString(t.Name)
	}
	if t.Alias != "" {
		sb.WriteString(" ")
		sb.WriteString(t.Alias)
	}
	return sb.String()
}

func joinSQL(j *JoinClause) string {
	sb := getBuilder()
	defer putBuilder(sb)
	sb.WriteString(j.Type)
	sb.WriteString(" JOIN ")
	sb.WriteString(tableRefSQL(&j.Right))
	if j.Condition != nil {
		sb.WriteString(" ON ")
		sb.WriteString(exprSQL(j.Condition))
	}
	return sb.String()
}

func windowSpecSQL(w *WindowSpec) string {
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

func windowFrameSQL(f *WindowFrame) string {
	if f.End != nil {
		return fmt.Sprintf("%s BETWEEN %s AND %s", f.Type, f.Start.Type, f.End.Type)
	}
	return fmt.Sprintf("%s %s", f.Type, f.Start.Type)
}

func fetchSQL(f *FetchClause) string {
	sb := getBuilder()
	defer putBuilder(sb)
	if f.OffsetValue != nil {
		fmt.Fprintf(sb, " OFFSET %d ROWS", *f.OffsetValue)
	}
	fmt.Fprintf(sb, " FETCH %s", f.FetchType)
	if f.FetchValue != nil {
		fmt.Fprintf(sb, " %d", *f.FetchValue)
	}
	if f.IsPercent {
		sb.WriteString(" PERCENT")
	}
	sb.WriteString(" ROWS")
	if f.WithTies {
		sb.WriteString(" WITH TIES")
	} else {
		sb.WriteString(" ONLY")
	}
	return sb.String()
}

func forSQL(f *ForClause) string {
	sb := getBuilder()
	defer putBuilder(sb)
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

func cteSQL(cte *CommonTableExpr) string {
	sb := getBuilder()
	defer putBuilder(sb)
	sb.WriteString(cte.Name)
	if len(cte.Columns) > 0 {
		sb.WriteString(" (")
		sb.WriteString(strings.Join(cte.Columns, ", "))
		sb.WriteString(")")
	}
	sb.WriteString(" AS ")
	if cte.Materialized != nil {
		if *cte.Materialized {
			sb.WriteString("MATERIALIZED ")
		} else {
			sb.WriteString("NOT MATERIALIZED ")
		}
	}
	sb.WriteString("(")
	sb.WriteString(stmtSQL(cte.Statement))
	sb.WriteString(")")
	return sb.String()
}

func onConflictSQL(oc *OnConflict) string {
	sb := getBuilder()
	defer putBuilder(sb)
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

func columnDefSQL(c *ColumnDef) string {
	sb := getBuilder()
	defer putBuilder(sb)
	sb.WriteString(c.Name)
	sb.WriteString(" ")
	sb.WriteString(c.Type)
	for _, con := range c.Constraints {
		con := con // G601: Create local copy to avoid memory aliasing
		sb.WriteString(" ")
		sb.WriteString(columnConstraintSQL(&con))
	}
	return sb.String()
}

func columnConstraintSQL(c *ColumnConstraint) string {
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

func tableConstraintSQL(tc *TableConstraint) string {
	sb := getBuilder()
	defer putBuilder(sb)
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

func referenceSQL(r *ReferenceDefinition) string {
	sb := getBuilder()
	defer putBuilder(sb)
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

func alterActionSQL(a *AlterTableAction) string {
	switch a.Type {
	case "ADD COLUMN":
		s := "ADD COLUMN "
		if a.ColumnDef != nil {
			s += columnDefSQL(a.ColumnDef)
		}
		return s
	case "DROP COLUMN":
		return "DROP COLUMN " + a.ColumnName
	case "ADD CONSTRAINT":
		if a.Constraint != nil {
			return "ADD " + tableConstraintSQL(a.Constraint)
		}
		return "ADD CONSTRAINT"
	default:
		return a.Type
	}
}

func mergeActionSQL(a *MergeAction) string {
	switch a.ActionType {
	case "UPDATE":
		sets := make([]string, len(a.SetClauses))
		for i, s := range a.SetClauses {
			sets[i] = s.Column + " = " + exprSQL(s.Value)
		}
		return "UPDATE SET " + strings.Join(sets, ", ")
	case "INSERT":
		var sb strings.Builder
		sb.WriteString("INSERT")
		if a.DefaultValues {
			sb.WriteString(" DEFAULT VALUES")
		} else {
			if len(a.Columns) > 0 {
				sb.WriteString(" (")
				sb.WriteString(strings.Join(a.Columns, ", "))
				sb.WriteString(")")
			}
			if len(a.Values) > 0 {
				sb.WriteString(" VALUES (")
				vals := make([]string, len(a.Values))
				for i, v := range a.Values {
					vals[i] = exprSQL(v)
				}
				sb.WriteString(strings.Join(vals, ", "))
				sb.WriteString(")")
			}
		}
		return sb.String()
	case "DELETE":
		return "DELETE"
	default:
		return a.ActionType
	}
}
