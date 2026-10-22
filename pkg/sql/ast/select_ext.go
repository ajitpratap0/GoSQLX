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

// select_ext.go holds the SELECT-body clause nodes added for dialect
// coverage: LIMIT/OFFSET expressions, ClickHouse LIMIT BY and FORMAT, GROUP BY
// modifiers, SELECT ... INTO, SQL Server FOR JSON/XML and OPTION (...) query
// hints, MySQL select modifiers, and their SQL rendering.

package ast

import (
	"bytes"
	"strings"
)

// GroupByModifiers are the GROUP BY modifiers that are not grouping
// expressions themselves.
//
//   - All: GROUP BY ALL (Snowflake, ClickHouse, DuckDB, Databricks); GroupBy
//     is then empty.
//   - WithRollup / WithCube: MySQL, MariaDB, SQL Server and ClickHouse
//     trailing GROUP BY a, b WITH ROLLUP / WITH CUBE. These are kept as
//     written because MySQL and MariaDB reject the ROLLUP(a, b) form.
//   - WithTotals: ClickHouse GROUP BY ... WITH TOTALS.
type GroupByModifiers struct {
	All        bool
	WithRollup bool
	WithCube   bool
	WithTotals bool
}

// IsZero reports whether no modifier is set.
func (m GroupByModifiers) IsZero() bool {
	return !m.All && !m.WithRollup && !m.WithCube && !m.WithTotals
}

// LimitByClause is the ClickHouse "LIMIT n [OFFSET m] BY expr, ..." clause,
// which keeps the first n rows of each group of Exprs. It may be followed by
// an ordinary LIMIT clause.
type LimitByClause struct {
	Count  Expression
	Offset Expression // nil when absent
	Exprs  []Expression
}

func (l *LimitByClause) expressionNode()     {}
func (l LimitByClause) TokenLiteral() string { return "LIMIT" }

// Children returns Count, Offset (when present) and the BY expressions.
func (l LimitByClause) Children() []Node {
	nodes := make([]Node, 0, 2+len(l.Exprs))
	if l.Count != nil {
		nodes = append(nodes, l.Count)
	}
	if l.Offset != nil {
		nodes = append(nodes, l.Offset)
	}
	for _, e := range l.Exprs {
		if e != nil {
			nodes = append(nodes, e)
		}
	}
	return nodes
}

// InterpolateClause is the ClickHouse "INTERPOLATE [(col [AS expr], ...)]"
// clause that follows an ORDER BY ... WITH FILL list.
type InterpolateClause struct {
	Items []InterpolateItem
}

// InterpolateItem is one INTERPOLATE column with its optional expression.
type InterpolateItem struct {
	Column string
	Expr   Expression // nil when written without AS
}

func (c *InterpolateClause) expressionNode()     {}
func (c InterpolateClause) TokenLiteral() string { return "INTERPOLATE" }

// Children returns the item expressions.
func (c InterpolateClause) Children() []Node {
	nodes := make([]Node, 0, len(c.Items))
	for _, it := range c.Items {
		if it.Expr != nil {
			nodes = append(nodes, it.Expr)
		}
	}
	return nodes
}

// SelectInto kinds.
const (
	SelectIntoTable     = "TABLE"     // SELECT ... INTO new_table (SQL Server, PostgreSQL)
	SelectIntoVariables = "VARIABLES" // SELECT ... INTO @a, @b / :v (MySQL, MariaDB, Oracle PL/SQL)
	SelectIntoOutfile   = "OUTFILE"   // MySQL / MariaDB INTO OUTFILE 'file'
	SelectIntoDumpfile  = "DUMPFILE"  // MySQL / MariaDB INTO DUMPFILE 'file'
)

// SelectInto is the INTO clause of a SELECT statement.
//
//	SELECT * INTO #tmp FROM t                       -- Kind TABLE, Table "#tmp"
//	SELECT * INTO TEMP TABLE t2 FROM t              -- PostgreSQL, Temporary "TEMP", TableKeyword
//	SELECT a, b INTO @x, @y FROM t                  -- Kind VARIABLES
//	SELECT * FROM t INTO OUTFILE '/tmp/t.csv'       -- Kind OUTFILE, Trailing
//	    FIELDS TERMINATED BY ',' LINES TERMINATED BY '\n'
type SelectInto struct {
	Kind string
	// Table is the target table name (Kind TABLE), possibly qualified.
	Table string
	// Temporary is the PostgreSQL TEMP / TEMPORARY / UNLOGGED modifier.
	Temporary string
	// TableKeyword records the optional PostgreSQL TABLE keyword.
	TableKeyword bool
	// Targets are the variables of Kind VARIABLES.
	Targets []Expression
	// File is the file name (a string literal) of Kind OUTFILE / DUMPFILE.
	File Expression
	// CharacterSet is the OUTFILE CHARACTER SET name.
	CharacterSet string
	// FieldsOptions / LinesOptions are the OUTFILE export options.
	FieldsOptions []IntoFileOption
	LinesOptions  []IntoFileOption
	// Trailing records that the clause was written after the FROM ...
	// clauses (MySQL), rather than right after the select list.
	Trailing bool
}

// IntoFileOption is one OUTFILE export option such as TERMINATED BY ','.
// Option is one of TERMINATED BY, ENCLOSED BY, OPTIONALLY ENCLOSED BY,
// ESCAPED BY or STARTING BY.
type IntoFileOption struct {
	Option string
	Value  Expression
}

func (s *SelectInto) expressionNode()     {}
func (s SelectInto) TokenLiteral() string { return "INTO" }

// Children returns the variable targets, the file name and the option values.
func (s SelectInto) Children() []Node {
	nodes := make([]Node, 0, len(s.Targets)+1+len(s.FieldsOptions)+len(s.LinesOptions))
	for _, t := range s.Targets {
		if t != nil {
			nodes = append(nodes, t)
		}
	}
	if s.File != nil {
		nodes = append(nodes, s.File)
	}
	for _, o := range s.FieldsOptions {
		if o.Value != nil {
			nodes = append(nodes, o.Value)
		}
	}
	for _, o := range s.LinesOptions {
		if o.Value != nil {
			nodes = append(nodes, o.Value)
		}
	}
	return nodes
}

// ForOutputClause is the SQL Server FOR JSON / FOR XML / FOR BROWSE clause.
//
//	FOR JSON PATH, ROOT('orders'), INCLUDE_NULL_VALUES
//	FOR XML PATH('row'), ROOT('rows'), TYPE
type ForOutputClause struct {
	Kind    string     // JSON, XML or BROWSE
	Mode    string     // PATH, AUTO, RAW or EXPLICIT (empty for BROWSE)
	ModeArg Expression // PATH('row') / RAW('row') element name, or nil
	Options []ForOutputOption
}

// ForOutputOption is one option of a FOR JSON / FOR XML clause such as
// ROOT('x'), TYPE, ELEMENTS XSINIL or WITHOUT_ARRAY_WRAPPER.
type ForOutputOption struct {
	Name string
	Arg  Expression // ROOT('x') argument, or nil
}

func (f *ForOutputClause) expressionNode()     {}
func (f ForOutputClause) TokenLiteral() string { return "FOR" }

// Children returns the mode and option arguments.
func (f ForOutputClause) Children() []Node {
	var nodes []Node
	if f.ModeArg != nil {
		nodes = append(nodes, f.ModeArg)
	}
	for _, o := range f.Options {
		if o.Arg != nil {
			nodes = append(nodes, o.Arg)
		}
	}
	return nodes
}

// QueryHint is one SQL Server OPTION (...) query hint.
//
//	RECOMPILE                     -- Name "RECOMPILE"
//	MAXDOP 1                      -- Name "MAXDOP", Value 1
//	LABEL = 'x'                   -- Name "LABEL", Equals, Value 'x'
//	USE HINT ('A', 'B')           -- Name "USE HINT", Args
//	OPTIMIZE FOR (@p = 1, @q UNKNOWN)
//	OPTIMIZE FOR UNKNOWN          -- Name "OPTIMIZE FOR UNKNOWN"
//
// Name is one or more upper-case words separated by single spaces.
type QueryHint struct {
	Name    string
	Equals  bool
	Value   Expression
	HasArgs bool
	Args    []QueryHintArg
}

// QueryHintArg is one parenthesized argument of a query hint; Unknown marks
// the OPTIMIZE FOR (@p UNKNOWN) form.
type QueryHintArg struct {
	Expr    Expression
	Unknown bool
}

// The keyword sets of the new SELECT clauses. Renderers write a word only
// when it is one of these (any case), so a hand-built AST cannot inject SQL.
var (
	selectModifierKeywords = []string{
		"HIGH_PRIORITY", "STRAIGHT_JOIN", "SQL_SMALL_RESULT", "SQL_BIG_RESULT",
		"SQL_BUFFER_RESULT", "SQL_NO_CACHE", "SQL_CACHE", "SQL_CALC_FOUND_ROWS",
	}
	selectIntoTemporaryKeywords = []string{"TEMP", "TEMPORARY", "UNLOGGED"}
	intoFileOptionKeywords      = []string{
		"TERMINATED BY", "ENCLOSED BY", "OPTIONALLY ENCLOSED BY", "ESCAPED BY", "STARTING BY",
	}
	forOutputKindKeywords   = []string{"JSON", "XML", "BROWSE"}
	forOutputModeKeywords   = []string{"PATH", "AUTO", "RAW", "EXPLICIT"}
	forOutputOptionKeywords = []string{
		"ROOT", "INCLUDE_NULL_VALUES", "WITHOUT_ARRAY_WRAPPER", "TYPE", "ELEMENTS",
		"ELEMENTS XSINIL", "ELEMENTS ABSENT", "BINARY BASE64", "XMLDATA", "XMLSCHEMA",
	}
	joinStrictnessKeywords = []string{"ANY", "ALL", "ASOF", "SEMI", "ANTI"}
	joinHintKeywords       = []string{"HASH", "LOOP", "MERGE", "REMOTE"}
)

// SelectModifierText returns s when it is a MySQL select modifier
// (SQL_CALC_FOUND_ROWS, STRAIGHT_JOIN, ...; any case) and "" otherwise.
func SelectModifierText(s string) string { return keywordOneOf(s, selectModifierKeywords) }

// SelectIntoTemporaryText returns s when it is TEMP, TEMPORARY or UNLOGGED
// (any case) and "" otherwise.
func SelectIntoTemporaryText(s string) string { return keywordOneOf(s, selectIntoTemporaryKeywords) }

// IntoFileOptionText returns s when it is an OUTFILE export option keyword
// (TERMINATED BY, ENCLOSED BY, ...; any case) and "" otherwise.
func IntoFileOptionText(s string) string { return keywordOneOf(s, intoFileOptionKeywords) }

// ForOutputKindText returns s when it is JSON, XML or BROWSE (any case) and
// "" otherwise.
func ForOutputKindText(s string) string { return keywordOneOf(s, forOutputKindKeywords) }

// ForOutputModeText returns s when it is PATH, AUTO, RAW or EXPLICIT (any
// case) and "" otherwise.
func ForOutputModeText(s string) string { return keywordOneOf(s, forOutputModeKeywords) }

// ForOutputOptionText returns s when it is a FOR JSON / FOR XML option name
// (ROOT, TYPE, INCLUDE_NULL_VALUES, ...; any case) and "" otherwise.
func ForOutputOptionText(s string) string { return keywordOneOf(s, forOutputOptionKeywords) }

// JoinStrictnessText returns s when it is a ClickHouse / Snowflake join
// strictness (ANY, ALL, ASOF, SEMI, ANTI; any case) and "" otherwise.
func JoinStrictnessText(s string) string { return keywordOneOf(s, joinStrictnessKeywords) }

// JoinHintText returns s when it is a SQL Server join hint (HASH, LOOP,
// MERGE, REMOTE; any case) and "" otherwise.
func JoinHintText(s string) string { return keywordOneOf(s, joinHintKeywords) }

// QueryHintNameText returns name when it is one or more words of letters,
// digits and underscores separated by single spaces (a query hint name such
// as RECOMPILE or OPTIMIZE FOR UNKNOWN), and "" otherwise.
func QueryHintNameText(name string) string {
	if name == "" {
		return ""
	}
	for _, w := range strings.Split(name, " ") {
		if w == "" || !isBareNameChars(w, false) {
			return ""
		}
	}
	return name
}

// FormatNameText returns name when it is a plain word usable as a ClickHouse
// FORMAT name (JSONEachRow, TabSeparated, Null, ...), and "" otherwise.
func FormatNameText(name string) string {
	if name == "" || !isBareNameChars(name, false) {
		return ""
	}
	return name
}

// HasLimit reports whether the statement has a LIMIT value in any form
// (integer, expression or ALL).
func (s *SelectStatement) HasLimit() bool {
	return s != nil && (s.Limit != nil || s.LimitExpr != nil || s.LimitAll)
}

// HasOffset reports whether the statement has an OFFSET value in any form.
func (s *SelectStatement) HasOffset() bool {
	return s != nil && (s.Offset != nil || s.OffsetExpr != nil)
}

// appendSelectExtChildren appends the expression children of the clauses
// declared in this file to children.
func (s *SelectStatement) appendSelectExtChildren(children []Node) []Node {
	if s.Into != nil {
		children = append(children, s.Into)
	}
	if s.Interpolate != nil {
		children = append(children, s.Interpolate)
	}
	if s.LimitBy != nil {
		children = append(children, s.LimitBy)
	}
	if s.LimitExpr != nil {
		children = append(children, s.LimitExpr)
	}
	if s.OffsetExpr != nil {
		children = append(children, s.OffsetExpr)
	}
	if s.RowsExamined != nil {
		children = append(children, s.RowsExamined)
	}
	if s.ForOutput != nil {
		children = append(children, s.ForOutput)
	}
	for i := range s.QueryHints {
		h := &s.QueryHints[i]
		if h.Value != nil {
			children = append(children, h.Value)
		}
		for _, a := range h.Args {
			if a.Expr != nil {
				children = append(children, a.Expr)
			}
		}
	}
	return children
}

// releaseSelectExt releases and clears the fields declared for the clauses
// in this file; releaseSelectStatement calls it.
func releaseSelectExt(stmt *SelectStatement, mode releaseMode) {
	stmt.SelectModifiers = stmt.SelectModifiers[:0]
	if stmt.Into != nil {
		for _, t := range stmt.Into.Targets {
			releaseExpression(t, mode)
		}
		releaseExpression(stmt.Into.File, mode)
		for _, o := range stmt.Into.FieldsOptions {
			releaseExpression(o.Value, mode)
		}
		for _, o := range stmt.Into.LinesOptions {
			releaseExpression(o.Value, mode)
		}
		stmt.Into = nil
	}
	stmt.GroupByModifiers = GroupByModifiers{}
	stmt.OrderSiblings = false
	if stmt.Interpolate != nil {
		for _, it := range stmt.Interpolate.Items {
			releaseExpression(it.Expr, mode)
		}
		stmt.Interpolate = nil
	}
	releaseExpression(stmt.LimitExpr, mode)
	stmt.LimitExpr = nil
	releaseExpression(stmt.OffsetExpr, mode)
	stmt.OffsetExpr = nil
	releaseExpression(stmt.RowsExamined, mode)
	stmt.RowsExamined = nil
	stmt.LimitAll = false
	stmt.OffsetRows = false
	stmt.LimitWithTies = false
	if stmt.LimitBy != nil {
		releaseExpression(stmt.LimitBy.Count, mode)
		releaseExpression(stmt.LimitBy.Offset, mode)
		for _, e := range stmt.LimitBy.Exprs {
			releaseExpression(e, mode)
		}
		stmt.LimitBy = nil
	}
	if stmt.ForOutput != nil {
		releaseExpression(stmt.ForOutput.ModeArg, mode)
		for _, o := range stmt.ForOutput.Options {
			releaseExpression(o.Arg, mode)
		}
		stmt.ForOutput = nil
	}
	for i := range stmt.QueryHints {
		releaseExpression(stmt.QueryHints[i].Value, mode)
		for _, a := range stmt.QueryHints[i].Args {
			releaseExpression(a.Expr, mode)
		}
		stmt.QueryHints[i] = QueryHint{}
	}
	stmt.QueryHints = stmt.QueryHints[:0]
	stmt.OutputFormat = ""
}

// ─── rendering ───────────────────────────────────────────────────────────────

// writeSelectModifiers writes the MySQL select modifiers, each followed by a
// space. Unknown words are dropped.
func writeSelectModifiers(buf *bytes.Buffer, mods []string) {
	for _, m := range mods {
		if t := SelectModifierText(m); t != "" {
			buf.WriteString(t)
			buf.WriteByte(' ')
		}
	}
}

// writeTop writes a TOP clause followed by a space. The count keeps its
// parentheses when they were written, and always gets them when it is not a
// plain number (TOP (@n), TOP (SELECT ...)), which T-SQL requires.
func writeTop(buf *bytes.Buffer, t *TopClause) {
	if t == nil || t.Count == nil {
		return
	}
	buf.WriteString("TOP ")
	if TopNeedsParens(t) {
		buf.WriteByte('(')
		writeExpr(buf, t.Count)
		buf.WriteByte(')')
	} else {
		writeExpr(buf, t.Count)
	}
	if t.IsPercent {
		buf.WriteString(" PERCENT")
	}
	if t.WithTies {
		buf.WriteString(" WITH TIES")
	}
	buf.WriteByte(' ')
}

// TopNeedsParens reports whether a TOP count is written in parentheses: when
// it was parenthesized in the source, or when it is anything but a numeric
// literal.
func TopNeedsParens(t *TopClause) bool {
	if t == nil {
		return false
	}
	if t.Parenthesized {
		return true
	}
	lit, ok := t.Count.(*LiteralValue)
	if !ok {
		return true
	}
	switch v := lit.Value.(type) {
	case int, int64, int32, uint64, float64:
		return false
	case string:
		return !IsPlainNumberText(v)
	}
	return true
}

// writeSelectInto writes " INTO ..." (with a leading space).
func writeSelectInto(buf *bytes.Buffer, in *SelectInto) {
	if in == nil {
		return
	}
	buf.WriteString(" INTO ")
	switch in.Kind {
	case SelectIntoVariables:
		writeExprList(buf, in.Targets)
	case SelectIntoOutfile, SelectIntoDumpfile:
		buf.WriteString(in.Kind)
		buf.WriteByte(' ')
		writeExpr(buf, in.File)
		if in.Kind == SelectIntoOutfile {
			if in.CharacterSet != "" {
				buf.WriteString(" CHARACTER SET ")
				writeName(buf, in.CharacterSet)
			}
			writeIntoFileOptions(buf, "FIELDS", in.FieldsOptions)
			writeIntoFileOptions(buf, "LINES", in.LinesOptions)
		}
	default:
		if t := SelectIntoTemporaryText(in.Temporary); t != "" {
			buf.WriteString(t)
			buf.WriteByte(' ')
		}
		if in.TableKeyword {
			buf.WriteString("TABLE ")
		}
		writeQualifiedName(buf, in.Table)
	}
}

func writeIntoFileOptions(buf *bytes.Buffer, clause string, opts []IntoFileOption) {
	wrote := false
	for _, o := range opts {
		kw := IntoFileOptionText(o.Option)
		if kw == "" || o.Value == nil {
			continue
		}
		if !wrote {
			buf.WriteByte(' ')
			buf.WriteString(clause)
			wrote = true
		}
		buf.WriteByte(' ')
		buf.WriteString(kw)
		buf.WriteByte(' ')
		writeExpr(buf, o.Value)
	}
}

// writeGroupBy writes the GROUP BY clause including its modifiers.
func writeGroupBy(buf *bytes.Buffer, s *SelectStatement) {
	m := s.GroupByModifiers
	if len(s.GroupBy) == 0 && !m.All {
		return
	}
	buf.WriteString(" GROUP BY ")
	if m.All {
		buf.WriteString("ALL")
	} else {
		writeExprList(buf, s.GroupBy)
	}
	switch {
	case m.WithRollup:
		buf.WriteString(" WITH ROLLUP")
	case m.WithCube:
		buf.WriteString(" WITH CUBE")
	}
	if m.WithTotals {
		buf.WriteString(" WITH TOTALS")
	}
}

// writeLimitValue writes the LIMIT count: Limit, else LimitExpr, else ALL.
func writeLimitValue(buf *bytes.Buffer, s *SelectStatement) {
	switch {
	case s.Limit != nil:
		writeInt(buf, int64(*s.Limit))
	case s.LimitExpr != nil:
		writeExpr(buf, s.LimitExpr)
	default:
		buf.WriteString("ALL")
	}
}

// writeOffsetValue writes the OFFSET value: Offset, else OffsetExpr.
func writeOffsetValue(buf *bytes.Buffer, s *SelectStatement) {
	if s.Offset != nil {
		writeInt(buf, int64(*s.Offset))
		return
	}
	writeExpr(buf, s.OffsetExpr)
}

// writeLimitOffset writes the LIMIT BY, LIMIT and OFFSET clauses. OFFSET
// keeps ROWS when it was written or when FETCH follows (OFFSET n ROWS FETCH
// ... is required by SQL Server, Oracle and MariaDB).
func writeLimitOffset(buf *bytes.Buffer, s *SelectStatement) {
	if lb := s.LimitBy; lb != nil && lb.Count != nil && len(lb.Exprs) > 0 {
		buf.WriteString(" LIMIT ")
		writeExpr(buf, lb.Count)
		if lb.Offset != nil {
			buf.WriteString(" OFFSET ")
			writeExpr(buf, lb.Offset)
		}
		buf.WriteString(" BY ")
		writeExprList(buf, lb.Exprs)
	}
	if s.HasLimit() {
		buf.WriteString(" LIMIT ")
		writeLimitValue(buf, s)
		if s.LimitWithTies {
			buf.WriteString(" WITH TIES")
		}
	}
	if s.HasOffset() {
		buf.WriteString(" OFFSET ")
		writeOffsetValue(buf, s)
		if s.OffsetRows || s.Fetch != nil {
			buf.WriteByte(' ')
			buf.WriteString(OffsetRowsKeyword(s))
		}
	}
	if s.RowsExamined != nil {
		buf.WriteString(" ROWS EXAMINED ")
		writeExpr(buf, s.RowsExamined)
	}
}

// writeForOutput writes " FOR JSON|XML|BROWSE ...".
func writeForOutput(buf *bytes.Buffer, f *ForOutputClause) {
	if f == nil {
		return
	}
	kind := ForOutputKindText(f.Kind)
	if kind == "" {
		return
	}
	buf.WriteString(" FOR ")
	buf.WriteString(kind)
	if mode := ForOutputModeText(f.Mode); mode != "" {
		buf.WriteByte(' ')
		buf.WriteString(mode)
		if f.ModeArg != nil {
			buf.WriteByte('(')
			writeExpr(buf, f.ModeArg)
			buf.WriteByte(')')
		}
	}
	for _, o := range f.Options {
		name := ForOutputOptionText(o.Name)
		if name == "" {
			continue
		}
		buf.WriteString(", ")
		buf.WriteString(name)
		if o.Arg != nil {
			buf.WriteByte('(')
			writeExpr(buf, o.Arg)
			buf.WriteByte(')')
		}
	}
}

// writeQueryHints writes " OPTION (hint, ...)".
func writeQueryHints(buf *bytes.Buffer, hints []QueryHint) {
	if len(hints) == 0 {
		return
	}
	buf.WriteString(" OPTION (")
	first := true
	for i := range hints {
		h := &hints[i]
		name := QueryHintNameText(h.Name)
		if name == "" {
			continue
		}
		if !first {
			buf.WriteString(", ")
		}
		first = false
		buf.WriteString(name)
		if h.Value != nil {
			if h.Equals {
				buf.WriteString(" = ")
			} else {
				buf.WriteByte(' ')
			}
			writeExpr(buf, h.Value)
		}
		if h.HasArgs {
			buf.WriteString(" (")
			for j, a := range h.Args {
				if j > 0 {
					buf.WriteString(", ")
				}
				writeExpr(buf, a.Expr)
				if a.Unknown {
					buf.WriteString(" UNKNOWN")
				}
			}
			buf.WriteByte(')')
		}
	}
	buf.WriteByte(')')
}

// writeFormat writes " FORMAT name" (ClickHouse).
func writeFormat(buf *bytes.Buffer, name string) {
	if n := FormatNameText(name); n != "" {
		buf.WriteString(" FORMAT ")
		buf.WriteString(n)
	}
}

// writeLockWait writes " WAIT n" for an Oracle / MariaDB lock timeout.
func writeLockWait(buf *bytes.Buffer, f *ForClause) {
	if f.Wait != nil {
		buf.WriteString(" WAIT ")
		writeExpr(buf, f.Wait)
	}
}

// JoinKeywordsText returns the keywords written between the left side and
// the joined table of a (non-comma) join, space-separated: "LEFT JOIN",
// "GLOBAL ANY LEFT JOIN", "ASOF JOIN", "INNER HASH JOIN", "CROSS APPLY",
// "STRAIGHT_JOIN". An unknown join type, strictness or hint is dropped.
func JoinKeywordsText(j *JoinClause) string {
	buf := getBuf()
	defer putBuf(buf)
	writeJoinKeywords(buf, j)
	return buf.String()
}

// writeJoinKeywords writes the JoinKeywordsText of j without allocating.
func writeJoinKeywords(buf *bytes.Buffer, j *JoinClause) {
	t := JoinTypeText(j.Type)
	if strings.EqualFold(t, "CROSS APPLY") {
		buf.WriteString("CROSS APPLY")
		return
	}
	if strings.EqualFold(t, "OUTER APPLY") {
		buf.WriteString("OUTER APPLY")
		return
	}
	if strings.EqualFold(j.Hint, "STRAIGHT_JOIN") {
		buf.WriteString("STRAIGHT_JOIN")
		return
	}
	if j.Global {
		buf.WriteString("GLOBAL ")
	}
	if strictness := JoinStrictnessText(j.Strictness); strictness != "" {
		writeUpperASCII(buf, strictness)
		buf.WriteByte(' ')
		// INNER is the default kind under a strictness, and Snowflake only
		// accepts a bare ASOF JOIN.
		if strings.EqualFold(t, "INNER") {
			t = ""
		}
	}
	if t != "" {
		buf.WriteString(t)
		buf.WriteByte(' ')
	}
	if h := JoinHintText(j.Hint); h != "" {
		writeUpperASCII(buf, h)
		buf.WriteByte(' ')
	}
	buf.WriteString("JOIN")
}

// writeUpperASCII writes s upper-cased (ASCII only) without allocating.
func writeUpperASCII(buf *bytes.Buffer, s string) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		buf.WriteByte(c)
	}
}

// FetchRowsKeyword returns ROW for a FETCH clause without a count or with a
// count of 1 (FETCH FIRST ROW ONLY, FETCH NEXT 1 ROW ONLY) and ROWS
// otherwise; the two keywords mean the same.
func FetchRowsKeyword(f *FetchClause) string {
	if f == nil || (f.FetchValue == nil && f.FetchExpr == nil) || (f.FetchValue != nil && *f.FetchValue == 1) {
		return "ROW"
	}
	return "ROWS"
}

// OffsetRowsKeyword returns ROW for OFFSET 1 and ROWS otherwise; the two
// keywords mean the same.
func OffsetRowsKeyword(s *SelectStatement) string {
	if s != nil && s.Offset != nil && *s.Offset == 1 {
		return "ROW"
	}
	return "ROWS"
}

// OrderUsingOperatorText returns op when it is a PostgreSQL ORDER BY ...
// USING sort operator (<, >, <=, >=) and "" otherwise.
func OrderUsingOperatorText(op string) string {
	switch op {
	case "<", ">", "<=", ">=":
		return op
	}
	return ""
}

// writeInterpolate writes " INTERPOLATE [(col [AS expr], ...)]".
func writeInterpolate(buf *bytes.Buffer, c *InterpolateClause) {
	if c == nil {
		return
	}
	buf.WriteString(" INTERPOLATE")
	if len(c.Items) == 0 {
		return
	}
	buf.WriteString(" (")
	for i, it := range c.Items {
		if i > 0 {
			buf.WriteString(", ")
		}
		writeName(buf, it.Column)
		if it.Expr != nil {
			buf.WriteString(" AS ")
			writeExpr(buf, it.Expr)
		}
	}
	buf.WriteByte(')')
}
