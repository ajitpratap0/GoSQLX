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

// table_factor.go holds the table-factor modifiers of a FROM item that are
// not part of the core TableReference fields (row sampling, Oracle flashback,
// MySQL partition selection and index hints, SQLite INDEXED BY, Oracle
// database links) and the shared rendering of every TableReference modifier,
// used by both TableReference SQL() and pkg/formatter.

package ast

import (
	"bytes"
	"sort"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// TableSampleClause is a row-sampling clause on a table reference:
//
//	PostgreSQL:  t [AS] x TABLESAMPLE BERNOULLI (10) REPEATABLE (42)
//	SQL Server:  t TABLESAMPLE SYSTEM (10 PERCENT) REPEATABLE (1)
//	Snowflake:   t SAMPLE ROW (10 ROWS) SEED (7), t TABLESAMPLE (25)
//	Oracle:      t SAMPLE BLOCK (10, 2) SEED (5) x
type TableSampleClause struct {
	// Keyword is SAMPLE or TABLESAMPLE, as written.
	Keyword string
	// Method is the sampling method (BERNOULLI, SYSTEM, BLOCK, ROW, or a
	// PostgreSQL extension method such as SYSTEM_ROWS); "" when omitted.
	Method string
	// Args are the parenthesized arguments (sample size, Oracle seed group).
	Args []Expression
	// Unit is PERCENT or ROWS when it follows the last argument, else "".
	Unit string
	// SeedKeyword is REPEATABLE or SEED when a seed is given, else "".
	SeedKeyword string
	// Seed is the seed expression of REPEATABLE (n) / SEED (n).
	Seed Expression
	// AfterAlias reports that the clause is written after the table alias
	// (SQL standard, PostgreSQL, SQL Server, Snowflake) rather than before
	// it (Oracle).
	AfterAlias bool
	Pos        models.Location
}

func (s *TableSampleClause) expressionNode()     {}
func (s TableSampleClause) TokenLiteral() string { return s.Keyword }
func (s TableSampleClause) Children() []Node {
	nodes := nodifyExpressions(s.Args)
	if s.Seed != nil {
		nodes = append(nodes, s.Seed)
	}
	return nodes
}

// FlashbackClause is an Oracle flashback query clause on a table reference:
//
//	t AS OF SCN 123
//	t AS OF TIMESTAMP SYSTIMESTAMP - INTERVAL '1' HOUR
//	t VERSIONS BETWEEN SCN MINVALUE AND MAXVALUE
type FlashbackClause struct {
	// Versions is true for VERSIONS BETWEEN, false for AS OF.
	Versions bool
	// Kind is SCN or TIMESTAMP.
	Kind string
	// Point is the AS OF expression.
	Point Expression
	// Start and End are the VERSIONS BETWEEN bounds.
	Start Expression
	End   Expression
	Pos   models.Location
}

func (f *FlashbackClause) expressionNode() {}
func (f FlashbackClause) TokenLiteral() string {
	if f.Versions {
		return "VERSIONS BETWEEN"
	}
	return "AS OF"
}
func (f FlashbackClause) Children() []Node {
	var nodes []Node
	for _, e := range []Expression{f.Point, f.Start, f.End} {
		if e != nil {
			nodes = append(nodes, e)
		}
	}
	return nodes
}

// IndexHint is one MySQL / MariaDB index hint:
//
//	USE INDEX (ix_a, ix_b), FORCE KEY FOR JOIN (PRIMARY), IGNORE INDEX FOR ORDER BY (ix)
type IndexHint struct {
	// Action is USE, FORCE or IGNORE.
	Action string
	// Keyword is INDEX or KEY.
	Keyword string
	// For is JOIN, ORDER BY or GROUP BY, or "" for no FOR clause.
	For string
	// Names are the index names; empty for USE INDEX ().
	Names []string
}

// TableModifiers holds the less common table-factor modifiers. It is a
// pointer on TableReference so the many references without any of them pay
// one word.
type TableModifiers struct {
	// Values is a derived table whose body is a VALUES table constructor:
	// FROM (VALUES (1, 'a'), (2, 'b')) AS v(id, name).
	Values *Values
	// TableSample is a row-sampling clause: TABLESAMPLE / SAMPLE.
	TableSample *TableSampleClause
	// Flashback is the Oracle AS OF / VERSIONS BETWEEN flashback clause.
	Flashback *FlashbackClause
	// DBLink is the Oracle database link of t@dblink.
	DBLink string
	// Partitions is the MySQL / MariaDB / Oracle partition selection
	// PARTITION (p0, p1).
	Partitions []string
	// PartitionFor is the Oracle PARTITION FOR (key value, ...) selection of
	// the partition holding the given partition key values.
	PartitionFor *PartitionForClause
	// IndexHints are the MySQL / MariaDB index hints after the alias.
	IndexHints []IndexHint
	// IndexedBy is the SQLite INDEXED BY index name.
	IndexedBy string
	// NotIndexed is the SQLite NOT INDEXED modifier.
	NotIndexed bool
	// WithSchema is the column schema of SQL Server OPENJSON(...) WITH (...).
	WithSchema []OpenJSONColumn
	// Group is set when the reference is a parenthesized joined table used as
	// a join operand: a JOIN (b JOIN c ON ...) ON ... or t1 LEFT JOIN (t2, t3)
	// ON .... The reference has no name, alias or other modifier then.
	Group *JoinGroup
}

// PartitionForClause holds the partition key values of an Oracle PARTITION
// FOR (value, ...) table selection.
type PartitionForClause struct {
	Values []Expression
}

func (c *PartitionForClause) expressionNode()     {}
func (c PartitionForClause) TokenLiteral() string { return "PARTITION FOR" }

// Children returns the key value expressions.
func (c PartitionForClause) Children() []Node {
	nodes := make([]Node, 0, len(c.Values))
	for _, e := range c.Values {
		if e != nil {
			nodes = append(nodes, e)
		}
	}
	return nodes
}

// JoinGroup is a parenthesized joined table: the tables of a FROM list and the
// joins that follow them, as in "(b JOIN c ON b.id = c.b_id)" or
// "(t2, t3)". It is the operand of a JOIN, where flattening it into the
// enclosing join chain would change which tables an ON condition may see (and,
// for outer joins, the result). Joins at the left-most position of a FROM
// clause are flattened by the parser instead; there the grouping has no effect.
type JoinGroup struct {
	// Tables are the comma-separated table references; at least one.
	Tables []TableReference
	// Joins are the JOIN clauses that follow Tables.
	Joins []JoinClause
}

func (g *JoinGroup) statementNode()      {}
func (g JoinGroup) TokenLiteral() string { return "(" }
func (g *JoinGroup) Children() []Node    { return g.childrenInPlace() }
func (g *JoinGroup) childrenInPlace() []Node {
	nodes := make([]Node, 0, len(g.Tables)+len(g.Joins))
	for i := range g.Tables {
		nodes = append(nodes, &g.Tables[i])
	}
	for i := range g.Joins {
		nodes = append(nodes, &g.Joins[i])
	}
	return nodes
}

// joinGroup returns the parenthesized joined table t stands for, or nil.
func (t *TableReference) joinGroup() *JoinGroup {
	if t.Modifiers == nil {
		return nil
	}
	return t.Modifiers.Group
}

// TableRefJoinGroup returns the parenthesized joined table t stands for, or
// nil when t is an ordinary table reference.
func TableRefJoinGroup(t *TableReference) *JoinGroup { return t.joinGroup() }

// writeJoinGroup writes g in parentheses: its tables separated by ", ", then
// its joins.
func writeJoinGroup(buf *bytes.Buffer, g *JoinGroup) {
	buf.WriteByte('(')
	writeTableRefList(buf, g.Tables)
	for i := range g.Joins {
		if !g.Joins[i].Comma {
			buf.WriteByte(' ')
		}
		writeJoin(buf, &g.Joins[i])
	}
	buf.WriteByte(')')
}

// OpenJSONColumn is one column of a SQL Server OPENJSON WITH schema:
//
//	name type ['$.path'] [AS JSON]
type OpenJSONColumn struct {
	Name   string
	Type   string
	Path   string // the JSON path without quotes; "" when omitted
	AsJSON bool
}

// tableSample returns the sampling clause of t, or nil.
func (t *TableReference) tableSample() *TableSampleClause {
	if t.Modifiers == nil {
		return nil
	}
	return t.Modifiers.TableSample
}

// flashback returns the Oracle flashback clause of t, or nil.
func (t *TableReference) flashback() *FlashbackClause {
	if t.Modifiers == nil {
		return nil
	}
	return t.Modifiers.Flashback
}

// textWriter is the writer interface shared by *bytes.Buffer and
// *strings.Builder.
type textWriter interface {
	WriteString(s string) (int, error)
	WriteByte(c byte) error
}

func identityKeyword(s string) string { return s }

// writeBareOrQuoted writes a plain word ([A-Za-z_][A-Za-z0-9_]*) as is and
// anything else double-quoted, so a hand-built value cannot inject SQL.
func writeBareOrQuoted(w textWriter, s string) {
	if isBareTableHint(s) {
		w.WriteString(s)
		return
	}
	buf := getBuf()
	defer putBuf(buf)
	writeQuotedIdentifier(buf, s)
	w.WriteString(buf.String())
}

// writeTableRefNameSuffix writes what follows a plain table name: the Oracle
// @dblink.
func writeTableRefNameSuffix(w textWriter, t *TableReference) {
	if t.Modifiers == nil || t.Modifiers.DBLink == "" {
		return
	}
	w.WriteByte('@')
	w.WriteString(QuoteQualifiedName(t.Modifiers.DBLink))
}

// writeTableRefPreAlias writes the modifiers that precede the table alias:
// MySQL PARTITION (...), FOR SYSTEM_TIME, Snowflake AT / BEFORE / CHANGES,
// Oracle SAMPLE and flashback clauses. Each is preceded by a space.
func writeTableRefPreAlias(w textWriter, t *TableReference, kw func(string) string) {
	if m := t.Modifiers; m != nil && len(m.WithSchema) > 0 {
		writeOpenJSONSchema(w, m.WithSchema, kw)
	}
	if m := t.Modifiers; m != nil && len(m.Partitions) > 0 {
		w.WriteByte(' ')
		w.WriteString(kw("PARTITION"))
		w.WriteString(" (")
		for i, p := range m.Partitions {
			if i > 0 {
				w.WriteString(", ")
			}
			writeBareOrQuoted(w, p)
		}
		w.WriteByte(')')
	}
	if m := t.Modifiers; m != nil && m.PartitionFor != nil && len(m.PartitionFor.Values) > 0 {
		w.WriteByte(' ')
		w.WriteString(kw("PARTITION FOR"))
		w.WriteString(" (")
		for i, e := range m.PartitionFor.Values {
			if i > 0 {
				w.WriteString(", ")
			}
			w.WriteString(exprSQL(e))
		}
		w.WriteByte(')')
	}
	if t.ForSystemTime != nil {
		w.WriteByte(' ')
		writeForSystemTime(w, t.ForSystemTime, kw)
	}
	if t.TimeTravel != nil {
		writeTimeTravel(w, t.TimeTravel, kw)
	}
	if s := t.tableSample(); s != nil && !s.AfterAlias {
		writeTableSample(w, s, kw)
	}
	if f := t.flashback(); f != nil {
		writeFlashback(w, f, kw)
	}
}

// writeTableRefPostAlias writes the modifiers that follow the table alias:
// TABLESAMPLE, ClickHouse FINAL, MySQL index hints and SQLite INDEXED BY.
// Each is preceded by a space.
func writeTableRefPostAlias(w textWriter, t *TableReference, kw func(string) string) {
	if s := t.tableSample(); s != nil && s.AfterAlias {
		writeTableSample(w, s, kw)
	}
	if t.Final {
		w.WriteByte(' ')
		w.WriteString(kw("FINAL"))
	}
	m := t.Modifiers
	if m == nil {
		return
	}
	for _, h := range m.IndexHints {
		writeIndexHint(w, h, kw)
	}
	if m.IndexedBy != "" {
		w.WriteByte(' ')
		w.WriteString(kw("INDEXED BY"))
		w.WriteByte(' ')
		writeBareOrQuoted(w, m.IndexedBy)
	} else if m.NotIndexed {
		w.WriteByte(' ')
		w.WriteString(kw("NOT INDEXED"))
	}
}

// TableRefPreAliasSQL returns the table modifiers written between a table
// name and its alias, each preceded by a space, with keywords passed through
// kw (nil keeps them upper case). It returns "" without allocating when
// there are none.
func TableRefPreAliasSQL(t *TableReference, kw func(string) string) string {
	if t == nil || (t.ForSystemTime == nil && t.TimeTravel == nil && t.flashback() == nil &&
		(t.tableSample() == nil || t.tableSample().AfterAlias) &&
		(t.Modifiers == nil || (len(t.Modifiers.Partitions) == 0 && t.Modifiers.PartitionFor == nil && len(t.Modifiers.WithSchema) == 0))) {
		return ""
	}
	if kw == nil {
		kw = identityKeyword
	}
	var sb strings.Builder
	writeTableRefPreAlias(&sb, t, kw)
	return sb.String()
}

// TableRefPostAliasSQL returns the table modifiers written after a table
// alias (TABLESAMPLE, FINAL, index hints, INDEXED BY), each preceded by a
// space; see TableRefPreAliasSQL.
func TableRefPostAliasSQL(t *TableReference, kw func(string) string) string {
	if t == nil || (!t.Final && (t.tableSample() == nil || !t.tableSample().AfterAlias) &&
		(t.Modifiers == nil || (len(t.Modifiers.IndexHints) == 0 && t.Modifiers.IndexedBy == "" && !t.Modifiers.NotIndexed))) {
		return ""
	}
	if kw == nil {
		kw = identityKeyword
	}
	var sb strings.Builder
	writeTableRefPostAlias(&sb, t, kw)
	return sb.String()
}

// TableRefNameSuffixSQL returns the Oracle "@dblink" suffix of a table name,
// or "".
func TableRefNameSuffixSQL(t *TableReference) string {
	if t == nil || t.Modifiers == nil || t.Modifiers.DBLink == "" {
		return ""
	}
	var sb strings.Builder
	writeTableRefNameSuffix(&sb, t)
	return sb.String()
}

// MatchRecognizeSQL returns " MATCH_RECOGNIZE (...)" for mr, with keywords
// passed through kw (nil keeps them upper case), or "" for nil.
func MatchRecognizeSQL(mr *MatchRecognizeClause, kw func(string) string) string {
	if mr == nil {
		return ""
	}
	if kw == nil {
		kw = identityKeyword
	}
	var sb strings.Builder
	writeMatchRecognize(&sb, mr, kw)
	return sb.String()
}

func writeForSystemTime(w textWriter, c *ForSystemTimeClause, kw func(string) string) {
	w.WriteString(kw("FOR SYSTEM_TIME"))
	w.WriteByte(' ')
	switch c.Type {
	case SystemTimeAsOf:
		w.WriteString(kw("AS OF"))
		w.WriteByte(' ')
		w.WriteString(exprSQL(c.Point))
	case SystemTimeBetween:
		w.WriteString(kw("BETWEEN"))
		w.WriteByte(' ')
		w.WriteString(exprSQL(c.Start))
		w.WriteByte(' ')
		w.WriteString(kw("AND"))
		w.WriteByte(' ')
		w.WriteString(exprSQL(c.End))
	case SystemTimeFromTo:
		w.WriteString(kw("FROM"))
		w.WriteByte(' ')
		w.WriteString(exprSQL(c.Start))
		w.WriteByte(' ')
		w.WriteString(kw("TO"))
		w.WriteByte(' ')
		w.WriteString(exprSQL(c.End))
	case SystemTimeContainedIn:
		w.WriteString(kw("CONTAINED IN"))
		w.WriteString(" (")
		w.WriteString(exprSQL(c.Start))
		w.WriteString(", ")
		w.WriteString(exprSQL(c.End))
		w.WriteByte(')')
	case SystemTimeAll:
		w.WriteString(kw("ALL"))
	}
}

// timeTravelKinds are the Snowflake time-travel clause keywords.
var timeTravelKinds = []string{"AT", "BEFORE", "CHANGES"}

// writeTimeTravel writes " AT (NAME => expr, ...)" and any chained clauses.
// Named arguments are written in name order; their order has no meaning.
func writeTimeTravel(w textWriter, c *TimeTravelClause, kw func(string) string) {
	writeOneTimeTravel(w, c, kw)
	for _, ch := range c.Chained {
		if ch != nil {
			writeOneTimeTravel(w, ch, kw)
		}
	}
}

func writeOneTimeTravel(w textWriter, c *TimeTravelClause, kw func(string) string) {
	kind := keywordOneOf(c.Kind, timeTravelKinds)
	if kind == "" {
		return
	}
	w.WriteByte(' ')
	w.WriteString(kw(strings.ToUpper(kind)))
	w.WriteString(" (")
	names := make([]string, 0, len(c.Named))
	for n := range c.Named {
		if isBareTableHint(n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for i, n := range names {
		if i > 0 {
			w.WriteString(", ")
		}
		w.WriteString(kw(n))
		w.WriteString(" => ")
		w.WriteString(timeTravelValueSQL(c.Named[n]))
	}
	w.WriteByte(')')
}

// timeTravelValueSQL renders a time-travel argument. A bare keyword value
// (CHANGES (INFORMATION => DEFAULT)) is stored as an Identifier and written
// bare when it is a plain word.
func timeTravelValueSQL(e Expression) string {
	if id, ok := e.(*Identifier); ok && id != nil && id.Table == "" && isBareTableHint(id.Name) {
		return id.Name
	}
	return exprSQL(e)
}

var (
	tableSampleKeywords = []string{"SAMPLE", "TABLESAMPLE"}
	tableSampleUnits    = []string{"PERCENT", "ROWS"}
	tableSampleSeeds    = []string{"REPEATABLE", "SEED"}
	flashbackKinds      = []string{"SCN", "TIMESTAMP"}
	indexHintActions    = []string{"USE", "FORCE", "IGNORE"}
	indexHintKeywords   = []string{"INDEX", "KEY"}
	indexHintFors       = []string{"JOIN", "ORDER BY", "GROUP BY"}
)

func writeTableSample(w textWriter, s *TableSampleClause, kw func(string) string) {
	keyword := keywordOneOf(s.Keyword, tableSampleKeywords)
	if keyword == "" {
		keyword = "TABLESAMPLE"
	}
	w.WriteByte(' ')
	w.WriteString(kw(strings.ToUpper(keyword)))
	if s.Method != "" {
		w.WriteByte(' ')
		if isBareTableHint(s.Method) {
			w.WriteString(kw(strings.ToUpper(s.Method)))
		} else {
			writeBareOrQuoted(w, s.Method)
		}
	}
	w.WriteString(" (")
	for i, a := range s.Args {
		if i > 0 {
			w.WriteString(", ")
		}
		w.WriteString(exprSQL(a))
	}
	if u := keywordOneOf(s.Unit, tableSampleUnits); u != "" {
		w.WriteByte(' ')
		w.WriteString(kw(strings.ToUpper(u)))
	}
	w.WriteByte(')')
	if seed := keywordOneOf(s.SeedKeyword, tableSampleSeeds); seed != "" && s.Seed != nil {
		w.WriteByte(' ')
		w.WriteString(kw(strings.ToUpper(seed)))
		w.WriteString(" (")
		w.WriteString(exprSQL(s.Seed))
		w.WriteByte(')')
	}
}

func writeFlashback(w textWriter, f *FlashbackClause, kw func(string) string) {
	kind := keywordOneOf(f.Kind, flashbackKinds)
	if kind == "" {
		return
	}
	kind = kw(strings.ToUpper(kind))
	w.WriteByte(' ')
	if f.Versions {
		w.WriteString(kw("VERSIONS BETWEEN"))
		w.WriteByte(' ')
		w.WriteString(kind)
		w.WriteByte(' ')
		w.WriteString(exprSQL(f.Start))
		w.WriteByte(' ')
		w.WriteString(kw("AND"))
		w.WriteByte(' ')
		w.WriteString(exprSQL(f.End))
		return
	}
	w.WriteString(kw("AS OF"))
	w.WriteByte(' ')
	w.WriteString(kind)
	w.WriteByte(' ')
	w.WriteString(exprSQL(f.Point))
}

func writeIndexHint(w textWriter, h IndexHint, kw func(string) string) {
	action := keywordOneOf(h.Action, indexHintActions)
	if action == "" {
		return
	}
	keyword := keywordOneOf(h.Keyword, indexHintKeywords)
	if keyword == "" {
		keyword = "INDEX"
	}
	w.WriteByte(' ')
	w.WriteString(kw(strings.ToUpper(action)))
	w.WriteByte(' ')
	w.WriteString(kw(strings.ToUpper(keyword)))
	if f := keywordOneOf(h.For, indexHintFors); f != "" {
		w.WriteByte(' ')
		w.WriteString(kw("FOR"))
		w.WriteByte(' ')
		w.WriteString(kw(strings.ToUpper(f)))
	}
	w.WriteString(" (")
	for i, n := range h.Names {
		if i > 0 {
			w.WriteString(", ")
		}
		writeBareOrQuoted(w, n)
	}
	w.WriteByte(')')
}

// isMatchRecognizeRawText reports whether s, a raw PATTERN or AFTER MATCH
// text, holds only characters those clauses use, so writing it back cannot
// end the clause or the statement early.
func isMatchRecognizeRawText(s string, pattern bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == ' ':
		case pattern && strings.IndexByte("+*?|(){},^$-", c) >= 0:
		default:
			return false
		}
	}
	return pattern || balancedParens(s)
}

func balancedParens(s string) bool {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}

// writeMatchRecognize writes " MATCH_RECOGNIZE (...)".
func writeMatchRecognize(w textWriter, mr *MatchRecognizeClause, kw func(string) string) {
	w.WriteByte(' ')
	w.WriteString(kw("MATCH_RECOGNIZE"))
	w.WriteString(" (")
	sep := ""
	next := func() {
		w.WriteString(sep)
		sep = " "
	}
	if len(mr.PartitionBy) > 0 {
		next()
		w.WriteString(kw("PARTITION BY"))
		w.WriteByte(' ')
		for i, e := range mr.PartitionBy {
			if i > 0 {
				w.WriteString(", ")
			}
			w.WriteString(exprSQL(e))
		}
	}
	if len(mr.OrderBy) > 0 {
		next()
		w.WriteString(kw("ORDER BY"))
		w.WriteByte(' ')
		for i := range mr.OrderBy {
			if i > 0 {
				w.WriteString(", ")
			}
			w.WriteString(exprSQL(mr.OrderBy[i].Expression))
			if !mr.OrderBy[i].Ascending {
				w.WriteByte(' ')
				w.WriteString(kw("DESC"))
			}
		}
	}
	if len(mr.Measures) > 0 {
		next()
		w.WriteString(kw("MEASURES"))
		w.WriteByte(' ')
		for i, m := range mr.Measures {
			if i > 0 {
				w.WriteString(", ")
			}
			w.WriteString(exprSQL(m.Expr))
			if m.Alias != "" {
				w.WriteByte(' ')
				w.WriteString(kw("AS"))
				w.WriteByte(' ')
				w.WriteString(QuoteName(m.Alias))
			}
		}
	}
	switch strings.ToUpper(mr.RowsPerMatch) {
	case "ONE ROW PER MATCH", "ALL ROWS PER MATCH":
		next()
		w.WriteString(kw(strings.ToUpper(mr.RowsPerMatch)))
	}
	if mr.AfterMatch != "" && isMatchRecognizeRawText(mr.AfterMatch, false) {
		next()
		w.WriteString(mr.AfterMatch)
	}
	if mr.Pattern != "" && isMatchRecognizeRawText(mr.Pattern, true) && balancedParens(mr.Pattern) {
		next()
		w.WriteString(kw("PATTERN"))
		w.WriteString(" (")
		w.WriteString(mr.Pattern)
		w.WriteByte(')')
	}
	if len(mr.Definitions) > 0 {
		next()
		w.WriteString(kw("DEFINE"))
		w.WriteByte(' ')
		for i, d := range mr.Definitions {
			if i > 0 {
				w.WriteString(", ")
			}
			writeBareOrQuoted(w, d.Name)
			w.WriteByte(' ')
			w.WriteString(kw("AS"))
			w.WriteByte(' ')
			w.WriteString(exprSQL(d.Condition))
		}
	}
	w.WriteByte(')')
}

// releaseTableFactorModifiers releases the expressions held by the
// table-factor modifiers of tr and clears them.
func releaseTableFactorModifiers(tr *TableReference, mode releaseMode) {
	if s := tr.tableSample(); s != nil {
		for i := range s.Args {
			releaseExpression(s.Args[i], mode)
			s.Args[i] = nil
		}
		releaseExpression(s.Seed, mode)
		s.Args, s.Seed = nil, nil
	}
	if f := tr.flashback(); f != nil {
		releaseExpression(f.Point, mode)
		releaseExpression(f.Start, mode)
		releaseExpression(f.End, mode)
		f.Point, f.Start, f.End = nil, nil, nil
	}
	if m := tr.Modifiers; m != nil && m.PartitionFor != nil {
		for i := range m.PartitionFor.Values {
			releaseExpression(m.PartitionFor.Values[i], mode)
			m.PartitionFor.Values[i] = nil
		}
	}
	if m := tr.Modifiers; m != nil && m.Values != nil {
		releaseValues(m.Values, mode)
		m.Values = nil
	}
	if g := tr.joinGroup(); g != nil {
		for i := range g.Tables {
			releaseTableReference(&g.Tables[i], mode)
		}
		for i := range g.Joins {
			releaseTableReference(&g.Joins[i].Right, mode)
			releaseExpression(g.Joins[i].Condition, mode)
			releaseExpression(g.Joins[i].MatchCondition, mode)
			for _, u := range g.Joins[i].Using {
				releaseExpression(u, mode)
			}
			g.Joins[i] = JoinClause{}
		}
		g.Tables, g.Joins = nil, nil
	}
	tr.Modifiers = nil // not pooled; its expressions were released above
	tr.Only = false
}

// tableAliasFollowsClause reports whether the alias of t is written after a
// PIVOT / UNPIVOT / MATCH_RECOGNIZE clause (as "AS alias") rather than right
// after the table.
func tableAliasFollowsClause(t *TableReference) bool {
	return t.Pivot != nil || t.Unpivot != nil || t.MatchRecognize != nil
}

// TableAliasFollowsClause reports whether the alias of t belongs after its
// PIVOT / UNPIVOT / MATCH_RECOGNIZE clause rather than right after the table.
func TableAliasFollowsClause(t *TableReference) bool {
	return t != nil && tableAliasFollowsClause(t)
}

// writeRowConstructorRows writes MySQL VALUES rows as ROW(a, b), ROW(c, d).
func writeRowConstructorRows(buf *bytes.Buffer, rows [][]Expression) {
	for i, row := range rows {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString("ROW(")
		writeExprList(buf, row)
		buf.WriteByte(')')
	}
}

// writeColumnAliasEntries writes the entries of a table column alias list,
// each with its type when one is recorded, honouring the delimiters
// recorded in list.Quotes; nq, when not nil, adjusts each NameQuote (the
// formatter uses it to apply the target dialect's delimiter).
func writeColumnAliasEntries(w textWriter, list *ColumnAliasList, nq func(NameQuote) NameQuote) {
	for i, n := range list.Names {
		if i > 0 {
			w.WriteString(", ")
		}
		q := nameQuoteAt(list.Quotes, i)
		if nq != nil {
			q = nq(q)
		}
		w.WriteString(QuoteColumnNameWith(n, q))
		if i < len(list.Types) && list.Types[i] != "" {
			w.WriteByte(' ')
			w.WriteString(QuoteDataType(list.Types[i]))
		}
	}
}

// TableColumnAliasesSQL returns the "(a, b)" column alias list of t's alias,
// with column types when recorded, or "" when there is none.
func TableColumnAliasesSQL(t *TableReference) string {
	return TableColumnAliasesSQLWith(t, nil)
}

// TableColumnAliasesSQLWith is TableColumnAliasesSQL with each name's
// recorded NameQuote passed through nq first (nil leaves it unchanged).
func TableColumnAliasesSQLWith(t *TableReference, nq func(NameQuote) NameQuote) string {
	if t == nil || t.ColumnAliases == nil || len(t.ColumnAliases.Names) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteByte('(')
	writeColumnAliasEntries(&sb, t.ColumnAliases, nq)
	sb.WriteByte(')')
	return sb.String()
}

// isTableHintText reports whether h is a table hint the parser produces: a
// bare word (NOLOCK) or a bare word with an argument list of bare words or
// numbers separated by ", " (INDEX(ix_a, ix_b), INDEX(0)).
func isTableHintText(h string) bool {
	open := strings.IndexByte(h, '(')
	if open < 0 {
		return isBareTableHint(h)
	}
	if !isBareTableHint(h[:open]) || !strings.HasSuffix(h, ")") || open+2 > len(h)-1 {
		return false
	}
	for _, arg := range strings.Split(h[open+1:len(h)-1], ", ") {
		if !isBareTableHint(arg) && !isDigits(arg) {
			return false
		}
	}
	return true
}

// TableHintSQL returns a SQL Server table hint ready to write inside
// WITH (...), with its hint keyword passed through kw (nil keeps it): a hint
// the parser produces (see QuoteTableHint) is written as is, anything else is
// double-quoted.
func TableHintSQL(h string, kw func(string) string) string {
	if !isTableHintText(h) {
		return QuoteTableHint(h)
	}
	if kw == nil {
		return h
	}
	if open := strings.IndexByte(h, '('); open >= 0 {
		return kw(h[:open]) + h[open:]
	}
	return kw(h)
}

// isPositionalColumnName reports whether name is a Snowflake positional
// column reference: $ followed by digits ($1, $12).
func isPositionalColumnName(name string) bool {
	if len(name) < 2 || name[0] != '$' {
		return false
	}
	for i := 1; i < len(name); i++ {
		if name[i] < '0' || name[i] > '9' {
			return false
		}
	}
	return true
}

// writeOpenJSONSchema writes " WITH (name type ['path'] [AS JSON], ...)".
func writeOpenJSONSchema(w textWriter, cols []OpenJSONColumn, kw func(string) string) {
	w.WriteByte(' ')
	w.WriteString(kw("WITH"))
	w.WriteString(" (")
	for i, c := range cols {
		if i > 0 {
			w.WriteString(", ")
		}
		w.WriteString(QuoteColumnName(c.Name))
		w.WriteByte(' ')
		w.WriteString(QuoteDataType(c.Type))
		if c.Path != "" {
			buf := getBuf()
			writeStringLiteral(buf, c.Path)
			w.WriteByte(' ')
			w.WriteString(buf.String())
			putBuf(buf)
		}
		if c.AsJSON {
			w.WriteByte(' ')
			w.WriteString(kw("AS JSON"))
		}
	}
	w.WriteByte(')')
}
