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

// sql_ddl_objects.go - shared SQL writers for CREATE TABLE heads and tails,
// CREATE INDEX, CREATE [MATERIALIZED] VIEW, DROP and TRUNCATE. The SQL()
// methods and the formatter both use them; DDLStyle carries the
// formatter's keyword casing and nested-node rendering.

package ast

import (
	"bytes"
	"strings"
)

// DDLStyle tells the shared DDL writers how to case keywords and render
// nested expressions and queries. The zero value writes keywords as given
// (upper case) and nested nodes in their SQL() form.
type DDLStyle struct {
	// Keyword cases a keyword; nil leaves it unchanged.
	Keyword func(string) string
	// Expr renders an expression; nil uses its SQL form.
	Expr func(Expression) string
	// Stmt renders a nested query; nil uses its SQL form.
	Stmt func(Statement) string
	// ClauseSep separates a statement from its nested query and trailing
	// clauses (WHERE, WITH ...); empty means one space.
	ClauseSep string
	// NameQuote adjusts the recorded NameQuote of a name before it is
	// written (the formatter sets the target dialect's default delimiter);
	// nil leaves it unchanged.
	NameQuote func(NameQuote) NameQuote
}

func (s DDLStyle) nq(q NameQuote) NameQuote {
	if s.NameQuote == nil {
		return q
	}
	return s.NameQuote(q)
}

// nqList returns qs with each entry adjusted by s.NameQuote, or qs itself
// when there is nothing to adjust.
func (s DDLStyle) nqList(qs []NameQuote, n int) []NameQuote {
	if s.NameQuote == nil {
		return qs
	}
	out := make([]NameQuote, n)
	for i := range out {
		out[i] = s.NameQuote(nameQuoteAt(qs, i))
	}
	return out
}

func (s DDLStyle) kw(k string) string {
	if s.Keyword == nil {
		return k
	}
	return s.Keyword(k)
}

func (s DDLStyle) writeKw(buf *bytes.Buffer, k string) {
	buf.WriteString(s.kw(k))
}

func (s DDLStyle) writeExpr(buf *bytes.Buffer, e Expression) {
	if s.Expr == nil {
		writeExpr(buf, e)
		return
	}
	buf.WriteString(s.Expr(e))
}

func (s DDLStyle) writeExprList(buf *bytes.Buffer, list []Expression) {
	for i, e := range list {
		if i > 0 {
			buf.WriteString(", ")
		}
		s.writeExpr(buf, e)
	}
}

func (s DDLStyle) writeStmt(buf *bytes.Buffer, st Statement) {
	if s.Stmt == nil {
		writeStmt(buf, st)
		return
	}
	buf.WriteString(s.Stmt(st))
}

func (s DDLStyle) sep() string {
	if s.ClauseSep == "" {
		return " "
	}
	return s.ClauseSep
}

// CreateTableHeadSQL returns "CREATE [OR REPLACE] [kind] TABLE
// [IF NOT EXISTS] name [ON CLUSTER c]" followed by the LIKE, CLONE,
// PARTITION OF or AS-table source, if any.
func CreateTableHeadSQL(c *CreateTableStatement, st DDLStyle) string {
	buf := getBuf()
	defer putBuf(buf)
	writeCreateTableHead(buf, c, st)
	return buf.String()
}

// CreateTableTailSQL returns everything written after the column list of
// CREATE TABLE (with a leading space): INHERITS, WITH SYSTEM VERSIONING,
// partitioning, table options, ClickHouse engine clauses and the AS query.
func CreateTableTailSQL(c *CreateTableStatement, st DDLStyle) string {
	buf := getBuf()
	defer putBuf(buf)
	writeCreateTableTail(buf, c, st)
	return buf.String()
}

func writeCreateTableHead(buf *bytes.Buffer, c *CreateTableStatement, st DDLStyle) {
	st.writeKw(buf, "CREATE ")
	if c.OrReplace {
		st.writeKw(buf, "OR REPLACE ")
	}
	if k := TableKindText(c.Kind); k != "" {
		st.writeKw(buf, k)
		buf.WriteByte(' ')
	} else if c.Temporary {
		st.writeKw(buf, "TEMPORARY ")
	}
	st.writeKw(buf, "TABLE ")
	if c.IfNotExists {
		st.writeKw(buf, "IF NOT EXISTS ")
	}
	writeQualifiedNameQ(buf, c.Name, st.nq(c.NameQuote))
	writeOnCluster(buf, c.OnCluster, st)
	switch {
	case c.Like != "":
		buf.WriteByte(' ')
		st.writeKw(buf, "LIKE ")
		writeQualifiedNameQ(buf, c.Like, st.nq(c.SourceQuote))
	case c.Clone != nil:
		buf.WriteByte(' ')
		st.writeKw(buf, "CLONE ")
		writeQualifiedNameQ(buf, c.Clone.Source, st.nq(c.SourceQuote))
		if at := keywordOneOf(c.Clone.At, []string{"AT", "BEFORE"}); at != "" && c.Clone.Point != nil {
			if kind := keywordOneOf(c.Clone.PointKind, clonePointKeywords); kind != "" {
				buf.WriteByte(' ')
				st.writeKw(buf, at)
				buf.WriteString(" (")
				st.writeKw(buf, kind)
				buf.WriteString(" => ")
				st.writeExpr(buf, c.Clone.Point)
				buf.WriteByte(')')
			}
		}
	case c.PartitionOf != "":
		buf.WriteByte(' ')
		st.writeKw(buf, "PARTITION OF ")
		writeQualifiedNameQ(buf, c.PartitionOf, st.nq(c.SourceQuote))
		writePartitionBound(buf, c.PartitionBound, st)
	case c.AsTable != "":
		buf.WriteByte(' ')
		st.writeKw(buf, "AS ")
		writeQualifiedNameQ(buf, c.AsTable, st.nq(c.SourceQuote))
	}
}

func writeOnCluster(buf *bytes.Buffer, cluster string, st DDLStyle) {
	if cluster == "" {
		return
	}
	buf.WriteByte(' ')
	st.writeKw(buf, "ON CLUSTER ")
	writeQualifiedName(buf, cluster)
}

func writePartitionBound(buf *bytes.Buffer, b *PartitionBound, st DDLStyle) {
	if b == nil {
		return
	}
	buf.WriteByte(' ')
	switch {
	case b.Default:
		st.writeKw(buf, "DEFAULT")
	case len(b.In) > 0:
		st.writeKw(buf, "FOR VALUES IN ")
		writeBoundList(buf, b.In, st)
	case len(b.From) > 0:
		st.writeKw(buf, "FOR VALUES FROM ")
		writeBoundList(buf, b.From, st)
		buf.WriteByte(' ')
		st.writeKw(buf, "TO ")
		writeBoundList(buf, b.To, st)
	default:
		st.writeKw(buf, "FOR VALUES WITH (MODULUS ")
		st.writeExpr(buf, b.Modulus)
		buf.WriteString(", ")
		st.writeKw(buf, "REMAINDER ")
		st.writeExpr(buf, b.Remainder)
		buf.WriteByte(')')
	}
}

// writeBoundList writes "(v, ...)" where MINVALUE, MAXVALUE and DEFAULT
// stay bare keywords.
func writeBoundList(buf *bytes.Buffer, list []Expression, st DDLStyle) {
	buf.WriteByte('(')
	for i, e := range list {
		if i > 0 {
			buf.WriteString(", ")
		}
		writeBoundValue(buf, e, st)
	}
	buf.WriteByte(')')
}

func writeBoundValue(buf *bytes.Buffer, e Expression, st DDLStyle) {
	if id, ok := e.(*Identifier); ok && id.Table == "" && !id.Quoted {
		if k := keywordOneOf(id.Name, []string{"MAXVALUE", "MINVALUE", "DEFAULT"}); k != "" {
			st.writeKw(buf, k)
			return
		}
	}
	st.writeExpr(buf, e)
}

func writeCreateTableTail(buf *bytes.Buffer, c *CreateTableStatement, st DDLStyle) {
	if len(c.Inherits) > 0 {
		buf.WriteByte(' ')
		st.writeKw(buf, "INHERITS (")
		writeQualifiedNameList(buf, c.Inherits)
		buf.WriteByte(')')
	}
	if c.WithSystemVersioning {
		buf.WriteByte(' ')
		st.writeKw(buf, "WITH SYSTEM VERSIONING")
	}
	split := c.OptionsBeforePartition
	if split > len(c.Options) || c.PartitionBy == nil {
		split = len(c.Options)
	}
	writeTableOptions(buf, c.Options[:split], st)
	if c.PartitionBy != nil {
		writePartitionBy(buf, c.PartitionBy, st)
		writePartitionDefinitions(buf, c.Partitions, st)
	}
	writeTableOptions(buf, c.Options[split:], st)
	if c.WithoutRowID && !hasTableOption(c.Options, "WITHOUT ROWID") {
		buf.WriteByte(' ')
		st.writeKw(buf, "WITHOUT ROWID")
	}
	writeEngineClauses(buf, c.Engine, st)
	if c.AsQuery != nil {
		buf.WriteByte(' ')
		st.writeKw(buf, "AS")
		buf.WriteString(st.sep())
		st.writeStmt(buf, c.AsQuery)
		writeWithData(buf, c.WithData, st)
	}
}

func writeWithData(buf *bytes.Buffer, withData *bool, st DDLStyle) {
	if withData == nil {
		return
	}
	buf.WriteString(st.sep())
	if *withData {
		st.writeKw(buf, "WITH DATA")
	} else {
		st.writeKw(buf, "WITH NO DATA")
	}
}

func hasTableOption(opts []TableOption, name string) bool {
	for i := range opts {
		if opts[i].Name == name {
			return true
		}
	}
	return false
}

// isSQLiteTableOption reports whether name is a SQLite table option, which
// are separated by commas.
func isSQLiteTableOption(name string) bool {
	return name == "STRICT" || name == "WITHOUT ROWID"
}

// writeTableOptions writes each option with a leading space (a comma
// between consecutive SQLite options). Options with an unknown name are
// dropped.
func writeTableOptions(buf *bytes.Buffer, opts []TableOption, st DDLStyle) {
	prev := ""
	for i := range opts {
		o := &opts[i]
		name := TableOptionNameText(o.Name)
		if name == "" {
			continue
		}
		if isSQLiteTableOption(prev) && isSQLiteTableOption(name) {
			buf.WriteByte(',')
		}
		buf.WriteByte(' ')
		writeTableOption(buf, o, st.kw(name), st)
		prev = name
	}
}

// TableOptionsSQL returns the options written as by CREATE TABLE, each with
// a leading space.
func TableOptionsSQL(opts []TableOption, st DDLStyle) string {
	buf := getBuf()
	defer putBuf(buf)
	writeTableOptions(buf, opts, st)
	return buf.String()
}

// isOptionWords reports whether s is one or more option-name words
// (letters, digits, '_' and '.') separated by single spaces.
func isOptionWords(s string) bool {
	if s == "" || s[0] == ' ' || s[len(s)-1] == ' ' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_' || c == '.' || (c >= '0' && c <= '9') || (c|0x20 >= 'a' && c|0x20 <= 'z'):
		case c == ' ' && s[i-1] != ' ':
		default:
			return false
		}
	}
	return true
}

func writeTableOption(buf *bytes.Buffer, o *TableOption, name string, st DDLStyle) {
	buf.WriteString(name)
	switch o.Form {
	case TableOptionFlag:
	case TableOptionArgs:
		buf.WriteString(" (")
		st.writeExprList(buf, o.Args)
		buf.WriteByte(')')
	case TableOptionList:
		buf.WriteString(" (")
		n := 0
		for i := range o.Sub {
			sub := &o.Sub[i]
			if !isOptionWords(sub.Name) {
				continue
			}
			if n > 0 {
				buf.WriteString(", ")
			}
			n++
			buf.WriteString(sub.Name)
			if sub.HasValue {
				buf.WriteString(" = ")
				writeOptionValueKind(buf, sub.Value, sub.ValueKind)
			}
		}
		buf.WriteByte(')')
	case TableOptionSpaced:
		buf.WriteByte(' ')
		writeTableOptionValue(buf, o)
	default:
		buf.WriteByte('=')
		writeTableOptionValue(buf, o)
	}
}

func writeTableOptionValue(buf *bytes.Buffer, o *TableOption) {
	writeOptionValueKind(buf, o.Value, o.ValueKind)
}

func writeOptionValueKind(buf *bytes.Buffer, v string, kind TableOptionValueKind) {
	switch kind {
	case TableOptionString:
		writeStringLiteral(buf, v)
	case TableOptionNumber:
		if isDecimalDigits(v) {
			buf.WriteString(v)
			return
		}
		writeStringLiteral(buf, v)
	default:
		writeOptionValue(buf, v)
	}
}

func isDecimalDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func writePartitionBy(buf *bytes.Buffer, pb *PartitionBy, st DDLStyle) {
	typ := strings.ToUpper(PartitionByText(pb.Type))
	buf.WriteByte(' ')
	st.writeKw(buf, "PARTITION BY")
	if pb.Linear && (typ == "HASH" || typ == "KEY") {
		buf.WriteByte(' ')
		st.writeKw(buf, "LINEAR")
	}
	if typ != "" {
		buf.WriteByte(' ')
		st.writeKw(buf, typ)
	}
	if typ == "SYSTEM_TIME" {
		if pb.Interval != nil {
			buf.WriteByte(' ')
			st.writeExpr(buf, pb.Interval)
		}
		return
	}
	// An unknown method is left out: "PARTITION BY  (cols)" does not parse.
	buf.WriteString(" (")
	if len(pb.Expressions) > 0 {
		st.writeExprList(buf, pb.Expressions)
	} else {
		writeColumnNameList(buf, pb.Columns)
	}
	buf.WriteByte(')')
	if pb.Interval != nil {
		buf.WriteByte(' ')
		st.writeKw(buf, "INTERVAL (")
		st.writeExpr(buf, pb.Interval)
		buf.WriteByte(')')
	}
	if pb.Partitions != nil {
		buf.WriteByte(' ')
		st.writeKw(buf, "PARTITIONS ")
		st.writeExpr(buf, pb.Partitions)
	}
}

func writePartitionDefinitions(buf *bytes.Buffer, defs []PartitionDefinition, st DDLStyle) {
	if len(defs) == 0 {
		return
	}
	buf.WriteString(" (")
	for i := range defs {
		if i > 0 {
			buf.WriteString(", ")
		}
		writePartitionDefinition(buf, &defs[i], st)
	}
	buf.WriteByte(')')
}

// partitionDefTypes are the PartitionDefinition.Type values the renderers
// write.
var partitionDefTypes = []string{"LESS THAN", "IN", "FROM TO", "VALUES", "HISTORY", "CURRENT"}

func writePartitionDefinition(buf *bytes.Buffer, d *PartitionDefinition, st DDLStyle) {
	st.writeKw(buf, "PARTITION ")
	writeColumnName(buf, d.Name)
	switch typ := strings.ToUpper(keywordOneOf(d.Type, partitionDefTypes)); typ {
	case "LESS THAN":
		buf.WriteByte(' ')
		st.writeKw(buf, "VALUES LESS THAN ")
		if d.LessThan != nil {
			writeBoundList(buf, []Expression{d.LessThan}, st)
		} else {
			writeBoundList(buf, d.Values, st)
		}
	case "IN":
		buf.WriteByte(' ')
		st.writeKw(buf, "VALUES IN ")
		writeBoundList(buf, d.InValues, st)
	case "FROM TO":
		buf.WriteByte(' ')
		st.writeKw(buf, "VALUES FROM ")
		writeBoundList(buf, []Expression{d.From}, st)
		buf.WriteByte(' ')
		st.writeKw(buf, "TO ")
		writeBoundList(buf, []Expression{d.To}, st)
	case "VALUES":
		buf.WriteByte(' ')
		st.writeKw(buf, "VALUES ")
		writeBoundList(buf, d.Values, st)
	case "":
	default:
		buf.WriteByte(' ')
		st.writeKw(buf, typ)
	}
	if d.Tablespace != "" {
		buf.WriteByte(' ')
		st.writeKw(buf, "TABLESPACE ")
		writeColumnName(buf, d.Tablespace)
	}
}

// EngineClausesSQL returns the ClickHouse clauses written after ENGINE = ...
// (with a leading space), or "" for nil.
func EngineClausesSQL(e *TableEngineClauses, st DDLStyle) string {
	buf := getBuf()
	defer putBuf(buf)
	writeEngineClauses(buf, e, st)
	return buf.String()
}

func writeEngineClauses(buf *bytes.Buffer, e *TableEngineClauses, st DDLStyle) {
	if e == nil {
		return
	}
	clause := func(kw string, x Expression) {
		if x == nil {
			return
		}
		buf.WriteByte(' ')
		st.writeKw(buf, kw)
		buf.WriteByte(' ')
		st.writeExpr(buf, x)
	}
	clause("PARTITION BY", e.PartitionBy)
	clause("PRIMARY KEY", e.PrimaryKey)
	clause("ORDER BY", e.OrderBy)
	clause("SAMPLE BY", e.SampleBy)
	if len(e.TTL) > 0 {
		buf.WriteByte(' ')
		st.writeKw(buf, "TTL ")
		for i := range e.TTL {
			if i > 0 {
				buf.WriteString(", ")
			}
			writeTTLRule(buf, &e.TTL[i], st)
		}
	}
	if len(e.Settings) > 0 {
		buf.WriteByte(' ')
		st.writeKw(buf, "SETTINGS ")
		writeDDLSettings(buf, e.Settings, st)
	}
	if e.Comment != nil {
		buf.WriteByte(' ')
		st.writeKw(buf, "COMMENT ")
		writeStringLiteral(buf, *e.Comment)
	}
}

func writeDDLSettings(buf *bytes.Buffer, settings []QuerySetting, st DDLStyle) {
	for i := range settings {
		if i > 0 {
			buf.WriteString(", ")
		}
		writeSafeIdentifier(buf, settings[i].Name)
		buf.WriteString(" = ")
		st.writeExpr(buf, settings[i].Value)
	}
}

func writeTTLRule(buf *bytes.Buffer, r *TTLRule, st DDLStyle) {
	st.writeExpr(buf, r.Expr)
	switch a := strings.ToUpper(TTLActionText(r.Action)); a {
	case "":
	case "DELETE":
		buf.WriteByte(' ')
		st.writeKw(buf, a)
	default:
		buf.WriteByte(' ')
		st.writeKw(buf, a)
		buf.WriteByte(' ')
		writeStringLiteral(buf, r.Target)
	}
	if r.Where != nil {
		buf.WriteByte(' ')
		st.writeKw(buf, "WHERE ")
		st.writeExpr(buf, r.Where)
	}
	if len(r.GroupBy) > 0 {
		buf.WriteByte(' ')
		st.writeKw(buf, "GROUP BY ")
		st.writeExprList(buf, r.GroupBy)
		if len(r.Set) > 0 {
			buf.WriteByte(' ')
			st.writeKw(buf, "SET ")
			writeDDLSettings(buf, r.Set, st)
		}
	}
}

// CreateIndexSQL renders a CREATE INDEX statement in the given style.
func CreateIndexSQL(c *CreateIndexStatement, st DDLStyle) string {
	buf := getBuf()
	defer putBuf(buf)
	writeCreateIndex(buf, c, st)
	return buf.String()
}

func writeCreateIndex(buf *bytes.Buffer, c *CreateIndexStatement, st DDLStyle) {
	st.writeKw(buf, "CREATE ")
	if c.OrReplace {
		st.writeKw(buf, "OR REPLACE ")
	}
	if c.Unique {
		st.writeKw(buf, "UNIQUE ")
	}
	if k := IndexKindText(c.Kind); k != "" {
		st.writeKw(buf, k)
		buf.WriteByte(' ')
	}
	st.writeKw(buf, "INDEX ")
	if c.Concurrently {
		st.writeKw(buf, "CONCURRENTLY ")
	}
	if c.IfNotExists {
		st.writeKw(buf, "IF NOT EXISTS ")
	}
	if c.Name != "" {
		writeQualifiedNameQ(buf, c.Name, st.nq(c.NameQuote))
		buf.WriteByte(' ')
	}
	st.writeKw(buf, "ON ")
	if c.Only {
		st.writeKw(buf, "ONLY ")
	}
	writeQualifiedNameQ(buf, c.Table, st.nq(c.TableQuote))

	if c.Using != "" {
		buf.WriteByte(' ')
		st.writeKw(buf, "USING ")
		// An access method is a plain word even when it is a keyword
		// (hash); anything else is quoted.
		if isBareNameChars(c.Using, false) {
			buf.WriteString(c.Using)
		} else {
			writeQuotedIdentifier(buf, c.Using)
		}
	}

	buf.WriteString(" (")
	for i := range c.Columns {
		if i > 0 {
			buf.WriteString(", ")
		}
		writeIndexColumn(buf, &c.Columns[i], st)
	}
	buf.WriteByte(')')

	if len(c.Include) > 0 {
		buf.WriteByte(' ')
		st.writeKw(buf, "INCLUDE (")
		writeColumnNameListQ(buf, c.Include, st.nqList(c.IncludeQuotes, len(c.Include)))
		buf.WriteByte(')')
	}
	split := c.OptionsBeforeWhere
	if split > len(c.Options) || c.Where == nil {
		split = len(c.Options)
	}
	writeIndexOptions(buf, c.Options[:split], st)
	if c.Where != nil {
		buf.WriteString(st.sep())
		st.writeKw(buf, "WHERE ")
		st.writeExpr(buf, c.Where)
	}
	writeIndexOptions(buf, c.Options[split:], st)
}

func writeIndexOptions(buf *bytes.Buffer, opts []TableOption, st DDLStyle) {
	for i := range opts {
		name := TableOptionNameText(opts[i].Name)
		if name == "" {
			continue
		}
		buf.WriteByte(' ')
		writeTableOption(buf, &opts[i], st.kw(name), st)
	}
}

func writeIndexColumn(buf *bytes.Buffer, col *IndexColumn, st DDLStyle) {
	if col.Expr != nil {
		switch col.Expr.(type) {
		case *FunctionCall, *ParenthesizedExpression:
			st.writeExpr(buf, col.Expr)
		default:
			buf.WriteByte('(')
			st.writeExpr(buf, col.Expr)
			buf.WriteByte(')')
		}
	} else {
		writeTableAliasQ(buf, col.Column, st.nq(col.ColumnQuote))
	}
	if col.Collate != "" {
		buf.WriteByte(' ')
		st.writeKw(buf, "COLLATE ")
		writeCollationName(buf, col.Collate, col.CollateQuoted)
	}
	if col.OpClass != "" {
		buf.WriteByte(' ')
		writeColumnName(buf, col.OpClass)
	}
	if dir := SortDirectionText(col.Direction); dir != "" {
		buf.WriteByte(' ')
		st.writeKw(buf, dir)
	}
	if col.NullsLast {
		buf.WriteByte(' ')
		st.writeKw(buf, "NULLS LAST")
	} else if col.NullsFirst {
		buf.WriteByte(' ')
		st.writeKw(buf, "NULLS FIRST")
	}
}

// CreateViewSQL renders a CREATE VIEW statement in the given style.
func CreateViewSQL(c *CreateViewStatement, st DDLStyle) string {
	buf := getBuf()
	defer putBuf(buf)
	writeCreateView(buf, c, st)
	return buf.String()
}

func writeCreateView(buf *bytes.Buffer, c *CreateViewStatement, st DDLStyle) {
	st.writeKw(buf, "CREATE ")
	if c.OrReplace {
		st.writeKw(buf, "OR REPLACE ")
	} else if c.OrAlter {
		st.writeKw(buf, "OR ALTER ")
	}
	if m := KeywordWordsText(c.Modifiers); m != "" {
		st.writeKw(buf, m)
		buf.WriteByte(' ')
	} else if c.Temporary {
		st.writeKw(buf, "TEMPORARY ")
	}
	st.writeKw(buf, "VIEW ")
	if c.IfNotExists {
		st.writeKw(buf, "IF NOT EXISTS ")
	}
	writeQualifiedNameQ(buf, c.Name, st.nq(c.NameQuote))
	writeOnCluster(buf, c.OnCluster, st)
	if len(c.Columns) > 0 {
		buf.WriteString(" (")
		writeNameListQ(buf, c.Columns, st.nqList(c.ColumnQuotes, len(c.Columns)))
		buf.WriteByte(')')
	}
	buf.WriteByte(' ')
	st.writeKw(buf, "AS")
	buf.WriteString(st.sep())
	st.writeStmt(buf, c.Query)
	if c.ReadOnly {
		buf.WriteString(st.sep())
		st.writeKw(buf, "WITH READ ONLY")
	}
	// WithOption is CHECK OPTION, CASCADED or LOCAL CHECK OPTION; anything
	// else can only come from a hand-built AST and is dropped.
	if opt := ViewWithOptionText(c.WithOption); opt != "" {
		buf.WriteString(st.sep())
		st.writeKw(buf, "WITH ")
		st.writeKw(buf, opt)
	}
}

// CreateMaterializedViewSQL renders a CREATE MATERIALIZED VIEW statement in
// the given style.
func CreateMaterializedViewSQL(c *CreateMaterializedViewStatement, st DDLStyle) string {
	buf := getBuf()
	defer putBuf(buf)
	writeCreateMaterializedView(buf, c, st)
	return buf.String()
}

func writeCreateMaterializedView(buf *bytes.Buffer, c *CreateMaterializedViewStatement, st DDLStyle) {
	st.writeKw(buf, "CREATE ")
	if c.OrReplace {
		st.writeKw(buf, "OR REPLACE ")
	}
	st.writeKw(buf, "MATERIALIZED VIEW ")
	if c.IfNotExists {
		st.writeKw(buf, "IF NOT EXISTS ")
	}
	writeQualifiedNameQ(buf, c.Name, st.nq(c.NameQuote))
	writeOnCluster(buf, c.OnCluster, st)
	if c.To != "" {
		buf.WriteByte(' ')
		st.writeKw(buf, "TO ")
		writeQualifiedNameQ(buf, c.To, st.nq(c.ToQuote))
	}
	switch {
	case len(c.ColumnDefs) > 0:
		buf.WriteString(" (")
		for i := range c.ColumnDefs {
			if i > 0 {
				buf.WriteString(", ")
			}
			buf.WriteString(columnDefSQL(&c.ColumnDefs[i]))
		}
		buf.WriteByte(')')
	case len(c.Columns) > 0:
		buf.WriteString(" (")
		writeNameListQ(buf, c.Columns, st.nqList(c.ColumnQuotes, len(c.Columns)))
		buf.WriteByte(')')
	}
	if c.Tablespace != "" {
		buf.WriteByte(' ')
		st.writeKw(buf, "TABLESPACE ")
		writeColumnName(buf, c.Tablespace)
	}
	writeTableOptions(buf, c.EngineOptions, st)
	writeEngineClauses(buf, c.Engine, st)
	if c.Populate {
		buf.WriteByte(' ')
		st.writeKw(buf, "POPULATE")
	}
	if r := KeywordWordsText(c.Refresh); r != "" {
		buf.WriteByte(' ')
		st.writeKw(buf, r)
	}
	buf.WriteByte(' ')
	st.writeKw(buf, "AS")
	buf.WriteString(st.sep())
	st.writeStmt(buf, c.Query)
	writeWithData(buf, c.WithData, st)
}

// DropSQL renders a DROP statement in the given style.
func DropSQL(d *DropStatement, st DDLStyle) string {
	buf := getBuf()
	defer putBuf(buf)
	writeDrop(buf, d, st)
	return buf.String()
}

func writeDrop(buf *bytes.Buffer, d *DropStatement, st DDLStyle) {
	st.writeKw(buf, "DROP ")
	objType := DropObjectTypeText(d.ObjectType)
	if d.Temporary && keywordOneOf(objType, []string{"TABLE"}) != "" {
		st.writeKw(buf, "TEMPORARY ")
	}
	// An unknown object type is left out: "DROP  name" does not parse.
	st.writeKw(buf, objType)
	buf.WriteByte(' ')
	if d.Concurrently {
		st.writeKw(buf, "CONCURRENTLY ")
	}
	if d.IfExists {
		st.writeKw(buf, "IF EXISTS ")
	}
	writeQualifiedNameListQ(buf, d.Names, st.nqList(d.NameQuotes, len(d.Names)))
	writeOnCluster(buf, d.OnCluster, st)
	if d.OnTable != "" {
		buf.WriteByte(' ')
		st.writeKw(buf, "ON ")
		writeQualifiedNameQ(buf, d.OnTable, st.nq(d.OnTableQuote))
	}
	if c := CascadeText(d.CascadeType); c != "" {
		buf.WriteByte(' ')
		st.writeKw(buf, c)
	}
	if d.Purge {
		buf.WriteByte(' ')
		st.writeKw(buf, "PURGE")
	}
	if d.Sync {
		buf.WriteByte(' ')
		st.writeKw(buf, "SYNC")
	}
}

// TruncateSQL renders a TRUNCATE statement in the given style.
func TruncateSQL(t *TruncateStatement, st DDLStyle) string {
	buf := getBuf()
	defer putBuf(buf)
	writeTruncate(buf, t, st)
	return buf.String()
}

func writeTruncate(buf *bytes.Buffer, t *TruncateStatement, st DDLStyle) {
	st.writeKw(buf, "TRUNCATE TABLE ")
	writeQualifiedNameListQ(buf, t.Tables, st.nqList(t.TableQuotes, len(t.Tables)))
	if t.RestartIdentity {
		buf.WriteByte(' ')
		st.writeKw(buf, "RESTART IDENTITY")
	} else if t.ContinueIdentity {
		buf.WriteByte(' ')
		st.writeKw(buf, "CONTINUE IDENTITY")
	}
	if c := CascadeText(t.CascadeType); c != "" {
		buf.WriteByte(' ')
		st.writeKw(buf, c)
	}
	if s := TruncateStorageText(t.Storage); s != "" {
		buf.WriteByte(' ')
		st.writeKw(buf, s)
	}
}
