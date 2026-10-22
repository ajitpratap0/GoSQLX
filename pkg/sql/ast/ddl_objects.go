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

// ddl_objects.go - AST fields for the CREATE TABLE, CREATE INDEX and
// CREATE VIEW forms beyond their column-list core: CREATE TABLE AS query,
// LIKE / CLONE / PARTITION OF, table-kind modifiers, generic table options,
// ClickHouse ENGINE trailing clauses, index kinds and options, and view
// modifiers. The structs are embedded in the statement nodes so the fields
// read as the statement's own.

package ast

// TableOptionForm says how a TableOption is written.
type TableOptionForm uint8

const (
	// TableOptionEquals is NAME=value (the zero value; ENGINE=InnoDB).
	TableOptionEquals TableOptionForm = iota
	// TableOptionSpaced is NAME value, without '=' (TABLESPACE users,
	// DEFAULT CHARACTER SET utf8mb4, PCTFREE 10).
	TableOptionSpaced
	// TableOptionFlag is a bare option without a value (STRICT,
	// WITHOUT ROWID, COPY GRANTS, ON COMMIT DROP, LOCAL).
	TableOptionFlag
	// TableOptionArgs is NAME (expr, ...) (CLUSTER BY (a, b),
	// INHERITS-like lists).
	TableOptionArgs
	// TableOptionList is NAME (option, ...) where each entry is itself a
	// TableOption (WITH (fillfactor = 70), WITH (FILLFACTOR = 90, ONLINE = ON)).
	TableOptionList
)

// OptionParam is one entry of a parenthesized option list: name [= value]
// (fillfactor = 70, ONLINE = ON). It is plain data, not a Node.
type OptionParam struct {
	Name string
	// HasValue reports whether "= value" was written.
	HasValue  bool
	Value     string
	ValueKind TableOptionValueKind
}

// TableOptionValueKind says how a TableOption value is written.
type TableOptionValueKind uint8

const (
	// TableOptionWord is a bare word, quoted as an identifier when it is not
	// plainly shaped (the zero value).
	TableOptionWord TableOptionValueKind = iota
	// TableOptionString is a single-quoted string literal.
	TableOptionString
	// TableOptionNumber is an unsigned decimal number.
	TableOptionNumber
)

// CreateTableExtras holds the parts of CREATE TABLE beyond the column list.
// It is embedded in CreateTableStatement.
type CreateTableExtras struct {
	// OrReplace is CREATE OR REPLACE TABLE (Snowflake, MariaDB, ClickHouse).
	OrReplace bool
	// Kind is the table-kind modifier as written, upper-cased: TEMP,
	// TEMPORARY, GLOBAL TEMPORARY, LOCAL TEMPORARY, UNLOGGED, TRANSIENT or
	// VOLATILE. When empty, Temporary renders as TEMPORARY.
	Kind string
	// OnCluster is the ClickHouse ON CLUSTER name.
	OnCluster string
	// Like is the source table of CREATE TABLE t LIKE src.
	Like string
	// Clone is the Snowflake CLONE source.
	Clone *TableClone
	// PartitionOf is the parent table of PostgreSQL CREATE TABLE t
	// PARTITION OF parent; PartitionBound is its FOR VALUES / DEFAULT bound.
	PartitionOf    string
	PartitionBound *PartitionBound
	// AsTable is the ClickHouse source table of CREATE TABLE t AS other.
	AsTable string
	// AsQuery is the query of CREATE TABLE ... AS query.
	AsQuery Statement
	// WithData is the PostgreSQL WITH [NO] DATA of CREATE TABLE AS (nil
	// when not written).
	WithData *bool
	// Engine holds the ClickHouse clauses that follow ENGINE = ...
	Engine *TableEngineClauses
	// OptionsBeforePartition is how many Options were written before
	// PARTITION BY (MySQL and Oracle write table options first,
	// PostgreSQL writes them after).
	OptionsBeforePartition int
}

// TableClone is the Snowflake CLONE source of CREATE TABLE t CLONE src
// [AT | BEFORE (TIMESTAMP | OFFSET | STATEMENT => expr)].
type TableClone struct {
	Source string
	// At is AT or BEFORE, or empty.
	At string
	// PointKind is TIMESTAMP, OFFSET, STATEMENT or STREAM.
	PointKind string
	Point     Expression
}

// PartitionBound is the bound of a PostgreSQL table partition:
// FOR VALUES IN (...), FOR VALUES FROM (...) TO (...),
// FOR VALUES WITH (MODULUS n, REMAINDER m), or DEFAULT.
type PartitionBound struct {
	Default   bool
	In        []Expression
	From      []Expression
	To        []Expression
	Modulus   Expression
	Remainder Expression
}

// TableEngineClauses are the ClickHouse clauses written after
// ENGINE = ... in CREATE TABLE and CREATE MATERIALIZED VIEW.
type TableEngineClauses struct {
	PartitionBy Expression
	PrimaryKey  Expression
	OrderBy     Expression
	SampleBy    Expression
	TTL         []TTLRule
	Settings    []QuerySetting
	// Comment is the table COMMENT 'text' (nil when not written).
	Comment *string
}

// TTLRule is one ClickHouse table TTL rule:
// expr [DELETE | TO DISK 'd' | TO VOLUME 'v'] [WHERE cond]
// [GROUP BY keys [SET name = expr, ...]].
type TTLRule struct {
	Expr Expression
	// Action is DELETE, TO DISK or TO VOLUME, or empty.
	Action string
	// Target is the disk or volume name of TO DISK / TO VOLUME.
	Target  string
	Where   Expression
	GroupBy []Expression
	Set     []QuerySetting
}

// CreateIndexExtras holds the parts of CREATE INDEX beyond the core. It is
// embedded in CreateIndexStatement.
type CreateIndexExtras struct {
	// OrReplace is MariaDB CREATE OR REPLACE INDEX.
	OrReplace bool
	// Kind is the index kind written before INDEX: FULLTEXT, SPATIAL,
	// BITMAP, CLUSTERED or NONCLUSTERED.
	Kind string
	// Concurrently is PostgreSQL CREATE INDEX CONCURRENTLY.
	Concurrently bool
	// Only is PostgreSQL ON ONLY table.
	Only bool
	// Include lists the INCLUDE (cols) columns.
	Include []string
	// Options are the trailing index options (WITH (...), TABLESPACE x,
	// LOCAL, ONLINE, ...).
	Options []TableOption
	// OptionsBeforeWhere is how many Options precede the WHERE predicate
	// (PostgreSQL writes WITH (...) before WHERE, SQL Server after it).
	OptionsBeforeWhere int
}

// ViewExtras holds the CREATE VIEW / CREATE MATERIALIZED VIEW forms beyond
// the core. It is embedded in both view statements.
type ViewExtras struct {
	// OrAlter is SQL Server CREATE OR ALTER VIEW.
	OrAlter bool
	// Modifiers are the words written between CREATE [OR REPLACE] and VIEW,
	// upper-cased: TEMP, SECURE, FORCE, NO FORCE, RECURSIVE.
	Modifiers string
	// OnCluster is the ClickHouse ON CLUSTER name.
	OnCluster string
	// To is the ClickHouse materialized-view target table (TO name).
	To string
	// ColumnDefs are typed columns of a ClickHouse materialized view
	// (TO dst (a UInt8) or (a UInt8) ENGINE = ...).
	ColumnDefs []ColumnDef
	// EngineOptions are ENGINE = ... and other storage options of a
	// ClickHouse materialized view; Engine holds the clauses after them.
	EngineOptions []TableOption
	Engine        *TableEngineClauses
	// Populate is ClickHouse POPULATE.
	Populate bool
	// Refresh holds the Oracle materialized-view BUILD / REFRESH words as
	// written, upper-cased (BUILD IMMEDIATE REFRESH FAST ON COMMIT).
	Refresh string
	// ReadOnly is Oracle WITH READ ONLY.
	ReadOnly bool
}

// DropExtras holds the DROP forms beyond the core. It is embedded in
// DropStatement.
type DropExtras struct {
	// Temporary is MySQL DROP TEMPORARY TABLE.
	Temporary bool
	// Concurrently is PostgreSQL DROP INDEX CONCURRENTLY.
	Concurrently bool
	// OnTable is the table of MySQL / SQL Server DROP INDEX name ON table.
	OnTable string
	// OnCluster is the ClickHouse ON CLUSTER name.
	OnCluster string
	// Purge is Oracle PURGE.
	Purge bool
	// Sync is ClickHouse SYNC.
	Sync bool
}

// truncateStorageKeywords are the TRUNCATE storage clauses the renderers write.
var truncateStorageKeywords = []string{"DROP STORAGE", "REUSE STORAGE", "DROP ALL STORAGE"}

// TruncateStorageText returns s when it is DROP STORAGE, REUSE STORAGE or
// DROP ALL STORAGE (any case) and "" otherwise.
func TruncateStorageText(s string) string { return keywordOneOf(s, truncateStorageKeywords) }

// tableKindKeywords are the CREATE TABLE kind modifiers the renderers write.
var tableKindKeywords = []string{
	"TEMP", "TEMPORARY", "GLOBAL TEMPORARY", "LOCAL TEMPORARY", "GLOBAL TEMP",
	"LOCAL TEMP", "UNLOGGED", "TRANSIENT", "VOLATILE",
}

// TableKindText returns s when it is a CREATE TABLE kind modifier (TEMP,
// TEMPORARY, GLOBAL TEMPORARY, UNLOGGED, TRANSIENT, ...; any case) and ""
// otherwise.
func TableKindText(s string) string { return keywordOneOf(s, tableKindKeywords) }

// indexKindKeywords are the CREATE INDEX kinds the renderers write.
var indexKindKeywords = []string{
	"FULLTEXT", "SPATIAL", "BITMAP", "CLUSTERED", "NONCLUSTERED",
}

// IndexKindText returns s when it is a CREATE INDEX kind (FULLTEXT,
// SPATIAL, BITMAP, CLUSTERED, NONCLUSTERED; any case) and "" otherwise.
func IndexKindText(s string) string { return keywordOneOf(s, indexKindKeywords) }

// KeywordWordsText returns s when it is one or more upper-case words
// (letters, digits and '_') separated by single spaces, the shape the
// parser records for view modifiers and Oracle materialized-view BUILD /
// REFRESH clauses, and "" otherwise.
func KeywordWordsText(s string) string {
	if isKeywordWords(s) {
		return s
	}
	return ""
}

// ttlActionKeywords are the TTL rule actions the renderers write.
var ttlActionKeywords = []string{"DELETE", "TO DISK", "TO VOLUME"}

// TTLActionText returns s when it is a TTL rule action (DELETE, TO DISK,
// TO VOLUME; any case) and "" otherwise.
func TTLActionText(s string) string { return keywordOneOf(s, ttlActionKeywords) }

// clonePointKeywords are the Snowflake CLONE time-travel point kinds.
var clonePointKeywords = []string{"TIMESTAMP", "OFFSET", "STATEMENT", "STREAM"}

// isKeywordWords reports whether s is a sequence of upper-case words
// (letters, digits and '_') separated by single spaces.
func isKeywordWords(s string) bool {
	if s == "" || s[0] == ' ' || s[len(s)-1] == ' ' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
		case c == ' ' && s[i-1] != ' ':
		default:
			return false
		}
	}
	return true
}

// HasColumnList reports whether the statement is written with a
// parenthesized column list: always, unless it is one of the forms that
// take their columns from elsewhere (LIKE, CLONE, PARTITION OF, AS table,
// AS query) and declares none.
func (c *CreateTableStatement) HasColumnList() bool {
	if len(c.Columns) > 0 || len(c.Constraints) > 0 || len(c.PeriodDefinitions) > 0 {
		return true
	}
	return c.Like == "" && c.Clone == nil && c.PartitionOf == "" && c.AsTable == "" && c.AsQuery == nil
}

// resetTableOptions releases the expressions held by opts and clears every
// entry, keeping the backing array.
func resetTableOptions(opts []TableOption) []TableOption {
	for i := range opts {
		o := &opts[i]
		for j, a := range o.Args {
			PutExpression(a)
			o.Args[j] = nil
		}
		*o = TableOption{Args: o.Args[:0], Sub: o.Sub[:0]}
	}
	return opts[:0]
}

// releaseEngineClauses releases the expressions of e.
func releaseEngineClauses(e *TableEngineClauses) {
	if e == nil {
		return
	}
	PutExpression(e.PartitionBy)
	PutExpression(e.PrimaryKey)
	PutExpression(e.OrderBy)
	PutExpression(e.SampleBy)
	for i := range e.TTL {
		r := &e.TTL[i]
		PutExpression(r.Expr)
		PutExpression(r.Where)
		for _, g := range r.GroupBy {
			PutExpression(g)
		}
		for _, s := range r.Set {
			PutExpression(s.Value)
		}
	}
	for _, s := range e.Settings {
		PutExpression(s.Value)
	}
	*e = TableEngineClauses{}
}

// putExpressions releases every expression of list.
func putExpressions(list []Expression) {
	for _, e := range list {
		PutExpression(e)
	}
}

// resetCreateTableExtras releases the nodes held by x and clears it.
func resetCreateTableExtras(x *CreateTableExtras) {
	releaseStatement(x.AsQuery, releaseAll)
	if x.Clone != nil {
		PutExpression(x.Clone.Point)
	}
	if b := x.PartitionBound; b != nil {
		putExpressions(b.In)
		putExpressions(b.From)
		putExpressions(b.To)
		PutExpression(b.Modulus)
		PutExpression(b.Remainder)
	}
	releaseEngineClauses(x.Engine)
	*x = CreateTableExtras{}
}

// resetCreateIndexExtras releases the nodes held by x and clears it,
// keeping the slices' backing arrays.
func resetCreateIndexExtras(x *CreateIndexExtras) {
	*x = CreateIndexExtras{
		Include: x.Include[:0],
		Options: resetTableOptions(x.Options),
	}
}

// resetViewExtras releases the nodes held by x and clears it.
func resetViewExtras(x *ViewExtras) {
	for i := range x.ColumnDefs {
		for j := range x.ColumnDefs[i].Constraints {
			PutExpression(x.ColumnDefs[i].Constraints[j].Default)
			PutExpression(x.ColumnDefs[i].Constraints[j].Check)
		}
	}
	resetTableOptions(x.EngineOptions)
	releaseEngineClauses(x.Engine)
	*x = ViewExtras{}
}

// releasePartitionByExtras releases the expressions added to PartitionBy
// beyond its column list.
func releasePartitionByExtras(pb *PartitionBy) {
	putExpressions(pb.Expressions)
	PutExpression(pb.Partitions)
	PutExpression(pb.Interval)
	pb.Expressions = nil
	pb.Partitions = nil
	pb.Interval = nil
	pb.Linear = false
}
