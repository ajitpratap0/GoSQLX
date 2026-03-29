// Package gosqlxgorm provides a GORM plugin that parses each executed query
// with GoSQLX and records extracted metadata (tables, columns, statement type).
package gosqlxgorm

import (
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"gorm.io/gorm"
)

// reQuestionMark replaces GORM's ? positional placeholders.
var reQuestionMark = regexp.MustCompile(`\?`)

// QueryRecord holds metadata about a single recorded GORM query.
type QueryRecord struct {
	SQL     string
	Tables  []string
	Columns []string
	Type    string // SELECT, INSERT, UPDATE, DELETE, ...
	ParseOK bool
}

// PluginStats is the aggregate of all queries observed since initialization.
type PluginStats struct {
	TotalQueries int
	ParseErrors  int
	Queries      []QueryRecord
}

// defaultMaxHistory is the default maximum number of query records kept.
const defaultMaxHistory = 1000

// PluginOptions configures the GORM plugin behavior.
type PluginOptions struct {
	// MaxHistory limits the number of query records kept. Zero uses the default (1000).
	MaxHistory int
	// OnParseError is called when GoSQLX fails to parse a query. Optional.
	OnParseError func(sql string, err error)
}

// Plugin is a GORM plugin that parses each executed query with GoSQLX
// and records extracted metadata (tables, columns, statement type).
type Plugin struct {
	mu           sync.Mutex
	queries      []QueryRecord
	maxHistory   int
	onParseError func(sql string, err error)
}

// NewPlugin returns a new GoSQLX GORM plugin with default options.
func NewPlugin() *Plugin {
	return &Plugin{maxHistory: defaultMaxHistory}
}

// NewPluginWithOptions returns a new GoSQLX GORM plugin configured with opts.
func NewPluginWithOptions(opts PluginOptions) *Plugin {
	mh := opts.MaxHistory
	if mh <= 0 {
		mh = defaultMaxHistory
	}
	return &Plugin{
		maxHistory:   mh,
		onParseError: opts.OnParseError,
	}
}

// Name implements gorm.Plugin.
func (p *Plugin) Name() string { return "gosqlx" }

// Initialize implements gorm.Plugin by registering after-callbacks.
func (p *Plugin) Initialize(db *gorm.DB) error {
	db.Callback().Query().After("gorm:query").Register("gosqlx:after_query", p.afterStatement)
	db.Callback().Create().After("gorm:create").Register("gosqlx:after_create", p.afterStatement)
	db.Callback().Update().After("gorm:update").Register("gosqlx:after_update", p.afterStatement)
	db.Callback().Delete().After("gorm:delete").Register("gosqlx:after_delete", p.afterStatement)
	db.Callback().Raw().After("gorm:raw").Register("gosqlx:after_raw", p.afterStatement)
	return nil
}

func (p *Plugin) afterStatement(db *gorm.DB) {
	// Guard against nil Statement — this can happen during initialization callbacks.
	if db.Statement == nil {
		return
	}
	sql := db.Statement.SQL.String()
	if sql == "" {
		return
	}

	rec := QueryRecord{SQL: sql}

	// Normalize GORM-generated SQL for GoSQLX compatibility:
	//   1. Replace backtick-quoted identifiers with double-quoted identifiers
	//      (GORM SQLite/MySQL driver uses backticks; GoSQLX standard mode uses double-quotes).
	//   2. Replace ? positional placeholders with $N (PostgreSQL style).
	normalized := normalizeSQLForParsing(sql)

	// Try PostgreSQL dialect (handles double-quoted identifiers and $N placeholders),
	// then fall back to standard SQL parsing.
	tree, err := gosqlx.ParseWithDialect(normalized, keywords.DialectPostgreSQL)
	if err != nil {
		tree, err = gosqlx.Parse(normalized)
	}
	if err != nil {
		rec.ParseOK = false
		if p.onParseError != nil {
			p.onParseError(sql, err)
		}
	} else {
		rec.ParseOK = true
		rec.Tables = gosqlx.ExtractTables(tree)
		rec.Columns = gosqlx.ExtractColumns(tree)
		if tree != nil && len(tree.Statements) > 0 {
			rec.Type = stmtTypeName(tree.Statements[0])
		}
	}

	p.mu.Lock()
	p.queries = append(p.queries, rec)
	if len(p.queries) > p.maxHistory {
		// Trim oldest entries to stay within the limit.
		excess := len(p.queries) - p.maxHistory
		copy(p.queries, p.queries[excess:])
		p.queries = p.queries[:p.maxHistory]
	}
	p.mu.Unlock()
}

// normalizeSQLForParsing converts GORM-generated SQL into a form that GoSQLX
// can parse: backtick identifiers become double-quoted, and ? placeholders
// become $N placeholders.
func normalizeSQLForParsing(sql string) string {
	// Replace backtick-quoted identifiers with double-quoted identifiers.
	sql = strings.ReplaceAll(sql, "`", "\"")
	// Replace ? positional placeholders with $N.
	n := 0
	sql = reQuestionMark.ReplaceAllStringFunc(sql, func(string) string {
		n++
		return "$" + strconv.Itoa(n)
	})
	return sql
}

// Stats returns a snapshot of all recorded queries.
func (p *Plugin) Stats() PluginStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	var errCount int
	for _, q := range p.queries {
		if !q.ParseOK {
			errCount++
		}
	}
	qs := make([]QueryRecord, len(p.queries))
	copy(qs, p.queries)
	return PluginStats{
		TotalQueries: len(p.queries),
		ParseErrors:  errCount,
		Queries:      qs,
	}
}

// Reset clears all recorded queries.
func (p *Plugin) Reset() {
	p.mu.Lock()
	p.queries = p.queries[:0]
	p.mu.Unlock()
}

// stmtTypeName returns a human-readable SQL statement type name.
func stmtTypeName(stmt ast.Statement) string {
	switch stmt.(type) {
	case *ast.SelectStatement:
		return "SELECT"
	case *ast.InsertStatement:
		return "INSERT"
	case *ast.UpdateStatement:
		return "UPDATE"
	case *ast.DeleteStatement:
		return "DELETE"
	default:
		return "OTHER"
	}
}
