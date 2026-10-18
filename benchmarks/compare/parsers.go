package compare

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	gosqlxast "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	pgquery "github.com/pganalyze/pg_query_go/v6"
	tidbparser "github.com/pingcap/tidb/pkg/parser"
	_ "github.com/pingcap/tidb/pkg/parser/test_driver" // value-expression driver required by the TiDB parser
	xwb "github.com/xwb1989/sqlparser"
	vitess "vitess.io/vitess/go/vt/sqlparser"
)

// Parser describes one library under test.
type Parser struct {
	// ID is a stable identifier used in benchmark names and the results JSON.
	ID string
	// Name is the display name.
	Name string
	// Module is the Go module path; its pinned version comes from go.mod.
	Module string
	// Dialect is the grammar the library implements.
	Dialect string
	// CGo reports whether the library needs a C toolchain.
	CGo bool
	// New returns a parse function. Libraries whose documented usage is a
	// reusable parser instance create it here, once, outside the timed loop.
	// A parse function is not safe for concurrent use.
	New func() (ParseFunc, error)
}

// ParseFunc parses one SQL statement into the library's AST and discards it.
type ParseFunc func(sql string) error

// Parsers lists every library under test, GoSQLX first.
var Parsers = []Parser{
	{
		ID:      "gosqlx",
		Name:    "GoSQLX",
		Module:  "github.com/ajitpratap0/GoSQLX",
		Dialect: "multi-dialect (default settings)",
		New: func() (ParseFunc, error) {
			return func(sql string) error {
				tree, err := gosqlx.Parse(sql)
				if err != nil {
					return err
				}
				// Return the AST to its pool, as performance-sensitive callers do.
				gosqlxast.ReleaseAST(tree)
				return nil
			}, nil
		},
	},
	{
		ID:      "pg_query_go",
		Name:    "pg_query_go",
		Module:  "github.com/pganalyze/pg_query_go/v6",
		Dialect: "PostgreSQL (the real PostgreSQL grammar via CGo)",
		CGo:     true,
		New: func() (ParseFunc, error) {
			return func(sql string) error {
				_, err := pgquery.Parse(sql)
				return err
			}, nil
		},
	},
	{
		ID:      "vitess",
		Name:    "Vitess sqlparser",
		Module:  "vitess.io/vitess",
		Dialect: "MySQL",
		New: func() (ParseFunc, error) {
			p, err := vitess.New(vitess.Options{})
			if err != nil {
				return nil, fmt.Errorf("vitess: new parser: %w", err)
			}
			return func(sql string) error {
				_, err := p.Parse(sql)
				return err
			}, nil
		},
	},
	{
		ID:      "tidb",
		Name:    "TiDB parser",
		Module:  "github.com/pingcap/tidb/pkg/parser",
		Dialect: "MySQL (TiDB)",
		New: func() (ParseFunc, error) {
			p := tidbparser.New()
			return func(sql string) error {
				_, err := p.ParseOneStmt(sql, "", "")
				return err
			}, nil
		},
	},
	{
		ID:      "xwb1989",
		Name:    "xwb1989/sqlparser",
		Module:  "github.com/xwb1989/sqlparser",
		Dialect: "MySQL (2018 Vitess fork, unmaintained)",
		New: func() (ParseFunc, error) {
			return func(sql string) error {
				_, err := xwb.Parse(sql)
				return err
			}, nil
		},
	},
}

// ParserByID returns the parser with the given ID.
func ParserByID(id string) (Parser, bool) {
	for _, p := range Parsers {
		if p.ID == id {
			return p, true
		}
	}
	return Parser{}, false
}

// Supports reports whether p accepts q, returning the parse error otherwise.
func Supports(p Parser, q Query) error {
	parse, err := p.New()
	if err != nil {
		return err
	}
	return parse(q.SQL)
}
