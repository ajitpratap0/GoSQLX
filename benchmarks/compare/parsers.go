package compare

import (
	"fmt"
	"strings"

	chparser "github.com/AfterShip/clickhouse-sql-parser/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	gosqlxast "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	pgparser "github.com/auxten/postgresql-parser/pkg/sql/parser"
	dolt "github.com/dolthub/vitess/go/vt/sqlparser"
	pgquery "github.com/pganalyze/pg_query_go/v6"
	tidbparser "github.com/pingcap/tidb/pkg/parser"
	_ "github.com/pingcap/tidb/pkg/parser/test_driver" // value-expression driver required by the TiDB parser
	rqlite "github.com/rqlite/sql"
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
	// Legacy marks an unmaintained library kept for continuity. Legacy
	// parsers are benchmarked and listed in the acceptance table, but they do
	// not gate the common-accept sets.
	Legacy bool
	// Schema1 marks the parsers that the schema v1 fields (parsers, queries,
	// results) of the results JSON describe. The website reads those fields,
	// so peers added later appear only in the v2 fields until the website
	// opts in.
	Schema1 bool
	// License is the SPDX identifier (or description) of the library's
	// license, taken from the LICENSE file of the pinned version.
	License string
	// PeerDialects lists the corpus dialects (testdata/realworld/<dialect>)
	// this parser is a like-for-like peer for. Empty for GoSQLX, which
	// covers every dialect through NewDialect.
	PeerDialects []string
	// NewDialect returns a parse function for one corpus dialect. Only
	// GoSQLX sets it; every other library implements a single grammar.
	NewDialect func(dialect string) (ParseFunc, error)
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
		Schema1: true,
		License: "Apache-2.0",
		NewDialect: func(dialect string) (ParseFunc, error) {
			d := keywords.SQLDialect(dialect)
			return func(sql string) error {
				tree, err := gosqlx.ParseWithDialect(sql, d)
				if err != nil {
					return err
				}
				gosqlxast.ReleaseAST(tree)
				return nil
			}, nil
		},
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
		// Competitors do not release their ASTs. This variant skips
		// ReleaseAST so the cost of our release step is visible.
		ID:      "gosqlx_norelease",
		Name:    "GoSQLX (no ReleaseAST)",
		Module:  "github.com/ajitpratap0/GoSQLX",
		Dialect: "multi-dialect (default settings), AST left to the GC",
		License: "Apache-2.0",
		New: func() (ParseFunc, error) {
			return func(sql string) error {
				_, err := gosqlx.Parse(sql)
				return err
			}, nil
		},
	},
	{
		ID:           "pg_query_go",
		Name:         "pg_query_go",
		Module:       "github.com/pganalyze/pg_query_go/v6",
		Dialect:      "PostgreSQL (the real PostgreSQL grammar via CGo)",
		CGo:          true,
		Schema1:      true,
		License:      "BSD-3-Clause",
		PeerDialects: []string{"postgresql"},
		New: func() (ParseFunc, error) {
			return func(sql string) error {
				_, err := pgquery.Parse(sql)
				return err
			}, nil
		},
	},
	{
		ID:           "vitess",
		Name:         "Vitess sqlparser",
		Module:       "vitess.io/vitess",
		Dialect:      "MySQL",
		Schema1:      true,
		License:      "Apache-2.0",
		PeerDialects: []string{"mysql", "mariadb"},
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
		ID:           "tidb",
		Name:         "TiDB parser",
		Module:       "github.com/pingcap/tidb/pkg/parser",
		Dialect:      "MySQL (TiDB)",
		Schema1:      true,
		License:      "Apache-2.0",
		PeerDialects: []string{"mysql", "mariadb"},
		New: func() (ParseFunc, error) {
			p := tidbparser.New()
			return func(sql string) error {
				_, err := p.ParseOneStmt(sql, "", "")
				return err
			}, nil
		},
	},
	{
		ID:           "xwb1989",
		Name:         "xwb1989/sqlparser",
		Module:       "github.com/xwb1989/sqlparser",
		Dialect:      "MySQL (2018 Vitess fork, unmaintained)",
		Legacy:       true,
		Schema1:      true,
		License:      "Apache-2.0",
		PeerDialects: []string{"mysql", "mariadb"},
		New: func() (ParseFunc, error) {
			return func(sql string) error {
				_, err := xwb.Parse(sql)
				return err
			}, nil
		},
	},
}

func init() {
	Parsers = append(Parsers,
		Parser{
			ID:           "dolthub_vitess",
			Name:         "dolthub/vitess",
			Module:       "github.com/dolthub/vitess",
			Dialect:      "MySQL (Dolt's fork of Vitess, goyacc)",
			License:      "Apache-2.0",
			PeerDialects: []string{"mysql", "mariadb"},
			New: func() (ParseFunc, error) {
				return func(sql string) error {
					_, err := dolt.Parse(sql)
					return err
				}, nil
			},
		},
		Parser{
			ID:           "rqlite_sql",
			Name:         "rqlite/sql",
			Module:       "github.com/rqlite/sql",
			Dialect:      "SQLite (hand-written parser)",
			License:      "MIT",
			PeerDialects: []string{"sqlite"},
			New: func() (ParseFunc, error) {
				return func(sql string) error {
					p := rqlite.NewParser(strings.NewReader(sql))
					_, err := p.ParseStatement()
					return err
				}, nil
			},
		},
		Parser{
			ID:           "aftership_clickhouse",
			Name:         "AfterShip/clickhouse-sql-parser",
			Module:       "github.com/AfterShip/clickhouse-sql-parser",
			Dialect:      "ClickHouse (hand-written parser)",
			License:      "MIT",
			PeerDialects: []string{"clickhouse"},
			New: func() (ParseFunc, error) {
				return func(sql string) error {
					_, err := chparser.NewParser(sql).ParseStmts()
					return err
				}, nil
			},
		},
		Parser{
			ID:      "auxten_pg",
			Name:    "auxten/postgresql-parser",
			Module:  "github.com/auxten/postgresql-parser",
			Dialect: "PostgreSQL (CockroachDB parser, extracted)",
			// The module LICENSE says "variously licensed": parse.go carries
			// BSD (Vitess) plus Cockroach BSL 1.1 headers. See README.
			License:      "mixed: BSL-1.1 / CCL / MIT / BSD (see README before redistributing or quoting)",
			PeerDialects: []string{"postgresql"},
			New: func() (ParseFunc, error) {
				return func(sql string) error {
					_, err := pgparser.Parse(sql)
					return err
				}, nil
			},
		},
	)
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
