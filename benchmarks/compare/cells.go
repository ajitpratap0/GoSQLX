package compare

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/internal/tokscratch"
	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
	pgquery "github.com/pganalyze/pg_query_go/v6"
	tidbparser "github.com/pingcap/tidb/pkg/parser"
	"github.com/pingcap/tidb/pkg/parser/format"
	vitess "vitess.io/vitess/go/vt/sqlparser"
)

// Op is one timed operation. It must be safe to call repeatedly from one
// goroutine and must do the same work every time.
type Op func() error

// Impl is one library's implementation of a benchmark cell other than Parse
// (Lex, Normalize, Render). The cell name lives in the registry that holds it.
type Impl struct {
	// ID is a stable identifier used in benchmark names and the results JSON.
	ID string
	// Name is the display name.
	Name string
	// Parser is the ID of the Parsers entry this implementation belongs to.
	Parser string
	// Note states what the operation does and where it is not like for like.
	Note string
	// New prepares the operation for one SQL text. Setup (parsing the input
	// of a render, building a tokenizer) happens here, outside the timed
	// loop. An error means the library cannot handle this text and the
	// benchmark is skipped.
	//
	// The returned cleanup function, if non-nil, releases anything New
	// acquired (a pooled tokenizer, say); callers run it when the benchmark
	// or test is done.
	New func(sql string) (Op, func(), error)
}

// LexImpls are the tokenizer-only cells: BenchmarkLex/<q>/<impl>.
var LexImpls = []Impl{
	{
		ID: "gosqlx_scratch", Name: "GoSQLX tokenizer (scratch path)", Parser: "gosqlx",
		Note: "The path gosqlx.Parse uses: pooled tokenizer, tokens in its scratch buffer.",
		New: func(sql string) (Op, func(), error) {
			tkz := tokenizer.GetTokenizer()
			return func() error {
				_, err := tokscratch.String(tkz, sql)
				return err
			}, func() { tokenizer.PutTokenizer(tkz) }, nil
		},
	},
	{
		ID: "gosqlx_public", Name: "GoSQLX tokenizer (public path)", Parser: "gosqlx",
		Note: "Tokenizer.TokenizeString: returns a caller-owned token slice.",
		New: func(sql string) (Op, func(), error) {
			tkz := tokenizer.GetTokenizer()
			return func() error {
				_, err := tkz.TokenizeString(sql)
				return err
			}, func() { tokenizer.PutTokenizer(tkz) }, nil
		},
	},
	{
		ID: "vitess", Name: "Vitess Tokenizer.Scan", Parser: "vitess",
		Note: "Scan loop to EOF; tokens are not retained.",
		New: func(sql string) (Op, func(), error) {
			p, err := vitess.New(vitess.Options{})
			if err != nil {
				return nil, nil, fmt.Errorf("vitess: new parser: %w", err)
			}
			return func() error {
				tkn := p.NewStringTokenizer(sql)
				for {
					if typ, _ := tkn.Scan(); typ == 0 {
						return nil
					}
				}
			}, nil, nil
		},
	},
	{
		ID: "pgquery_scan", Name: "pg_query_go Scan", Parser: "pg_query_go",
		Note: "Real PostgreSQL scanner through CGo; result is converted to protobuf.",
		New: func(sql string) (Op, func(), error) {
			return func() error {
				_, err := pgquery.Scan(sql)
				return err
			}, nil, nil
		},
	},
}

// NormalizeImpls are the literal-normalisation cells:
// BenchmarkNormalize/<q>/<impl>. The outputs differ in form (placeholders,
// digests, fingerprints), so the numbers compare cost, not identical output.
// A token-mode GoSQLX normaliser does not exist yet; add gosqlx_tokens here
// when it lands.
var NormalizeImpls = []Impl{
	{
		ID: "gosqlx", Name: "GoSQLX Normalize", Parser: "gosqlx",
		Note: "Parse, replace literals with placeholders, render.",
		New: func(sql string) (Op, func(), error) {
			if _, err := gosqlx.Normalize(sql); err != nil {
				return nil, nil, err
			}
			return func() error { _, err := gosqlx.Normalize(sql); return err }, nil, nil
		},
	},
	{
		ID: "gosqlx_fingerprint", Name: "GoSQLX Fingerprint", Parser: "gosqlx",
		Note: "Normalize then hash.",
		New: func(sql string) (Op, func(), error) {
			if _, err := gosqlx.Fingerprint(sql); err != nil {
				return nil, nil, err
			}
			return func() error { _, err := gosqlx.Fingerprint(sql); return err }, nil, nil
		},
	},
	{
		ID: "tidb_digest", Name: "TiDB NormalizeDigest", Parser: "tidb",
		Note: "Token-level normalisation plus SHA-256 digest; no AST.",
		New: func(sql string) (Op, func(), error) {
			return func() error { _, _ = tidbparser.NormalizeDigest(sql); return nil }, nil, nil
		},
	},
	{
		ID: "pgquery_normalize", Name: "pg_query_go Normalize", Parser: "pg_query_go",
		Note: "Real PostgreSQL normaliser through CGo.",
		New: func(sql string) (Op, func(), error) {
			if _, err := pgquery.Normalize(sql); err != nil {
				return nil, nil, err
			}
			return func() error { _, err := pgquery.Normalize(sql); return err }, nil, nil
		},
	},
	{
		ID: "pgquery_fingerprint", Name: "pg_query_go Fingerprint", Parser: "pg_query_go",
		Note: "Real PostgreSQL fingerprint through CGo.",
		New: func(sql string) (Op, func(), error) {
			if _, err := pgquery.Fingerprint(sql); err != nil {
				return nil, nil, err
			}
			return func() error { _, err := pgquery.Fingerprint(sql); return err }, nil, nil
		},
	},
	{
		ID: "vitess_redact", Name: "Vitess RedactSQLQuery", Parser: "vitess",
		Note: "Parse, replace literals with bind variables, render.",
		New: func(sql string) (Op, func(), error) {
			p, err := vitess.New(vitess.Options{})
			if err != nil {
				return nil, nil, fmt.Errorf("vitess: new parser: %w", err)
			}
			if _, err := p.RedactSQLQuery(sql); err != nil {
				return nil, nil, err
			}
			return func() error { _, err := p.RedactSQLQuery(sql); return err }, nil, nil
		},
	},
}

// RenderImpls are the AST-to-SQL cells: BenchmarkRender/<q>/<impl>. The input
// is parsed once during setup; only the render is timed.
var RenderImpls = []Impl{
	{
		ID: "gosqlx_sql", Name: "GoSQLX AST.SQL", Parser: "gosqlx",
		Note: "Canonical SQL() rendering of the parsed AST.",
		New: func(sql string) (Op, func(), error) {
			tree, err := gosqlx.Parse(sql)
			if err != nil {
				return nil, nil, err
			}
			return func() error { _ = tree.SQL(); return nil }, nil, nil
		},
	},
	{
		ID: "gosqlx_compact", Name: "GoSQLX AST.Format (compact)", Parser: "gosqlx",
		Note: "Single-line formatter output (ast.CompactStyle).",
		New: func(sql string) (Op, func(), error) {
			tree, err := gosqlx.Parse(sql)
			if err != nil {
				return nil, nil, err
			}
			opts := ast.CompactStyle()
			return func() error {
				_, err := formatter.FormatASTChecked(tree, opts)
				return err
			}, nil, nil
		},
	},
	{
		ID: "vitess_string", Name: "Vitess sqlparser.String", Parser: "vitess",
		Note: "Canonical rendering of a parsed statement.",
		New: func(sql string) (Op, func(), error) {
			p, err := vitess.New(vitess.Options{})
			if err != nil {
				return nil, nil, fmt.Errorf("vitess: new parser: %w", err)
			}
			stmt, err := p.ParseStrictDDL(sql)
			if err != nil {
				return nil, nil, err
			}
			return func() error { _ = vitess.String(stmt); return nil }, nil, nil
		},
	},
	{
		ID: "tidb_restore", Name: "TiDB Restore", Parser: "tidb",
		Note: "Node.Restore with default flags into a strings.Builder.",
		New: func(sql string) (Op, func(), error) {
			stmt, err := tidbparser.New().ParseOneStmt(sql, "", "")
			if err != nil {
				return nil, nil, err
			}
			return func() error {
				var sb strings.Builder
				return stmt.Restore(format.NewRestoreCtx(format.DefaultRestoreFlags, &sb))
			}, nil, nil
		},
	},
	{
		ID: "pgquery_deparse", Name: "pg_query_go Deparse", Parser: "pg_query_go",
		Note: "Parse tree back to SQL through CGo (protobuf in, text out).",
		New: func(sql string) (Op, func(), error) {
			tree, err := pgquery.Parse(sql)
			if err != nil {
				return nil, nil, err
			}
			if _, err := pgquery.Deparse(tree); err != nil {
				return nil, nil, err
			}
			return func() error { _, err := pgquery.Deparse(tree); return err }, nil, nil
		},
	},
}
