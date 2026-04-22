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

package gosqlx

import (
	"context"
	"errors"
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Tree is an opaque handle to a parsed SQL AST. It is the recommended entry
// point for new code: by going through Tree instead of the raw *ast.AST,
// callers gain access to high-level helpers (Walk, Tables, Columns, Functions,
// Format) without having to import the internal AST package, and the library
// retains the freedom to evolve AST internals without breaking consumers.
//
// A *ast.AST escape hatch is still available via Raw() for power users who
// need node-level access.
//
// Tree values are safe to use from a single goroutine. Share across goroutines
// only for read-only inspection (Walk / Tables / Format). Concurrent mutation
// through Raw() is not supported.
type Tree struct {
	ast *ast.AST
	sql string // original source for error context / round-trip format
}

// Raw returns the underlying *ast.AST. It is an escape hatch for callers that
// need direct node access; prefer the Tree methods (Walk, Tables, Columns,
// Functions, Format) for forward compatibility.
//
// The returned AST is owned by the Tree — do not call ast.ReleaseAST on it
// directly. Use Tree.Release instead.
func (t *Tree) Raw() *ast.AST {
	if t == nil {
		return nil
	}
	return t.ast
}

// Statements returns the top-level AST statements. This is a power-user escape
// hatch used when callers want to switch on concrete statement types. For
// generic traversal prefer Walk.
//
// The returned slice aliases the underlying AST storage — do not mutate it.
func (t *Tree) Statements() []ast.Statement {
	if t == nil || t.ast == nil {
		return nil
	}
	return t.ast.Statements
}

// SQL returns the original SQL source that produced this Tree. This is the
// unmodified caller input, useful for error context and debugging.
func (t *Tree) SQL() string {
	if t == nil {
		return ""
	}
	return t.sql
}

// Walk traverses every node in the tree in depth-first, pre-order fashion.
// The visitor function is invoked for each node. Return true to descend into
// children, false to skip the current subtree.
//
// Walk correctly descends into nested SELECTs, CTEs, subqueries, UNION arms,
// and every other position where an ast.Node appears as a child, because it
// delegates to ast.Inspect which follows the Children() contract.
//
// Example — collect every identifier, including those inside subqueries:
//
//	var idents []string
//	tree.Walk(func(n ast.Node) bool {
//	    if id, ok := n.(*ast.Identifier); ok {
//	        idents = append(idents, id.Name)
//	    }
//	    return true
//	})
func (t *Tree) Walk(fn func(ast.Node) bool) {
	if t == nil || t.ast == nil || fn == nil {
		return
	}
	// ast.Inspect traverses via the Node.Children() contract, which has been
	// audited (C6) to cover every reachable subtree position.
	ast.Inspect(t.ast, fn)
}

// Tables returns the deduplicated list of table names referenced anywhere in
// the tree, including inside subqueries and CTEs. Delegates to ExtractTables
// for consistency with the existing top-level helper.
func (t *Tree) Tables() []string {
	if t == nil {
		return nil
	}
	return ExtractTables(t.ast)
}

// Columns returns the deduplicated list of column names referenced anywhere
// in the tree. Delegates to ExtractColumns.
func (t *Tree) Columns() []string {
	if t == nil {
		return nil
	}
	return ExtractColumns(t.ast)
}

// Functions returns the deduplicated list of function names called anywhere
// in the tree. Delegates to ExtractFunctions.
func (t *Tree) Functions() []string {
	if t == nil {
		return nil
	}
	return ExtractFunctions(t.ast)
}

// Format renders the Tree back to SQL text using the AST-based formatter.
// Unlike the top-level Format(sql, opts) function, this method does not
// re-tokenize or re-parse — it walks the already-parsed AST, so it is both
// faster and guaranteed to match the parsed structure.
//
// Pass zero or more FormatOption values to customize indent width and keyword
// casing; see WithIndent and WithUppercaseKeywords.
func (t *Tree) Format(opts ...FormatOption) string {
	if t == nil || t.ast == nil {
		return ""
	}
	return FormatAST(t.ast, opts...)
}

// Release returns any pooled resources associated with the tree. It is
// currently a best-effort no-op: Tree does not own pooled resources because
// the underlying *ast.AST lifetime is caller-driven (power users can still
// retrieve Raw()). Calling Release makes your code forward-compatible with
// future versions that may adopt explicit Tree-level pooling.
func (t *Tree) Release() {
	// Intentionally no-op. See doc comment.
	_ = t
}

// Rewrite applies pre and post transformation passes to each top-level
// Statement in the tree. pre runs before any children are considered; post
// runs after. Either may be nil to skip that pass. The return value of each
// function replaces the statement in the tree; returning the same node is the
// no-op case.
//
// SCOPE — Rewrite operates at Statement granularity only. Deeper rewrites
// (e.g., replacing an expression inside a WHERE clause) require walking the
// AST via Raw() and mutating the concrete struct fields directly. This is a
// deliberate design choice: the AST contains ~100 concrete node types with
// heterogeneous child-field layouts; a generic deep-rewrite API would require
// either reflection (slow, easy to misuse) or an exhaustive per-type switch
// (maintenance burden). Until there is a clear user need we prefer the honest
// narrow API over a permissive one that silently misses cases.
//
// Example — drop every DeleteStatement from a batch:
//
//	tree.Rewrite(nil, func(s ast.Statement) ast.Statement {
//	    if _, ok := s.(*ast.DeleteStatement); ok {
//	        return nil // filtered out
//	    }
//	    return s
//	})
//
// A nil return from pre or post drops the statement from the tree. Rewrite
// mutates t in place; call Clone() first to preserve the original.
//
// For intra-statement rewrites, combine Tree.WalkSelects / WalkBinaryExpressions
// / etc. with direct field assignment on the visited node. Because the walkers
// return pointers, any field you assign to is visible to subsequent reads
// through the same Tree.
func (t *Tree) Rewrite(pre, post func(ast.Statement) ast.Statement) {
	if t == nil || t.ast == nil {
		return
	}
	src := t.ast.Statements
	out := src[:0] // reuse backing array; final statements only appear once
	for _, s := range src {
		cur := s
		if pre != nil {
			cur = pre(cur)
			if cur == nil {
				continue
			}
		}
		if post != nil {
			cur = post(cur)
			if cur == nil {
				continue
			}
		}
		out = append(out, cur)
	}
	// Zero-out any trailing aliases so the GC can reclaim dropped statements.
	for i := len(out); i < len(src); i++ {
		src[i] = nil
	}
	t.ast.Statements = out
}

// Clone returns an independent deep copy of the tree. Mutations to the
// original (via Raw(), WalkSelects field writes, Rewrite, ...) do not affect
// the clone, and vice versa.
//
// IMPLEMENTATION — Clone is implemented by re-parsing t.SQL() with default
// options. This is simple and provably correct: the clone has exactly the
// structure the parser would produce today for the original source, which is
// the strongest possible guarantee of independence. The tradeoff is cost —
// Clone is O(parse) rather than O(nodes), and a clone of a tree that was
// produced with a non-default dialect / recovery mode will not preserve those
// parse options. For cases where either matters, hold onto the SQL string and
// call ParseTree yourself with the desired options.
//
// Clone returns nil if the receiver is nil, the original SQL is empty, or
// the re-parse fails (which would indicate a parser regression since the
// original SQL was known to parse successfully when t was constructed).
func (t *Tree) Clone() *Tree {
	if t == nil || t.sql == "" {
		return nil
	}
	cloned, err := ParseTree(context.Background(), t.sql)
	if err != nil {
		return nil
	}
	return cloned
}

// ParseTree parses SQL and returns an opaque Tree, the recommended entry
// point for new code. Configuration is supplied via functional options
// (WithDialect, WithStrict, WithTimeout, WithRecovery) rather than through
// the combinatorial ParseWithX helpers on the top-level API surface.
//
// Context handling:
//   - If ctx is nil, context.Background is used.
//   - WithTimeout(d) installs a deadline when ctx has none; an existing
//     earlier deadline on ctx wins.
//
// Error handling: returned errors are wrapped with sentinel values —
// ErrTokenize, ErrSyntax, ErrTimeout, ErrUnsupportedDialect — so callers can
// match with errors.Is. The underlying structured *errors.Error remains
// reachable via errors.As or the ErrorCode / ErrorLocation / ErrorHint
// helpers in this package.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
//	defer cancel()
//	tree, err := gosqlx.ParseTree(ctx, sql,
//	    gosqlx.WithDialect("postgresql"),
//	)
//	if err != nil {
//	    return err
//	}
//	for _, tbl := range tree.Tables() {
//	    ...
//	}
func ParseTree(ctx context.Context, sql string, opts ...Option) (*Tree, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg := applyOptions(opts)

	if cfg.timeout > 0 {
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, cfg.timeout)
			defer cancel()
		}
	}

	// Fail fast if the caller's context is already cancelled or expired.
	if err := ctx.Err(); err != nil {
		return nil, wrapContextErr(err)
	}

	astNode, err := parseWithConfig(ctx, sql, cfg)
	if err != nil {
		return nil, err
	}
	return &Tree{ast: astNode, sql: sql}, nil
}

// parseWithConfig is the shared implementation used by ParseTree and
// ParseReader. It resolves dialect, strict mode, and recovery, then drives
// the tokenizer and parser with the supplied context.
func parseWithConfig(ctx context.Context, sql string, cfg parseOptions) (*ast.AST, error) {
	// Validate the dialect up front so we return a well-typed sentinel rather
	// than a free-form error from deeper layers.
	if cfg.dialect != "" && !keywords.IsValidDialect(cfg.dialect) {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedDialect, cfg.dialect)
	}

	var (
		tokens []models.TokenWithSpan
		tokErr error
	)
	if cfg.dialect != "" {
		// Dialect-aware tokenizer cannot currently be obtained from the
		// shared pool; this matches existing ParseBytesWithDialect behaviour.
		tkz, err := tokenizer.NewWithDialect(keywords.SQLDialect(cfg.dialect))
		if err != nil {
			return nil, fmt.Errorf("%w: tokenizer init: %v", ErrTokenize, err)
		}
		tokens, tokErr = tkz.TokenizeContext(ctx, []byte(sql))
	} else {
		tkz := tokenizer.GetTokenizer()
		defer tokenizer.PutTokenizer(tkz)
		tokens, tokErr = tkz.TokenizeContext(ctx, []byte(sql))
	}
	if tokErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, wrapContextErr(ctxErr)
		}
		return nil, fmt.Errorf("%w: %w", ErrTokenize, tokErr)
	}

	p := parser.GetParser()
	defer parser.PutParser(p)
	if cfg.strict {
		p.ApplyOptions(parser.WithStrictMode())
	}
	if cfg.dialect != "" {
		p.ApplyOptions(parser.WithDialect(cfg.dialect))
	}

	if cfg.recover {
		stmts, errs := p.ParseWithRecoveryFromModelTokens(tokens)
		if len(errs) > 0 {
			// Join all diagnostics but surface them under ErrSyntax so
			// errors.Is(err, ErrSyntax) still matches.
			joined := errors.Join(errs...)
			return &ast.AST{Statements: stmts}, fmt.Errorf("%w: %w", ErrSyntax, joined)
		}
		return &ast.AST{Statements: stmts}, nil
	}

	astNode, err := p.ParseContextFromModelTokens(ctx, tokens)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, wrapContextErr(ctxErr)
		}
		return nil, fmt.Errorf("%w: %w", ErrSyntax, err)
	}
	return astNode, nil
}

// wrapContextErr returns the context error wrapped in ErrTimeout so callers
// can test errors.Is(err, ErrTimeout). context.DeadlineExceeded and
// context.Canceled both flow through this helper.
func wrapContextErr(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrTimeout, err)
}

// ─── Format options on the new top-level API ──────────────────────────────

// FormatOption configures the AST-based formatter exposed by FormatTree and
// FormatAST. Options are applied in order; later options override earlier
// ones when they touch the same field.
//
// See WithIndent, WithUppercaseKeywords.
type FormatOption func(*formatOptions)

// formatOptions is the internal config bag applied by FormatOption.
type formatOptions struct {
	indentWidth       int
	uppercaseKeywords bool
	keywordCaseSet    bool
}

// defaultFormatOptions returns sane formatter defaults: two-space indent,
// preserve original keyword case. These match the existing DefaultFormatOptions
// shape used by the legacy Format function.
func defaultFormatOptions() formatOptions {
	return formatOptions{
		indentWidth: 2,
	}
}

// WithIndent sets the number of spaces per indent level. Pass 0 for compact
// output (no indentation, single line). Negative values are clamped to 0.
func WithIndent(size int) FormatOption {
	if size < 0 {
		size = 0
	}
	return func(o *formatOptions) {
		o.indentWidth = size
	}
}

// WithUppercaseKeywords controls whether SQL keywords are uppercased in the
// formatted output. When false, keyword case is preserved as emitted by the
// AST formatter's default (which itself preserves the original parsed case).
func WithUppercaseKeywords(on bool) FormatOption {
	return func(o *formatOptions) {
		o.uppercaseKeywords = on
		o.keywordCaseSet = true
	}
}

// buildASTFormatOptions translates the public FormatOption surface into the
// concrete ast.FormatOptions the formatter consumes.
func buildASTFormatOptions(opts []FormatOption) ast.FormatOptions {
	cfg := defaultFormatOptions()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&cfg)
	}

	kwCase := ast.KeywordPreserve
	if cfg.keywordCaseSet && cfg.uppercaseKeywords {
		kwCase = ast.KeywordUpper
	}

	return ast.FormatOptions{
		IndentStyle:      ast.IndentSpaces,
		IndentWidth:      cfg.indentWidth,
		KeywordCase:      kwCase,
		LineWidth:        0,
		NewlinePerClause: cfg.indentWidth > 0,
		AddSemicolon:     false,
	}
}

// FormatTree renders a Tree back to SQL text using the AST-based formatter.
// It does not re-tokenize or re-parse; if you already have a Tree, prefer
// this over the top-level Format(sql, opts) function.
func FormatTree(t *Tree, opts ...FormatOption) string {
	if t == nil || t.ast == nil {
		return ""
	}
	return FormatAST(t.ast, opts...)
}

// FormatAST renders a raw *ast.AST back to SQL text. This is the escape-hatch
// equivalent of FormatTree for callers that hold the underlying AST directly
// (e.g., from the low-level parser API). Internally it delegates to
// pkg/formatter.FormatAST — it does not re-parse.
func FormatAST(a *ast.AST, opts ...FormatOption) string {
	if a == nil {
		return ""
	}
	astOpts := buildASTFormatOptions(opts)
	return formatter.FormatAST(a, astOpts)
}
