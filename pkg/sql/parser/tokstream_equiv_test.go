// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

// Differential harness for parser-ready token streams (W3-03).
//
// A parser-ready stream is what the parser consumes: compound keywords split
// into their parts, identifier and keyword types remapped, COUNT..MAX turned
// into identifiers, delimited identifiers marked. Today it is produced by
// tokenizing and then running the preprocess pass. The harness compares two
// producers of such streams on one shared input list, field for field:
//
//   - W3-03a1 (this change): the preprocess pass, now a loop over
//     internal/tokclass, against legacyPreprocess, a frozen copy of the pass
//     from before the move (legacy_preprocess_test.go). Equality proves the
//     move is a pure refactor.
//   - W3-03b plugs in the tokenizer's parser-ready mode as the producer under
//     test, with preprocess(Tokenize(sql)) as the expected stream, through the
//     same runEquivalence, inputs and comparator.
//
// Equality (diffStreams) is exact: Type, Value, Long, Quote, Start and End of
// every token; Word by content (nil-ness, Value, QuoteStyle, Keyword) rather
// than pointer; the captured comments; and the error (text, structured code,
// location and hint, and the context sentinel it wraps).

package parser_test

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	goparser "go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/internal/tokclass"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// tokStream is one producer's result for one input. It owns everything it
// references: tokens and their Words are deep copies, so a stream stays valid
// after the tokenizer that produced it is reused or returned to the pool.
type tokStream struct {
	Tokens   []models.TokenWithSpan
	Comments []models.Comment
	Err      error
}

// ownStream deep-copies a tokenizer result (tokens may be borrowed from the
// tokenizer's scratch buffer and Words from its slab).
func ownStream(toks []models.TokenWithSpan, comments []models.Comment, err error) tokStream {
	s := tokStream{Err: err}
	if toks != nil {
		s.Tokens = make([]models.TokenWithSpan, len(toks))
		for i, t := range toks {
			if t.Token.Word != nil {
				w := *t.Token.Word
				if w.Keyword != nil {
					k := *w.Keyword
					w.Keyword = &k
				}
				t.Token.Word = &w
			}
			s.Tokens[i] = t
		}
	}
	if len(comments) > 0 {
		s.Comments = slices.Clone(comments)
	}
	return s
}

// equivInput is one harness input. newCtx, when set, makes the producer use
// the context-aware tokenizer entry point with a fresh context per run.
type equivInput struct {
	name    string
	dialect keywords.SQLDialect
	sql     string
	newCtx  func() context.Context
}

// producer turns one input into a parser-ready stream using tkz, a tokenizer
// already configured for in.dialect. It must return an owned stream
// (ownStream) and must not return tkz to the pool.
type producer func(tkz *tokenizer.Tokenizer, in equivInput) tokStream

// tokenizePublic is the public tokenizer entry point the expected streams are
// built from: Tokenize, or TokenizeContext when the input carries a context.
func tokenizePublic(tkz *tokenizer.Tokenizer, in equivInput) ([]models.TokenWithSpan, error) {
	if in.newCtx != nil {
		return tkz.TokenizeContext(in.newCtx(), []byte(in.sql))
	}
	return tkz.Tokenize([]byte(in.sql))
}

// preprocessWith builds a producer that tokenizes with tokenizePublic and
// then runs pass over the tokens. On a tokenize error the stream has no
// tokens, as the parse entry points never preprocess a failed stream.
func preprocessWith(pass func([]models.TokenWithSpan) []models.TokenWithSpan) producer {
	return func(tkz *tokenizer.Tokenizer, in equivInput) tokStream {
		toks, err := tokenizePublic(tkz, in)
		if err != nil {
			return ownStream(nil, tkz.Comments, err)
		}
		return ownStream(pass(toks), tkz.Comments, nil)
	}
}

var (
	legacyProducer  = preprocessWith(parser.LegacyPreprocessTokens)
	shippedProducer = preprocessWith(parser.PreprocessTokens)
)

// diffTokens returns "" when want and got are equal field for field, or a
// description of the first difference.
func diffTokens(want, got []models.TokenWithSpan) string {
	if (want == nil) != (got == nil) {
		return fmt.Sprintf("token slice nil-ness: want nil=%t, got nil=%t", want == nil, got == nil)
	}
	n := min(len(want), len(got))
	for i := 0; i < n; i++ {
		if d := diffToken(want[i], got[i]); d != "" {
			return fmt.Sprintf("token %d: %s\n  want %s\n  got  %s", i, d, fmtToken(want[i]), fmtToken(got[i]))
		}
	}
	if len(want) != len(got) {
		return fmt.Sprintf("token count: want %d, got %d (first extra: %s)", len(want), len(got), fmtExtra(want, got, n))
	}
	return ""
}

func fmtExtra(want, got []models.TokenWithSpan, n int) string {
	if len(want) > n {
		return "want " + fmtToken(want[n])
	}
	return "got " + fmtToken(got[n])
}

// diffToken compares one token. The fields are listed explicitly (not
// reflect.DeepEqual on the struct) so that a field added to models.Token or
// models.TokenWithSpan fails TestDiffTokenCoversEveryField until it is
// compared here too.
func diffToken(a, b models.TokenWithSpan) string {
	switch {
	case a.Token.Type != b.Token.Type:
		return "Type"
	case a.Token.Value != b.Token.Value:
		return "Value"
	case a.Token.Long != b.Token.Long:
		return "Long"
	case a.Token.Quote != b.Token.Quote:
		return "Quote"
	case a.Start != b.Start:
		return "Start"
	case a.End != b.End:
		return "End"
	}
	wa, wb := a.Token.Word, b.Token.Word
	switch {
	case (wa == nil) != (wb == nil):
		return "Word nil-ness"
	case wa == nil:
		return ""
	case wa.Value != wb.Value:
		return "Word.Value"
	case wa.QuoteStyle != wb.QuoteStyle:
		return "Word.QuoteStyle"
	case !reflect.DeepEqual(wa.Keyword, wb.Keyword):
		return "Word.Keyword"
	}
	return ""
}

func fmtToken(t models.TokenWithSpan) string {
	s := fmt.Sprintf("%d:%d-%d:%d %s %q q=%q long=%t", t.Start.Line, t.Start.Column, t.End.Line, t.End.Column,
		t.Token.Type, t.Token.Value, t.Token.Quote, t.Token.Long)
	if w := t.Token.Word; w != nil {
		s += fmt.Sprintf(" w={%q %q %+v}", w.Value, w.QuoteStyle, w.Keyword)
	} else {
		s += " w=nil"
	}
	return s
}

// diffStreams compares two results: tokens, comments and error.
func diffStreams(want, got tokStream) string {
	if d := diffErr(want.Err, got.Err); d != "" {
		return d
	}
	if !reflect.DeepEqual(want.Comments, got.Comments) {
		return fmt.Sprintf("comments differ:\n  want %+v\n  got  %+v", want.Comments, got.Comments)
	}
	return diffTokens(want.Tokens, got.Tokens)
}

func diffErr(want, got error) string {
	if want == nil && got == nil {
		return ""
	}
	if w, g := goldens.Error(want), goldens.Error(got); w != g {
		return fmt.Sprintf("error differs:\n  want %s\n  got  %s", w, g)
	}
	for _, sentinel := range []error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(want, sentinel) != errors.Is(got, sentinel) {
			return fmt.Sprintf("errors.Is(%v) differs: want %t", sentinel, errors.Is(want, sentinel))
		}
	}
	return ""
}

// checkReadyShape returns "" when toks has the shape the parser relies on:
// it ends with EOF (when non-empty), and no compound-keyword or COUNT..MAX
// type survives. A Keyword token may still carry a compound value only when
// tokclass does not split it (a non-ASCII spelling whose byte length differs).
func checkReadyShape(toks []models.TokenWithSpan) string {
	if len(toks) > 0 && toks[len(toks)-1].Token.Type != models.TokenTypeEOF {
		return "last token is " + toks[len(toks)-1].Token.Type.String() + ", want EOF"
	}
	for i := range toks {
		typ := toks[i].Token.Type
		switch {
		case typ >= models.TokenTypeGroupBy && typ <= models.TokenTypeCrossJoin, typ == models.TokenTypeGroupingSets:
			return fmt.Sprintf("token %d: compound type %s survived", i, typ)
		case typ >= models.TokenTypeCount && typ <= models.TokenTypeMax:
			return fmt.Sprintf("token %d: aggregate type %s survived", i, typ)
		case typ == models.TokenTypeKeyword && tokclass.CompoundParts(&toks[i]) != nil:
			return fmt.Sprintf("token %d: unsplit compound keyword %q", i, toks[i].Token.Value)
		}
	}
	return ""
}

// equivStats summarises a harness run for the PR body.
type equivStats struct {
	streams, errors, tokens atomic.Int64
}

// runEquivalence runs want and got on every input and fails on the first
// difference per input. Inputs run in parallel (goldens.Parallel), so the
// pooled tokenizers are shared and reused across inputs, which also checks
// that no stale tokenizer state leaks between calls. Every third input uses a
// freshly constructed tokenizer for the producer under test instead.
func runEquivalence(t *testing.T, inputs []equivInput, want, got producer) *equivStats {
	t.Helper()
	st := &equivStats{}
	var failures atomic.Int64
	goldens.Parallel(len(inputs), func(i int) {
		if failures.Load() >= 20 {
			return
		}
		in := inputs[i]
		w := runProducer(want, in, false)
		g := runProducer(got, in, i%3 == 2)
		if d := diffStreams(w, g); d != "" {
			failures.Add(1)
			t.Errorf("%s [dialect %s]: %s\n  sql: %s", in.name, in.dialect, d, clip(in.sql))
			return
		}
		if g.Err == nil {
			if d := checkReadyShape(g.Tokens); d != "" {
				failures.Add(1)
				t.Errorf("%s [dialect %s]: shape: %s\n  sql: %s", in.name, in.dialect, d, clip(in.sql))
				return
			}
		}
		st.streams.Add(1)
		if g.Err != nil {
			st.errors.Add(1)
		}
		st.tokens.Add(int64(len(g.Tokens)))
	})
	if failures.Load() >= 20 {
		t.Fatal("stopping after 20 failing inputs")
	}
	return st
}

func runProducer(p producer, in equivInput, fresh bool) tokStream {
	if fresh {
		tkz, err := tokenizer.NewWithDialect(in.dialect)
		if err != nil {
			return tokStream{Err: err}
		}
		return p(tkz, in)
	}
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tkz.SetDialect(in.dialect)
	return p(tkz, in)
}

func clip(s string) string {
	if len(s) > 300 {
		return strconv.Quote(s[:300]) + "..."
	}
	return strconv.Quote(s)
}

// equivDialects is every dialect the library accepts (11).
func equivDialects() []keywords.SQLDialect {
	var ds []keywords.SQLDialect
	for _, d := range goldens.Dialects() {
		ds = append(ds, keywords.SQLDialect(d))
	}
	return ds
}

// equivTestdataRoots is the explicit allowlist of SQL fixture directories
// (relative to the repository root). It is not a recursive glob of testdata/
// so that a stray copy (CRITIQUE 16) cannot double the input.
var equivTestdataRoots = []string{
	"testdata/corpus",
	"testdata/mssql",
	"testdata/mysql",
	"testdata/oracle",
	"testdata/postgresql",
	"testdata/real_world",
	"testdata/realworld",
	"testdata/sql",
	"pkg/sql/parser/testdata/mariadb",
	"pkg/sql/parser/testdata/mysql",
	"pkg/sql/parser/testdata/postgresql",
	"pkg/sql/parser/testdata/real_world",
}

// equivInputs is the shared input list: the benchmark corpus, the SQL
// fixtures, a generated compound-keyword matrix, Unicode case folds, delimited
// and odd identifiers, and tokenizer errors, each under every dialect.
func equivInputs(t *testing.T) []equivInput {
	t.Helper()
	dialects := equivDialects()
	var in []equivInput
	each := func(name, sql string) {
		for _, d := range dialects {
			in = append(in, equivInput{name: name, dialect: d, sql: sql})
		}
	}

	for _, st := range goldens.Corpus(t) {
		each("corpus "+st.Key(), st.SQL)
	}

	root := filepath.Join("..", "..", "..")
	nfiles := 0
	for _, dir := range equivTestdataRoots {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, e os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if e.IsDir() && e.Name() == "testdata" {
				return filepath.SkipDir // a nested copy is never an input
			}
			if e.IsDir() || filepath.Ext(p) != ".sql" {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			each("file "+filepath.ToSlash(rel), string(b))
			nfiles++
			return nil
		})
		if err != nil {
			t.Fatalf("testdata root %s: %v", dir, err)
		}
	}
	if nfiles < 100 {
		t.Fatalf("only %d testdata files found; allowlist out of date?", nfiles)
	}

	for _, s := range compoundMatrix() {
		each("compound", s)
	}
	for _, s := range oddInputs {
		each("odd", s)
	}
	in = append(in, errorInputs(t)...)
	return in
}

// compoundKeys are the compound keywords the tokenizer joins (its
// compoundKeywordTypes keys); TestCompoundKeysMatchTokenizer in
// pkg/sql/tokenizer keeps the list in step.
var compoundKeys = tokclass.CompoundKeys()

// compoundMatrix is every compound key in three casings, joined by eight
// separators (comments break a compound), in six contexts.
func compoundMatrix() []string {
	casings := []func(string) string{strings.ToUpper, strings.ToLower, mixedCase}
	seps := []string{" ", "  ", "\t", "\n", "\r\n", "\n\t  ", " /* c */ ", " -- c\n "}
	contexts := []string{
		"%s x",
		"SELECT a FROM t %s x",
		"SELECT f(%s)",
		"SELECT a FROM t %s",
		"SELECT a FROM t %s;",
		"\uFEFF%s a",
	}
	var out []string
	for _, key := range compoundKeys {
		for _, c := range casings {
			for _, sep := range seps {
				phrase := strings.ReplaceAll(c(key), " ", sep)
				for _, ctx := range contexts {
					out = append(out, fmt.Sprintf(ctx, phrase))
				}
			}
		}
	}
	return append(out,
		"SELECT * FROM a LEFT OUTER JOIN b ON a.x = b.x",
		"SELECT * FROM a NATURAL LEFT OUTER JOIN b",
		"SELECT * FROM a left  outer\njoin b ON 1=1",
		"SELECT * FROM a NATURAL JOIN b",
		"SELECT groupby, group_by FROM t",
		`SELECT "GROUP" BY FROM t`,
		"SELECT `order` by FROM t",
		"SELECT [left] join FROM t",
		"SELECT a FROM t GROUP BY GROUPING SETS ((a), (b)) ORDER BY a",
	)
}

func mixedCase(s string) string {
	b := []byte(strings.ToLower(s))
	for i := 0; i < len(b); i += 2 {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

// oddInputs cover Unicode case folds (the remaps fold ASCII only, the
// tokenizer folds Unicode), the backtick-width rule and every other producer
// of identifier-typed tokens.
var oddInputs = []string{
	// Unicode folds.
	"ſelect a FROM t",
	"SELECT ſum(x) FROM t",
	"SELECT * FROM a joın b ON 1=1",
	"SELECT * FROM a LEFT joın b ON 1=1",
	"SELECT * FROM a croſſ join b",
	"SELECT a FROM t groupıng sets ((a))",
	"ALTER ROLE r valıd UNTIL 'x'",
	"SELECT \u212AEY FROM t",
	"CREATE TABLE t (a INT AUTO_INCREMENT_LONGER_THAN_16)",
	"SELECT valid, VALID, Valid, url, owner, member, policy, until, reset FROM t",
	"CREATE TABLE t (a INT AUTO_INCREMENT, b INT autoincrement)",
	"SELECT count(*), COUNT(a), Sum(b), avg(c), min(d), MAX(e) FROM t",
	// Delimited and odd identifiers.
	"SELECT `key`, `group`, `a b` FROM `t`",
	"SELECT `multi\nline` FROM t",
	"SELECT [x], [Group], [order by] FROM [t]",
	`SELECT "x""y", "KEY" FROM "t"`,
	`SELECT U&"d\0061t\+000061" FROM t`,
	`SELECT u&'\0041' FROM t`,
	"SELECT @x, @@x, @@session.sql_mode, @group FROM t",
	"SELECT * FROM #t",
	"SELECT $1, $2, :name, ? FROM t",
	"SELECT 1abc, 0x1g, 1e5x FROM t",
	"SELECT a.order, a.group, t.key FROM t",
	"INSERT INTO t (group by) VALUES (1)",
	"UPDATE t SET order by = 1",
	"SELECT a FROM t ORDER BY a GROUP BY a",
	"-- only a comment",
	"/* block */ SELECT 1 /* trailing */",
	"",
}

// errorInputs are inputs the tokenizer rejects, or rejects only under a
// context that is cancelled at a chosen check.
func errorInputs(t *testing.T) []equivInput {
	var in []equivInput
	for _, d := range equivDialects() {
		for _, s := range []string{
			"SELECT 'unterminated",
			"SELECT \"unterminated",
			"SELECT /* unterminated",
			"SELECT \xff FROM t",
			"SELECT \xc3 FROM t",
			`SELECT U&"\00zz" FROM t`,
			"SELECT `unterminated",
			"SELECT [unterminated",
		} {
			in = append(in, equivInput{name: "error", dialect: d, sql: s})
		}
	}
	// Cancellation: the tokenizer checks ctx before starting and every 100
	// tokens. cancelAfter(k) lets exactly k checks pass.
	for _, n := range []int{99, 100, 101, 250} {
		sql := strings.TrimSuffix(strings.Repeat("a ", n), " ")
		for _, k := range []int{0, 1, 2, 3} {
			in = append(in, equivInput{
				name: fmt.Sprintf("ctx tokens=%d cancel-after=%d", n, k), dialect: keywords.DialectGeneric,
				sql: sql, newCtx: func() context.Context { return cancelAfter(k) },
			})
		}
	}
	in = append(in, equivInput{
		name: "over MaxInputSize", dialect: keywords.DialectGeneric,
		sql: strings.Repeat(" ", tokenizer.MaxInputSize+1),
	})
	if !testing.Short() {
		// One-byte tokens at and just past the token limit (the stream is
		// tokens plus EOF).
		for _, n := range []int{tokenizer.MaxTokens - 1, tokenizer.MaxTokens} {
			in = append(in, equivInput{
				name: fmt.Sprintf("MaxTokens boundary n=%d", n), dialect: keywords.DialectGeneric,
				sql: strings.Repeat(",", n),
			})
		}
	}
	return in
}

// countingCtx is a context whose Err starts returning context.Canceled after
// `allow` calls, so a test can cancel at a chosen tokenizer check.
type countingCtx struct {
	context.Context
	allow int64
	calls atomic.Int64
	done  chan struct{}
}

func cancelAfter(allow int) context.Context {
	return &countingCtx{Context: context.Background(), allow: int64(allow), done: make(chan struct{})}
}

func (c *countingCtx) Done() <-chan struct{} { return c.done }

func (c *countingCtx) Err() error {
	if c.calls.Add(1) > c.allow {
		return context.Canceled
	}
	return nil
}

// TestTokclassMatchesLegacy proves the W3-03a1 move is a pure refactor: the
// preprocess pass built on internal/tokclass reproduces the frozen
// pre-move pass on every harness input under every dialect.
func TestTokclassMatchesLegacy(t *testing.T) {
	inputs := equivInputs(t)
	st := runEquivalence(t, inputs, legacyProducer, shippedProducer)
	t.Logf("streams=%d (errors %d) parser-ready tokens=%d", st.streams.Load(), st.errors.Load(), st.tokens.Load())
	if st.streams.Load() != int64(len(inputs)) {
		t.Fatalf("compared %d of %d inputs", st.streams.Load(), len(inputs))
	}
}

// TestTokclassMatchesLegacyEveryKey sweeps every word of the frozen remap
// switches (read from legacy_preprocess_test.go itself, so the domain cannot
// drift with tokclass) and every compound value, in three casings, as every
// gated token type and a few others, with spans that do and do not trigger
// the backtick-width rule. Corpus coverage of rare keywords is incidental;
// this is not.
func TestTokclassMatchesLegacyEveryKey(t *testing.T) {
	words := legacySwitchWords(t)
	words = append(words, compoundKeys...)
	words = append(words, "", "x", "users", "AUTO_INCREMENT_LONGER", "valıd", "ſum", "croſſ join", "\u212AEY")
	types := []models.TokenType{
		models.TokenTypeIdentifier, models.TokenTypeKeyword, models.TokenTypeWord,
		models.TokenTypeString, models.TokenTypeNumber, models.TokenTypeUnknown,
		models.TokenTypeGroupingSets,
	}
	for typ := models.TokenTypeCount; typ <= models.TokenTypeMax; typ++ {
		types = append(types, typ)
	}
	for typ := models.TokenTypeGroupBy; typ <= models.TokenTypeCrossJoin; typ++ {
		types = append(types, typ)
	}
	n := 0
	for _, w := range words {
		for _, v := range []string{w, strings.ToLower(w), mixedCase(w)} {
			for _, typ := range types {
				for _, q := range []rune{0, '"', '`'} {
					for _, wide := range []int{0, len(v), len(v) + 2} {
						in := []models.TokenWithSpan{{
							Token: models.Token{Type: typ, Value: v, Quote: q, Word: &models.Word{Value: v}},
							Start: models.Location{Line: 2, Column: 5},
							End:   models.Location{Line: 2, Column: 5 + wide},
						}}
						if wide == 0 {
							in[0].Start, in[0].End = models.Location{}, models.Location{}
						}
						want := parser.LegacyPreprocessTokens(in)
						got := parser.PreprocessTokens(in)
						if d := diffTokens(want, got); d != "" {
							t.Fatalf("type %s value %q quote %q width %d: %s", typ, v, q, wide, d)
						}
						n++
					}
				}
			}
		}
	}
	t.Logf("compared %d synthetic tokens over %d words", n, len(words))
}

// legacySwitchWords returns every string case label of the frozen
// legacyKeywordType and legacyIdentifierKeywordType switches.
func legacySwitchWords(t *testing.T) []string {
	t.Helper()
	f, err := goparser.ParseFile(token.NewFileSet(), "legacy_preprocess_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || (fn.Name.Name != "legacyKeywordType" && fn.Name.Name != "legacyIdentifierKeywordType") {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			cc, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, e := range cc.List {
				if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if s, err := strconv.Unquote(lit.Value); err == nil {
						seen[s] = true
					}
				}
			}
			return true
		})
	}
	// keywordType has 136 words (AUTO_INCREMENT and AUTOINCREMENT share a
	// case); identifierKeywordType's 62 are a subset.
	if len(seen) != 136 {
		t.Fatalf("found %d words in the legacy switches, want 136", len(seen))
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

// TestDiffTokenCoversEveryField guards the harness itself: changing any one
// field of a token must be reported, and the comparator must list every
// field of models.Token, models.TokenWithSpan and models.Word.
func TestDiffTokenCoversEveryField(t *testing.T) {
	for typ, n := range map[reflect.Type]int{
		reflect.TypeOf(models.TokenWithSpan{}): 3, // Token, Start, End
		reflect.TypeOf(models.Token{}):         5, // Type, Value, Word, Long, Quote
		reflect.TypeOf(models.Word{}):          3, // Value, QuoteStyle, Keyword
	} {
		if typ.NumField() != n {
			t.Errorf("%s has %d fields, diffToken compares %d: update diffToken", typ, typ.NumField(), n)
		}
	}
	base := models.TokenWithSpan{
		Token: models.Token{Type: models.TokenTypeIdentifier, Value: "a", Quote: '"',
			Word: &models.Word{Value: "a", QuoteStyle: '"', Keyword: &models.Keyword{Word: "A"}}},
		Start: models.Location{Line: 1, Column: 1}, End: models.Location{Line: 1, Column: 4},
	}
	clone := func() models.TokenWithSpan { return ownStream([]models.TokenWithSpan{base}, nil, nil).Tokens[0] }
	mutations := map[string]func(*models.TokenWithSpan){
		"Type":            func(x *models.TokenWithSpan) { x.Token.Type = models.TokenTypeKeyword },
		"Value":           func(x *models.TokenWithSpan) { x.Token.Value = "b" },
		"Long":            func(x *models.TokenWithSpan) { x.Token.Long = true },
		"Quote":           func(x *models.TokenWithSpan) { x.Token.Quote = '`' },
		"Start":           func(x *models.TokenWithSpan) { x.Start.Column = 2 },
		"End":             func(x *models.TokenWithSpan) { x.End.Line = 2 },
		"Word nil-ness":   func(x *models.TokenWithSpan) { x.Token.Word = nil },
		"Word.Value":      func(x *models.TokenWithSpan) { x.Token.Word.Value = "b" },
		"Word.QuoteStyle": func(x *models.TokenWithSpan) { x.Token.Word.QuoteStyle = 0 },
		"Word.Keyword":    func(x *models.TokenWithSpan) { x.Token.Word.Keyword.Reserved = true },
	}
	if d := diffToken(base, clone()); d != "" {
		t.Fatalf("identical tokens reported as %q", d)
	}
	for want, mutate := range mutations {
		m := clone()
		mutate(&m)
		if got := diffToken(base, m); got != want {
			t.Errorf("mutating %s: diffToken = %q", want, got)
		}
	}
	if d := diffStreams(tokStream{Err: context.Canceled}, tokStream{}); d == "" {
		t.Error("diffStreams missed an error vs no error")
	}
	if d := diffStreams(tokStream{Comments: []models.Comment{{Text: "-- a"}}}, tokStream{}); d == "" {
		t.Error("diffStreams missed a comment difference")
	}
	if d := diffTokens([]models.TokenWithSpan{base}, nil); d == "" {
		t.Error("diffTokens missed nil vs non-nil")
	}
}

// TestCheckReadyShapeRejects guards checkReadyShape: each malformed stream
// must be rejected.
func TestCheckReadyShapeRejects(t *testing.T) {
	eof := models.TokenWithSpan{Token: models.Token{Type: models.TokenTypeEOF}}
	tok := func(typ models.TokenType, v string) models.TokenWithSpan {
		return models.TokenWithSpan{Token: models.Token{Type: typ, Value: v}}
	}
	if d := checkReadyShape([]models.TokenWithSpan{tok(models.TokenTypeGroup, "GROUP"), tok(models.TokenTypeBy, "BY"), eof}); d != "" {
		t.Fatalf("valid stream rejected: %s", d)
	}
	for name, s := range map[string][]models.TokenWithSpan{
		"no EOF":         {tok(models.TokenTypeSelect, "SELECT")},
		"typed compound": {tok(models.TokenTypeGroupBy, "GROUP BY"), eof},
		"grouping sets":  {tok(models.TokenTypeGroupingSets, "GROUPING SETS"), eof},
		"aggregate":      {tok(models.TokenTypeCount, "COUNT"), eof},
		"keyword value":  {tok(models.TokenTypeKeyword, "cross join"), eof},
	} {
		if checkReadyShape(s) == "" {
			t.Errorf("%s: accepted", name)
		}
	}
}
