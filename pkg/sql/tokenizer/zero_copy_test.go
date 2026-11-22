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

package tokenizer

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// allTokenizerDialects lists the eight supported dialects.
var allTokenizerDialects = []keywords.SQLDialect{
	keywords.DialectPostgreSQL,
	keywords.DialectMySQL,
	keywords.DialectMariaDB,
	keywords.DialectSQLServer,
	keywords.DialectOracle,
	keywords.DialectSQLite,
	keywords.DialectSnowflake,
	keywords.DialectClickHouse,
}

// zeroCopyEquivalenceInputs exercises every scanner path that hands out
// substrings of the input (#546).
var zeroCopyEquivalenceInputs = []string{
	"",
	"SELECT id, name FROM users WHERE age > 25",
	"SELECT u.id, COUNT(o.id) AS n FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.id HAVING COUNT(o.id) > 0 ORDER BY n DESC LIMIT 10",
	"SELECT a -- trailing note\nFROM t",
	"-- standalone line comment\nSELECT 1",
	"SELECT /* inline block */ a FROM t",
	"/* standalone\n   block */\nSELECT 1 -- eof comment",
	"SELECT $$a$b$$",
	"SELECT $fn$ x $$ y $fn$",
	"SELECT $1, $23",
	"SELECT $tag$ multi\nline $notit$ $tag$, $",
	"SELECT N'abc', [a b], [], #t, ##g, # FROM [dbo].[My Table]",
	"SELECT :1, :b_2 FROM dual",
	"SELECT 名前 FROM ユーザー WHERE 'こんにちは' = x",
	"SELECT 1 1.5 2e10 3.4E-2",
	"SELECT a FROM t GROUP BY a",
	"SELECT a FROM t group   by a",
	"SELECT * FROM a LEFT\nJOIN b ON a.id = b.id",
	"SELECT * FROM a Left Join b ON true ORDER\n BY 1",
	"SELECT `back tick`, \"Quoted Col\" FROM t",
	"SELECT 'it''s', \"a\"\"b\" FROM t",
}

// zeroCopyInvalidInputs must fail identically through both entry points.
var zeroCopyInvalidInputs = []struct {
	sql     string
	dialect keywords.SQLDialect
}{
	{"SELECT 1e", keywords.DialectPostgreSQL},
	{"SELECT 'x", keywords.DialectPostgreSQL},
	{"/* open", keywords.DialectPostgreSQL},
	{"SELECT $$open", keywords.DialectPostgreSQL},
	{"SELECT [open", keywords.DialectSQLServer},
}

type tokenizeResult struct {
	tokens   []models.TokenWithSpan
	comments []models.Comment
	err      error
}

func runTokenize(t testing.TB, dialect keywords.SQLDialect, s string, asString bool) tokenizeResult {
	t.Helper()
	tkz, err := NewWithDialect(dialect)
	if err != nil {
		t.Fatalf("NewWithDialect(%s): %v", dialect, err)
	}
	var res tokenizeResult
	if asString {
		res.tokens, res.err = tkz.TokenizeString(s)
	} else {
		res.tokens, res.err = tkz.Tokenize([]byte(s))
	}
	res.comments = append([]models.Comment(nil), tkz.Comments...)
	return res
}

func assertSameResult(t testing.TB, label string, a, b tokenizeResult) {
	t.Helper()
	if (a.err == nil) != (b.err == nil) {
		t.Fatalf("%s: error mismatch: Tokenize err=%v, TokenizeString err=%v", label, a.err, b.err)
	}
	if a.err != nil {
		if a.err.Error() != b.err.Error() {
			t.Fatalf("%s: error text mismatch:\n  Tokenize:       %v\n  TokenizeString: %v", label, a.err, b.err)
		}
		return
	}
	if !reflect.DeepEqual(a.tokens, b.tokens) {
		t.Fatalf("%s: tokens differ:\n  Tokenize:       %+v\n  TokenizeString: %+v", label, a.tokens, b.tokens)
	}
	if !reflect.DeepEqual(a.comments, b.comments) {
		t.Fatalf("%s: comments differ:\n  Tokenize:       %+v\n  TokenizeString: %+v", label, a.comments, b.comments)
	}
}

func corpusFiles(t *testing.T) map[string]string {
	t.Helper()
	root := filepath.Join("..", "..", "..", "testdata")
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		out[path] = string(data)
		return nil
	})
	if err != nil {
		t.Fatalf("walk testdata: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("no testdata files found")
	}
	return out
}

// TestTokenizeString_MatchesTokenize checks that TokenizeString produces
// exactly the tokens, comments and errors of Tokenize([]byte(s)) (#546).
func TestTokenizeString_MatchesTokenize(t *testing.T) {
	inputs := map[string]string{}
	for i, s := range zeroCopyEquivalenceInputs {
		inputs[fmt.Sprintf("input_%02d", i)] = s
	}
	for path, s := range corpusFiles(t) {
		inputs[path] = s
	}

	for _, dialect := range allTokenizerDialects {
		for name, s := range inputs {
			label := fmt.Sprintf("%s/%s", dialect, name)
			assertSameResult(t, label, runTokenize(t, dialect, s, false), runTokenize(t, dialect, s, true))
		}
	}

	for _, tc := range zeroCopyInvalidInputs {
		a := runTokenize(t, tc.dialect, tc.sql, false)
		b := runTokenize(t, tc.dialect, tc.sql, true)
		if a.err == nil || b.err == nil {
			t.Fatalf("%q (%s): expected errors, got Tokenize=%v TokenizeString=%v", tc.sql, tc.dialect, a.err, b.err)
		}
		assertSameResult(t, tc.sql, a, b)
	}
}

func TestTokenizeStringContext(t *testing.T) {
	const s = "SELECT a, b FROM t -- c\nWHERE a = $1"
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	want, err := tkz.TokenizeString(s)
	if err != nil {
		t.Fatalf("TokenizeString: %v", err)
	}
	wantComments := append([]models.Comment(nil), tkz.Comments...)

	got, err := tkz.TokenizeStringContext(context.Background(), s)
	if err != nil {
		t.Fatalf("TokenizeStringContext: %v", err)
	}
	if !reflect.DeepEqual(want, got) || !reflect.DeepEqual(wantComments, tkz.Comments) {
		t.Fatalf("TokenizeStringContext differs from TokenizeString:\n want %+v\n got  %+v", want, got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := tkz.TokenizeStringContext(ctx, s); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ctx: got err %v, want context.Canceled", err)
	}

	// A context cancelled mid-scan is observed at the next 100-token check.
	long := "SELECT " + strings.Repeat("a, ", 500) + "b FROM t"
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	if _, err := tkz.TokenizeStringContext(ctx2, long); err != nil {
		t.Fatalf("live ctx: %v", err)
	}
}

// TestTokenize_WordSemanticsUnchanged pins Token.Word for every token that
// had one before the Word slab (#546): bare words keep a non-nil Word equal
// to their own text, double-quoted identifiers keep their QuoteStyle.
func TestTokenize_WordSemanticsUnchanged(t *testing.T) {
	inputs := []string{
		"SELECT id, Name FROM users u",
		`select "Quoted Col" from t`,
		"SELECT a FROM t GROUP BY a ORDER BY a",
		"SELECT * FROM a LEFT JOIN b ON a.id=b.id",
	}
	bareWord := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*( [A-Za-z_][A-Za-z0-9_]*)?$`)
	dialects := []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectSQLServer, keywords.DialectOracle}

	for _, dialect := range dialects {
		for _, s := range inputs {
			res := runTokenize(t, dialect, s, true)
			if res.err != nil {
				t.Fatalf("%s %q: %v", dialect, s, res.err)
			}
			seen := map[*models.Word]bool{}
			for _, tw := range res.tokens {
				tok := tw.Token
				switch {
				case tok.Type == models.TokenTypeDoubleQuotedString:
					if tok.Word == nil || tok.Word.QuoteStyle != '"' || tok.Word.Value != tok.Value {
						t.Errorf("%s %q: quoted token %q has Word %+v", dialect, s, tok.Value, tok.Word)
					}
				case bareWord.MatchString(tok.Value):
					if tok.Word == nil {
						t.Errorf("%s %q: bare word %q has nil Word", dialect, s, tok.Value)
						continue
					}
					first, _, _ := strings.Cut(tok.Value, " ")
					if tok.Word.Value != first || tok.Word.QuoteStyle != 0 || tok.Word.Keyword != nil {
						t.Errorf("%s %q: token %q has Word %+v, want {Value:%q}", dialect, s, tok.Value, *tok.Word, first)
					}
				}
				if tok.Word != nil {
					if seen[tok.Word] {
						t.Errorf("%s %q: Word pointer shared by token %q", dialect, s, tok.Value)
					}
					seen[tok.Word] = true
				}
			}
		}
	}
}

// TestCompoundKeywordValue pins the joined Value of compound keywords: the
// input text when one space separates the words, a single space otherwise.
func TestCompoundKeywordValue(t *testing.T) {
	tests := []struct {
		in, want string
		typ      models.TokenType
	}{
		{"GROUP BY", "GROUP BY", models.TokenTypeGroupBy},
		{"Left Join", "Left Join", models.TokenTypeLeftJoin},
		{"group   by", "group by", models.TokenTypeGroupBy},
		{"ORDER\n BY", "ORDER BY", models.TokenTypeOrderBy},
	}
	for _, tc := range tests {
		for _, asString := range []bool{false, true} {
			res := runTokenize(t, keywords.DialectPostgreSQL, tc.in, asString)
			if res.err != nil {
				t.Fatalf("%q: %v", tc.in, res.err)
			}
			if len(res.tokens) != 2 {
				t.Fatalf("%q: got %d tokens, want compound + EOF: %+v", tc.in, len(res.tokens), res.tokens)
			}
			tok := res.tokens[0].Token
			if tok.Value != tc.want || tok.Type != tc.typ {
				t.Errorf("%q: got {%v %q}, want {%v %q}", tc.in, tok.Type, tok.Value, tc.typ, tc.want)
			}
		}
	}
}

// TestCompoundKeywordValue_NoJoinAllocation checks that a compound keyword
// written with a single space allocates nothing for its Value: only inputs
// whose separator must be normalized pay for the joined string.
func TestCompoundKeywordValue_NoJoinAllocation(t *testing.T) {
	if testing.CoverMode() != "" || raceEnabled {
		t.Skip("allocation counts are not stable under coverage or race instrumentation")
	}
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)
	allocs := func(sql string) float64 {
		return testing.AllocsPerRun(50, func() {
			if _, err := tkz.TokenizeString(sql); err != nil {
				t.Fatal(err)
			}
		})
	}
	single := allocs("SELECT a FROM t GROUP BY a ORDER BY a")
	spread := allocs("SELECT a FROM t GROUP  BY a ORDER  BY a")
	if single != spread-2 {
		t.Errorf("allocs: single-space compounds %v, double-space %v; want exactly the 2 joined Values fewer", single, spread)
	}
}

type tokenSnapshot struct {
	values, words, comments []string
}

func snapshotTokens(tokens []models.TokenWithSpan, comments []models.Comment) tokenSnapshot {
	var s tokenSnapshot
	for _, tw := range tokens {
		s.values = append(s.values, strings.Clone(tw.Token.Value))
		if tw.Token.Word != nil {
			s.words = append(s.words, strings.Clone(tw.Token.Word.Value))
		} else {
			s.words = append(s.words, "<nil>")
		}
	}
	for _, c := range comments {
		s.comments = append(s.comments, strings.Clone(c.Text))
	}
	return s
}

// TestTokenize_DoesNotAliasInputBytes guards the []byte path: tokens must not
// observe later writes to the caller's buffer.
func TestTokenize_DoesNotAliasInputBytes(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectPostgreSQL, "SELECT col1, 42, $1 FROM t -- note\n/* blk */ WHERE x = 1.5e3 GROUP BY col1"},
		{keywords.DialectPostgreSQL, "SELECT $q$ body $q$ FROM t"},
		{keywords.DialectSQLServer, "SELECT [My Col] FROM #tmp"},
		{keywords.DialectOracle, "SELECT :1, :name FROM dual"},
	}
	for _, tc := range tests {
		input := []byte(tc.sql)
		tkz, err := NewWithDialect(tc.dialect)
		if err != nil {
			t.Fatal(err)
		}
		tokens, err := tkz.Tokenize(input)
		if err != nil {
			t.Fatalf("%q: %v", tc.sql, err)
		}
		comments := tkz.Comments
		before := snapshotTokens(tokens, comments)
		for i := range input {
			input[i] = 'X'
		}
		if after := snapshotTokens(tokens, comments); !reflect.DeepEqual(before, after) {
			t.Fatalf("%q: tokens alias the input buffer:\n before %+v\n after  %+v", tc.sql, before, after)
		}
	}
}

// TestTokenize_EarlierTokensSurviveReuse checks that neither src nor the Word
// slab is reused or mutated by later calls on the same or a pooled tokenizer.
func TestTokenize_EarlierTokensSurviveReuse(t *testing.T) {
	tkz := GetTokenizer()
	a, err := tkz.TokenizeString("SELECT alpha, beta FROM gamma GROUP BY alpha -- keep me")
	if err != nil {
		t.Fatal(err)
	}
	aComments := append([]models.Comment(nil), tkz.Comments...)
	want := snapshotTokens(a, aComments)

	var b strings.Builder
	b.WriteString("SELECT ")
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&b, "col_%d, ", i)
	}
	b.WriteString("last FROM t -- other")
	if _, err := tkz.Tokenize([]byte(b.String())); err != nil {
		t.Fatal(err)
	}
	PutTokenizer(tkz)

	tkz2 := GetTokenizer()
	defer PutTokenizer(tkz2)
	if _, err := tkz2.TokenizeString("SELECT zeta FROM eta /* c */"); err != nil {
		t.Fatal(err)
	}

	if got := snapshotTokens(a, aComments); !reflect.DeepEqual(want, got) {
		t.Fatalf("earlier tokens changed:\n want %+v\n got  %+v", want, got)
	}
}

// TestReset_DropsInputReferences checks that a reset (and so pooled)
// tokenizer keeps no reference to the previous input. PutTokenizer calls
// Reset.
func TestReset_DropsInputReferences(t *testing.T) {
	tkz, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tkz.Tokenize([]byte("SELECT a -- line\nFROM t /* block */")); err != nil {
		t.Fatal(err)
	}
	if len(tkz.Comments) != 2 {
		t.Fatalf("got %d comments, want 2", len(tkz.Comments))
	}
	if tkz.src == "" || tkz.wordChunk == nil {
		t.Fatal("expected src and wordChunk to be populated after Tokenize")
	}
	backing := tkz.Comments[:cap(tkz.Comments)]

	tkz.Reset()

	if tkz.src != "" || tkz.input != nil || tkz.wordChunk != nil || tkz.wordHint != 0 {
		t.Fatalf("Reset kept input state: src=%q input=%v wordChunk=%v wordHint=%d",
			tkz.src, tkz.input, tkz.wordChunk, tkz.wordHint)
	}
	if len(tkz.Comments) != 0 {
		t.Fatalf("Comments length %d after Reset", len(tkz.Comments))
	}
	for i, c := range backing {
		if c != (models.Comment{}) {
			t.Fatalf("Comments backing[%d] not zeroed: %+v", i, c)
		}
	}
}

func selectNColumns(n int) string {
	var b strings.Builder
	b.WriteString("SELECT ")
	for i := 1; i <= n; i++ {
		if i > 1 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "c%d", i)
	}
	b.WriteString(" FROM t WHERE c1 = 1")
	return b.String()
}

// TestTokenizeString_AllocsIndependentOfIdentifierCount checks that
// identifiers no longer cost an allocation each (#546).
func TestTokenizeString_AllocsIndependentOfIdentifierCount(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under the race detector")
	}
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	allocs := func(s string) float64 {
		return testing.AllocsPerRun(100, func() {
			if _, err := tkz.TokenizeString(s); err != nil {
				t.Fatal(err)
			}
		})
	}
	// N=10 and N=50 both fit in the first Word chunk (firstWordChunkMax).
	small, medium := allocs(selectNColumns(10)), allocs(selectNColumns(50))
	if small != medium {
		t.Fatalf("TokenizeString allocs grow with identifier count: N=10 -> %v, N=50 -> %v", small, medium)
	}
	// Beyond the first chunk, Word chunks grow geometrically, so 1500
	// identifiers cost a handful of extra allocations, not 1490.
	if large := allocs(selectNColumns(1500)); large > small+8 {
		t.Fatalf("TokenizeString allocs for N=1500: %v, want at most N=10's %v + 8", large, small)
	}

	medSQL := selectNColumns(50)
	medBytes := []byte(medSQL)
	bytesAllocs := testing.AllocsPerRun(100, func() {
		if _, err := tkz.Tokenize(medBytes); err != nil {
			t.Fatal(err)
		}
	})
	if bytesAllocs > medium+1 {
		t.Fatalf("Tokenize([]byte) uses %v allocs, want at most TokenizeString's %v + 1", bytesAllocs, medium)
	}
}

// TestTokenizer_ConcurrentNoCrossContamination runs pooled tokenizers from
// many goroutines and re-verifies retained tokens after all of them finish.
func TestTokenizer_ConcurrentNoCrossContamination(t *testing.T) {
	const goroutines, iterations = 16, 200
	type kept struct {
		tokens   []models.TokenWithSpan
		comments []models.Comment
		g, i     int
	}
	var (
		mu   sync.Mutex
		all  []kept
		wg   sync.WaitGroup
		errs = make(chan error, goroutines)
	)
	verify := func(tokens []models.TokenWithSpan, comments []models.Comment, g, i int) error {
		want := []string{"SELECT", fmt.Sprintf("col_%d_a", g), ",", fmt.Sprint(i), "FROM", fmt.Sprintf("t_%d", g), ""}
		if len(tokens) != len(want) {
			return fmt.Errorf("g%d i%d: got %d tokens, want %d", g, i, len(tokens), len(want))
		}
		for k, w := range want {
			if tokens[k].Token.Value != w {
				return fmt.Errorf("g%d i%d: token %d = %q, want %q", g, i, k, tokens[k].Token.Value, w)
			}
		}
		if wc := fmt.Sprintf("-- c%d", i); len(comments) != 1 || comments[0].Text != wc {
			return fmt.Errorf("g%d i%d: comments %+v, want %q", g, i, comments, wc)
		}
		return nil
	}
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				s := fmt.Sprintf("SELECT col_%d_a, %d -- c%d\nFROM t_%d", g, i, i, g)
				tkz := GetTokenizer()
				var (
					tokens []models.TokenWithSpan
					err    error
				)
				if i%2 == 0 {
					tokens, err = tkz.TokenizeString(s)
				} else {
					tokens, err = tkz.Tokenize([]byte(s))
				}
				comments := append([]models.Comment(nil), tkz.Comments...)
				PutTokenizer(tkz)
				if err == nil {
					err = verify(tokens, comments, g, i)
				}
				if err != nil {
					errs <- err
					return
				}
				if i%10 == 0 {
					mu.Lock()
					all = append(all, kept{tokens, comments, g, i})
					mu.Unlock()
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	for _, k := range all {
		if err := verify(k.tokens, k.comments, k.g, k.i); err != nil {
			t.Fatalf("after all goroutines finished: %v", err)
		}
	}
}
