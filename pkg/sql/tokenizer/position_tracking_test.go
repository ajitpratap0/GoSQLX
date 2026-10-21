package tokenizer

import (
	"bytes"
	"context"
	"math/rand"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// naiveLocation is a literal reimplementation of the pre-#544 toSQLPosition
// algorithm: the line is 1 + the number of '\n' before idx, and the column is
// 1 + the number of bytes (a tab is one) from the line start up to idx (clamped
// to len(input)). Columns are byte-based, not rune-based.
func naiveLocation(input []byte, idx int) models.Location {
	line, lineStart := 1, 0
	for i := 0; i < idx && i < len(input); i++ {
		if input[i] == '\n' {
			line++
			lineStart = i + 1
		}
	}
	column := 1
	for i := lineStart; i < idx && i < len(input); i++ {
		column++
	}
	return models.Location{Line: line, Column: column}
}

// skipTriviaBytes returns the offset of the first byte at or after i that is
// neither whitespace nor part of a "--" or "/* */" comment. It is an
// independent reimplementation of what the tokenizer skips before a token.
func skipTriviaBytes(input []byte, i int) int {
	for i < len(input) {
		switch {
		case input[i] == ' ' || input[i] == '\t' || input[i] == '\r' || input[i] == '\n':
			i++
		case bytes.HasPrefix(input[i:], []byte("--")):
			nl := bytes.IndexByte(input[i:], '\n')
			if nl < 0 {
				return len(input)
			}
			i += nl + 1
		case bytes.HasPrefix(input[i:], []byte("/*")):
			end := bytes.Index(input[i+2:], []byte("*/"))
			if end < 0 {
				return len(input)
			}
			i += 2 + end + 2
		default:
			return i
		}
	}
	return i
}

// positionTestInputs covers the shapes that stress the line lookup and the
// forward column cursor.
func positionTestInputs() map[string]string {
	var manyComments strings.Builder
	manyComments.WriteString("SELECT a")
	for i := 0; i < 40; i++ {
		manyComments.WriteString(" /* c */ + a")
	}
	manyComments.WriteString(" FROM t")

	return map[string]string{
		"empty":               "",
		"single_line":         "SELECT id, name FROM users WHERE id = 1",
		"tab_line_start":      "\tSELECT\t\tx\n\t\ty",
		"tab_mid_line":        "SELECT a,\tb,\t\tc FROM t",
		"mixed_tabs_spaces":   "SELECT\n  \t a,\n\t  b\nFROM \t t",
		"crlf":                "SELECT a,\r\n  b\r\nFROM t\r\nWHERE a = 1\r\n",
		"blank_lines":         "SELECT a\n\n\n\nFROM t\n\n",
		"trailing_newline":    "SELECT 1\n",
		"no_trailing_newline": "SELECT 1\nFROM dual",
		"utf8":                "SELECT \"名前\", 'héllo wörld' FROM ユーザー\n\tWHERE 名前 = 'ü'",
		"line_comments":       "SELECT a -- first\n  , b -- second\nFROM t --last",
		"block_comments":      "SELECT /* one\n two\n\tthree */ a\nFROM /* x */ t /* multi\nline */ WHERE b = 2",
		"many_block_comments": manyComments.String(),
		"tabbed_three_lines":  "\tSELECT a,\tb\n\t\tFROM t\n\t\t\tWHERE c = 'x'",
		"large_in_clause":     string(largeInClauseSQL),
	}
}

// tokenByteBounds replays Tokenize's scanning loop white-box and returns the
// [start, end) byte offsets of every non-EOF token, independent of
// toSQLPosition's result values. A token starts after the whitespace and
// comments before it.
func tokenByteBounds(t *testing.T, tkz *Tokenizer, input []byte) [][2]int {
	t.Helper()
	tkz.load(input, string(input))
	for i := 0; i < len(input); i++ {
		if input[i] == '\n' {
			tkz.lineStarts = append(tkz.lineStarts, i+1)
		}
	}
	var bounds [][2]int
	for tkz.pos.Index < len(tkz.input) {
		tkz.skipWhitespace()
		if tkz.pos.Index >= len(tkz.input) {
			break
		}
		start := skipTriviaBytes(input, tkz.pos.Index)
		if _, err := tkz.nextToken(); err != nil {
			t.Fatalf("replay nextToken: %v", err)
		}
		bounds = append(bounds, [2]int{start, tkz.pos.Index})
	}
	return bounds
}

func TestTokenizePositions_MatchReference(t *testing.T) {
	for name, sql := range positionTestInputs() {
		t.Run(name, func(t *testing.T) {
			input := []byte(sql)
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)

			tokens, err := tkz.Tokenize(input)
			if err != nil {
				t.Fatalf("Tokenize: %v", err)
			}
			comments := append([]models.Comment(nil), tkz.Comments...)

			// Token spans must equal the reference at the token byte bounds.
			bounds := tokenByteBounds(t, pooledTokenizer(t), input)
			if len(bounds) != len(tokens)-1 {
				t.Fatalf("replay found %d tokens, Tokenize returned %d (+EOF)", len(bounds), len(tokens)-1)
			}
			for i, b := range bounds {
				if want := naiveLocation(input, b[0]); tokens[i].Start != want {
					t.Errorf("token %d (%q) Start = %+v, want %+v", i, tokens[i].Token.Value, tokens[i].Start, want)
				}
				if want := naiveLocation(input, b[1]); tokens[i].End != want {
					t.Errorf("token %d (%q) End = %+v, want %+v", i, tokens[i].Token.Value, tokens[i].End, want)
				}
			}
			eof := tokens[len(tokens)-1]
			if want := naiveLocation(input, len(input)); eof.Start != want || eof.End != want {
				t.Errorf("EOF span = %+v-%+v, want %+v", eof.Start, eof.End, want)
			}

			// Comment start locations must match the reference too.
			from := 0
			for _, c := range comments {
				off := bytes.Index(input[from:], []byte(c.Text))
				if off < 0 {
					t.Fatalf("comment %q not found in input", c.Text)
				}
				off += from
				if want := naiveLocation(input, off); c.Start != want {
					t.Errorf("comment %q Start = %+v, want %+v", c.Text, c.Start, want)
				}
				from = off + len(c.Text)
			}

			// Every byte offset, ascending, exercises the forward cursor.
			if _, err := tkz.Tokenize(input); err != nil {
				t.Fatalf("Tokenize: %v", err)
			}
			for i := 0; i <= len(input); i++ {
				if got, want := tkz.toSQLPosition(Position{Index: i}), naiveLocation(input, i); got != want {
					t.Fatalf("toSQLPosition(%d) = %+v, want %+v", i, got, want)
				}
			}
			// Out-of-range offsets clamp to the end of input, as before.
			for _, i := range []int{len(input) + 5, len(input) + 1} {
				if got, want := tkz.toSQLPosition(Position{Index: i}), naiveLocation(input, i); got != want {
					t.Fatalf("toSQLPosition(%d) = %+v, want %+v", i, got, want)
				}
			}
		})
	}
}

// pooledTokenizer returns a pooled tokenizer that is returned on cleanup.
func pooledTokenizer(t *testing.T) *Tokenizer {
	t.Helper()
	tkz := GetTokenizer()
	t.Cleanup(func() { PutTokenizer(tkz) })
	return tkz
}

func TestToSQLPosition_BackwardAndRandomRequests(t *testing.T) {
	for name, sql := range positionTestInputs() {
		t.Run(name, func(t *testing.T) {
			input := []byte(sql)
			tkz := pooledTokenizer(t)
			if _, err := tkz.Tokenize(input); err != nil {
				t.Fatalf("Tokenize: %v", err)
			}

			for i := len(input); i >= 0; i-- {
				if got, want := tkz.toSQLPosition(Position{Index: i}), naiveLocation(input, i); got != want {
					t.Fatalf("descending toSQLPosition(%d) = %+v, want %+v", i, got, want)
				}
			}

			rng := rand.New(rand.NewSource(1))
			order := rng.Perm(len(input) + 1)
			for _, i := range order {
				if got, want := tkz.toSQLPosition(Position{Index: i}), naiveLocation(input, i); got != want {
					t.Fatalf("random toSQLPosition(%d) = %+v, want %+v", i, got, want)
				}
			}
		})
	}
}

type wantSpan struct {
	value      string
	start, end models.Location
}

func assertSpans(t *testing.T, sql string, want []wantSpan) {
	t.Helper()
	tkz := pooledTokenizer(t)
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Tokenize(%q): %v", sql, err)
	}
	for _, w := range want {
		found := false
		for _, tok := range tokens {
			if tok.Token.Value != w.value {
				continue
			}
			found = true
			if tok.Start != w.start || tok.End != w.end {
				t.Errorf("%q span = %+v-%+v, want %+v-%+v", w.value, tok.Start, tok.End, w.start, w.end)
			}
			break
		}
		if !found {
			t.Errorf("token %q not found in %q", w.value, sql)
		}
	}
}

func TestToSQLPosition_Tabs(t *testing.T) {
	assertSpans(t, "\tSELECT\t\tx\n\t\ty", []wantSpan{
		{"SELECT", models.Location{Line: 1, Column: 2}, models.Location{Line: 1, Column: 8}},
		{"x", models.Location{Line: 1, Column: 10}, models.Location{Line: 1, Column: 11}},
		{"y", models.Location{Line: 2, Column: 3}, models.Location{Line: 2, Column: 4}},
	})
}

func TestToSQLPosition_MultiLine(t *testing.T) {
	sql := "SELECT a\n  , bb -- trailing\nFROM t /* spans\nlines */ WHERE c"
	assertSpans(t, sql, []wantSpan{
		{"SELECT", models.Location{Line: 1, Column: 1}, models.Location{Line: 1, Column: 7}},
		{"a", models.Location{Line: 1, Column: 8}, models.Location{Line: 1, Column: 9}},
		{"bb", models.Location{Line: 2, Column: 5}, models.Location{Line: 2, Column: 7}},
		// A token's Start is the token itself, not the comment before it.
		// First token after a line comment.
		{"FROM", models.Location{Line: 3, Column: 1}, models.Location{Line: 3, Column: 5}},
		{"t", models.Location{Line: 3, Column: 6}, models.Location{Line: 3, Column: 7}},
		// First token after a block comment spanning lines 3-4.
		{"WHERE", models.Location{Line: 4, Column: 10}, models.Location{Line: 4, Column: 15}},
		{"c", models.Location{Line: 4, Column: 16}, models.Location{Line: 4, Column: 17}},
	})
}

func spansOf(t *testing.T, tkz *Tokenizer, sql string) []models.TokenWithSpan {
	t.Helper()
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Tokenize(%q): %v", sql, err)
	}
	return tokens
}

func equalSpans(a, b []models.TokenWithSpan) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Start != b[i].Start || a[i].End != b[i].End || a[i].Token.Value != b[i].Token.Value {
			return false
		}
	}
	return true
}

func TestToSQLPosition_PooledReuse(t *testing.T) {
	long := strings.Repeat("\tSELECT a,\t\tb FROM t WHERE x = 'long value'\n", 50) + "\t\t\tLIMIT 10"
	short := "SELECT c FROM u"

	fresh, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	wantShort := spansOf(t, fresh, short)
	fresh2, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	wantLong := spansOf(t, fresh2, long)

	// Long then short across PutTokenizer/GetTokenizer.
	a := GetTokenizer()
	_ = spansOf(t, a, long)
	PutTokenizer(a)
	b := GetTokenizer()
	if got := spansOf(t, b, short); !equalSpans(got, wantShort) {
		t.Errorf("short after long (pooled): spans differ from fresh tokenizer:\n got  %+v\n want %+v", got, wantShort)
	}
	PutTokenizer(b)

	// Short then long.
	c := GetTokenizer()
	_ = spansOf(t, c, short)
	PutTokenizer(c)
	d := GetTokenizer()
	defer PutTokenizer(d)
	if got := spansOf(t, d, long); !equalSpans(got, wantLong) {
		t.Errorf("long after short (pooled): spans differ from fresh tokenizer")
	}

	// Same tokenizer reused directly without the pool in between.
	_ = spansOf(t, d, long)
	if got := spansOf(t, d, short); !equalSpans(got, wantShort) {
		t.Errorf("short after long (same tokenizer): spans differ from fresh tokenizer")
	}

	// White-box: Reset invalidates the line hint.
	_ = spansOf(t, d, "SELECT a\nFROM t")
	if d.posCacheLine != 1 {
		t.Errorf("after 2-line input, posCacheLine = %d, want 1 (last line)", d.posCacheLine)
	}
	d.Reset()
	if d.posCacheLine != 0 {
		t.Errorf("after Reset, posCacheLine = %d, want 0", d.posCacheLine)
	}

	// A position request at offset 0 on new input must be {1,1}.
	_ = spansOf(t, d, long)
	_ = spansOf(t, d, short)
	if got := d.toSQLPosition(Position{Index: 0}); got != (models.Location{Line: 1, Column: 1}) {
		t.Errorf("toSQLPosition(0) on new input = %+v, want {1 1}", got)
	}
}

func TestTokenizeContext_PositionsMatchTokenize(t *testing.T) {
	for name, sql := range positionTestInputs() {
		t.Run(name, func(t *testing.T) {
			tkz := pooledTokenizer(t)
			want, err := tkz.Tokenize([]byte(sql))
			if err != nil {
				t.Fatalf("Tokenize: %v", err)
			}
			got, err := tkz.TokenizeContext(context.Background(), []byte(sql))
			if err != nil {
				t.Fatalf("TokenizeContext: %v", err)
			}
			if !equalSpans(got, want) {
				t.Errorf("TokenizeContext spans differ from Tokenize spans")
			}
		})
	}
}
