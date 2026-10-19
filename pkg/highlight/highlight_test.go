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

package highlight

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// render formats spans as "category:text" pairs for readable assertions.
func render(src string, spans []Span) string {
	parts := make([]string, 0, len(spans))
	for _, s := range spans {
		parts = append(parts, s.Category.String()+":"+s.Text(src))
	}
	return strings.Join(parts, " ")
}

// find returns the category of the first span whose text equals text.
func find(t *testing.T, src string, spans []Span, text string) Category {
	t.Helper()
	for _, s := range spans {
		if s.Text(src) == text {
			return s.Category
		}
	}
	t.Fatalf("no span with text %q in: %s", text, render(src, spans))
	return Plain
}

func TestSpans_Classification(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    map[string]Category
	}{
		{
			name: "select basics",
			sql:  "SELECT u.id, COUNT(*) AS n FROM users u WHERE u.active = TRUE AND u.deleted_at IS NULL",
			want: map[string]Category{
				"SELECT": Keyword, "u": Identifier, ".": Punctuation, "id": Identifier,
				"COUNT": Function, "*": Operator, "AS": Keyword, "users": Identifier,
				"=": Operator, "TRUE": Constant, "NULL": Constant, ",": Punctuation,
			},
		},
		{
			name: "literals",
			sql:  "SELECT 'str', 1.5e3, 0x1F, E'esc', N'nat', X'FF', $$body$$ FROM t",
			want: map[string]Category{
				"'str'": String, "1.5e3": Number, "0x1F": Number, "E'esc'": String,
				"N'nat'": String, "X'FF'": String, "$$body$$": String,
			},
		},
		{
			name: "placeholders",
			sql:  "SELECT * FROM t WHERE a = $1 AND b = ? AND c = :name AND d = @v",
			want: map[string]Category{"$1": Placeholder, "?": Placeholder, ":name": Placeholder, "@v": Placeholder},
		},
		{
			name: "comments",
			sql:  "-- lead\nSELECT 1 /* inline */ FROM t -- tail",
			want: map[string]Category{"-- lead": Comment, "/* inline */": Comment, "-- tail": Comment, "SELECT": Keyword},
		},
		{
			name: "non-reserved keywords the tokenizer leaves as identifiers",
			sql:  "INSERT INTO t (a) VALUES (1) RETURNING a",
			want: map[string]Category{"RETURNING": Keyword, "INTO": Keyword, "VALUES": Keyword, "t": Identifier},
		},
		{
			name: "column definitions",
			sql:  "CREATE TABLE t (id INT PRIMARY KEY, name VARCHAR(10) NOT NULL, d DOUBLE PRECISION, ts TIMESTAMP DEFAULT now())",
			want: map[string]Category{
				"INT": DataType, "VARCHAR": DataType, "DOUBLE": DataType, "PRECISION": DataType,
				"TIMESTAMP": DataType, "now": Function, "PRIMARY": Keyword, "id": Identifier,
			},
		},
		{
			name: "type casts",
			sql:  "SELECT x::int, CAST(y AS DATE), date FROM t",
			want: map[string]Category{"::": Operator, "int": DataType, "CAST": Function, "DATE": DataType, "date": Identifier},
		},
		{
			name: "column lists are not calls",
			sql:  "INSERT INTO users (id) SELECT id FROM s; CREATE INDEX idx ON users (id)",
			want: map[string]Category{"users": Identifier, "idx": Identifier},
		},
		{
			name: "qualified names",
			sql:  "SELECT s.fn(x), t.null, t.order FROM s",
			want: map[string]Category{"fn": Function, "null": Identifier},
		},
		{
			name:    "mysql backticks and double-quoted strings",
			dialect: keywords.DialectMySQL,
			sql:     "SELECT `a b`, \"str\" FROM t",
			want:    map[string]Category{"`a b`": QuotedIdentifier, `"str"`: String},
		},
		{
			name: "standard double-quoted identifiers",
			sql:  `SELECT "Col" FROM t`,
			want: map[string]Category{`"Col"`: QuotedIdentifier},
		},
		{
			name:    "sql server",
			dialect: keywords.DialectSQLServer,
			sql:     "DECLARE @x INT; SELECT [c d], @@VERSION FROM #tmp",
			want: map[string]Category{
				"DECLARE": Keyword, "@x": Placeholder, "INT": DataType, "[c d]": QuotedIdentifier,
				"@@VERSION": Placeholder, "#tmp": Identifier,
			},
		},
		{
			name:    "clickhouse nested types",
			dialect: keywords.DialectClickHouse,
			sql:     "CREATE TABLE t (a Nullable(String), m Map(String, UInt64)) ENGINE = MergeTree()",
			want: map[string]Category{
				"Nullable": DataType, "String": DataType, "Map": DataType, "UInt64": DataType, "MergeTree": Function,
			},
		},
		{
			name: "json operators",
			sql:  "SELECT j->>'k', j->'a' FROM t",
			want: map[string]Category{"->>": Operator, "->": Operator, "'k'": String},
		},
		{
			name: "tabs (tokenizer counts a tab as 4 columns)",
			sql:  "\tSELECT\ta,\tb\tFROM\tt /* x */\tWHERE\tc = '\tv'",
			want: map[string]Category{
				"SELECT": Keyword, "a": Identifier, "b": Identifier, "FROM": Keyword, "t": Identifier,
				"/* x */": Comment, "WHERE": Keyword, "'\tv'": String,
			},
		},
		{
			name: "tabs on later lines",
			sql:  "SELECT 1\n\t\tFROM\tt\n\tWHERE x = 1",
			want: map[string]Category{"FROM": Keyword, "t": Identifier, "WHERE": Keyword, "x": Identifier},
		},
		{
			name: "keywords before a parenthesis that are not calls",
			sql:  "CREATE TABLE t (id INT, UNIQUE (id), c INT DEFAULT (now()), CHECK (id > 0)); SELECT a IN (1) FROM t WHERE EXISTS (SELECT 1)",
			want: map[string]Category{
				"UNIQUE": Keyword, "DEFAULT": Keyword, "CHECK": Keyword, "IN": Keyword, "EXISTS": Keyword, "now": Function,
			},
		},
		{
			name: "token types outside the classified ranges",
			sql:  "SELECT a FROM t WHERE a ILIKE 'x' OR b NOT ILIKE 'y'",
			want: map[string]Category{"ILIKE": Keyword},
		},
		{
			name: "unicode",
			sql:  "SELECT é, 'ünï' FROM t",
			want: map[string]Category{"é": Identifier, "'ünï'": String},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spans := Spans(tt.sql, WithDialect(tt.dialect))
			assertInvariants(t, tt.sql, spans)
			for text, want := range tt.want {
				if got := find(t, tt.sql, spans, text); got != want {
					t.Errorf("%q: got %s, want %s\nall: %s", text, got, want, render(tt.sql, spans))
				}
			}
		})
	}
}

func TestSpans_ErrorRecovery(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		want    string
	}{
		{"", "SELECT 'ok', 'unterminated", "keyword:SELECT string:'ok' punctuation:, error:'unterminated"},
		{"", "SELECT 1 /* open", "keyword:SELECT number:1 error:/* open"},
		{"", "'x", "error:'x"},
		{"", "\tSELECT 1 /* x", "keyword:SELECT number:1 error:/* x"},
		{"", "\t\tSELECT a, 'abc", "keyword:SELECT identifier:a punctuation:, error:'abc"},
		// The tokenizer reports column 0 for a quoted identifier broken by a
		// newline, and the end of input for unterminated dollar quotes.
		{"", "SELECT 1,\n\"abc\nFROM t", "keyword:SELECT number:1 punctuation:, error:\"abc\nFROM t"},
		{"", "\n\"\n", "error:\"\n"},
		{"", "SELECT $$body", "keyword:SELECT error:$$body"},
		{"", "SELECT $$a$$, $t$b$t$; SELECT $tag$body", "keyword:SELECT string:$$a$$ punctuation:, string:$t$b$t$ punctuation:; keyword:SELECT error:$tag$body"},
		{keywords.DialectSQLServer, "SELECT [col", "keyword:SELECT error:[col"},
		{keywords.DialectMySQL, `SELECT 'it\'s', 'open`, `keyword:SELECT string:'it\'s' punctuation:, error:'open`},
	}
	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			spans := Spans(tt.sql, WithDialect(tt.dialect))
			assertInvariants(t, tt.sql, spans)
			if got := render(tt.sql, spans); got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

func TestSpans_EmptyAndWhitespace(t *testing.T) {
	if got := Spans(""); got != nil {
		t.Errorf("empty input: got %v, want nil", got)
	}
	if got := Spans("  \n\t "); len(got) != 0 {
		t.Errorf("whitespace input: got %v, want no spans", got)
	}
}

func TestSpans_UnknownDialectFallsBack(t *testing.T) {
	sql := "SELECT 1"
	got := render(sql, Spans(sql, WithDialect("no-such-dialect")))
	if got != "keyword:SELECT number:1" {
		t.Errorf("got %s", got)
	}
}

func TestSpans_AllDialects(t *testing.T) {
	sql := "WITH c AS (SELECT a, SUM(b) OVER (PARTITION BY a) FROM t /* x */ WHERE d > 1) SELECT * FROM c -- end"
	for _, d := range keywords.AllDialects() {
		t.Run(string(d), func(t *testing.T) {
			spans := Spans(sql, WithDialect(d))
			assertInvariants(t, sql, spans)
			if find(t, sql, spans, "SELECT") != Keyword {
				t.Errorf("SELECT not a keyword under %s", d)
			}
			if find(t, sql, spans, "/* x */") != Comment {
				t.Errorf("block comment not a comment under %s", d)
			}
		})
	}
}

// TestSpans_Corpus runs every SQL fixture in the repository through the
// invariant checks, so tokens of new types can never silently go unhighlighted.
func TestSpans_Corpus(t *testing.T) {
	files, err := filepath.Glob("../../testdata/*/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Skip("no SQL fixtures found")
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		dialect := keywords.SQLDialect(filepath.Base(filepath.Dir(f)))
		t.Run(f, func(t *testing.T) {
			sql := string(data)
			assertInvariants(t, sql, Spans(sql, WithDialect(dialect)))
		})
	}
}

func TestSpans_JSON(t *testing.T) {
	sql := "SELECT 1"
	data, err := json.Marshal(Spans(sql))
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"start":0,"end":6,"category":"keyword"},{"start":7,"end":8,"category":"number"}]`
	if string(data) != want {
		t.Errorf("got %s\nwant %s", data, want)
	}
	var back []Span
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if render(sql, back) != "keyword:SELECT number:1" {
		t.Errorf("round trip: %s", render(sql, back))
	}
}

func TestCategory_Names(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Categories() {
		name := c.String()
		if seen[name] {
			t.Errorf("duplicate name %q", name)
		}
		seen[name] = true
		back, ok := ParseCategory(name)
		if !ok || back != c {
			t.Errorf("ParseCategory(%q) = %v, %v", name, back, ok)
		}
	}
	if _, err := Category(200).MarshalText(); err == nil {
		t.Error("expected error marshaling invalid category")
	}
	var c Category
	if err := c.UnmarshalText([]byte("bogus")); err == nil {
		t.Error("expected error unmarshaling unknown category")
	}
	if Category(200).String() != "category(200)" {
		t.Errorf("invalid category String: %s", Category(200))
	}
}

func TestSpans_Concurrent(t *testing.T) {
	sql := "SELECT a, COUNT(*) FROM t WHERE b = 'x' -- c\nGROUP BY a"
	want := render(sql, Spans(sql))
	dialects := keywords.AllDialects()
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = Spans(sql, WithDialect(dialects[i%len(dialects)]))
			if got := render(sql, Spans(sql)); got != want {
				t.Errorf("concurrent result differs: %s", got)
			}
		}(i)
	}
	wg.Wait()
}

// assertInvariants checks the contract every Spans result must satisfy.
func assertInvariants(t *testing.T, src string, spans []Span) {
	t.Helper()
	prevEnd := 0
	for i, s := range spans {
		if s.Start < prevEnd || s.Start >= s.End || s.End > len(src) {
			t.Fatalf("span %d %+v out of order or range (prevEnd=%d, len=%d)", i, s, prevEnd, len(src))
		}
		if s.Category == Plain || s.Category >= numCategories {
			t.Fatalf("span %d has invalid category %d", i, s.Category)
		}
		if !utf8.RuneStart(src[s.Start]) || (s.End < len(src) && !utf8.RuneStart(src[s.End])) {
			t.Fatalf("span %d %+v splits a UTF-8 sequence", i, s)
		}
		if s.Category == Error && s.End != len(src) {
			t.Fatalf("error span %d does not extend to end of input", i)
		}
		prevEnd = s.End
	}
	// Every non-space byte outside spans is unexpected: the tokenizer accounts
	// for all significant input.
	cursor := 0
	for _, s := range spans {
		if gap := strings.TrimSpace(src[cursor:s.Start]); gap != "" {
			t.Errorf("unclassified text %q before %+v", gap, s)
		}
		cursor = s.End
	}
	if gap := strings.TrimSpace(src[cursor:]); gap != "" && len(spans) > 0 {
		t.Errorf("unclassified trailing text %q", gap)
	}
}

func FuzzSpans(f *testing.F) {
	for _, seed := range []string{
		"SELECT * FROM t",
		"SELECT 'unterminated",
		"/* open",
		"CREATE TABLE t (a INT, b VARCHAR(3))",
		"SELECT $1, :a, @b, ?, x::int FROM t -- c",
		"SELECT `q`, [b], \"c\", N'x', 0x1F",
		"SELECT é FROM ünï",
		"\tSELECT\t1,\t2 FROM t\t/* c */\tWHERE a = '\t'",
		"\n\"\n",
		"SELECT 1; SELECT $tag$body",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, sql string) {
		if !utf8.ValidString(sql) {
			return
		}
		spans := Spans(sql)
		prevEnd := 0
		for _, s := range spans {
			if s.Start < prevEnd || s.Start >= s.End || s.End > len(sql) || s.Category == Plain {
				t.Fatalf("invalid span %+v (prevEnd=%d len=%d)", s, prevEnd, len(sql))
			}
			prevEnd = s.End
		}
		// Token spans hug their text: only lexemes that can contain
		// whitespace may start or end with it.
		for _, s := range spans {
			switch s.Category {
			case String, Comment, QuotedIdentifier, Error:
				continue
			}
			text := s.Text(sql)
			if strings.TrimSpace(text) != text {
				t.Fatalf("%s span %+v has surrounding whitespace: %q", s.Category, s, text)
			}
		}
		// Clean input never leaves significant text unclassified.
		if len(spans) == 0 || spans[len(spans)-1].Category != Error {
			cursor := 0
			for _, s := range spans {
				if gap := strings.TrimSpace(sql[cursor:s.Start]); gap != "" {
					t.Fatalf("unclassified text %q before %+v", gap, s)
				}
				cursor = s.End
			}
			if gap := strings.TrimSpace(sql[cursor:]); gap != "" {
				t.Fatalf("unclassified trailing text %q (spans: %v)", gap, spans)
			}
		}
		// Renderers must reproduce the source exactly once markup is removed.
		if got := stripANSI(ANSI(sql, spans, ANSIOptions{})); got != sql {
			t.Fatalf("ANSI round trip mismatch:\n got %q\nwant %q", got, sql)
		}
	})
}

func BenchmarkSpans(b *testing.B) {
	sql := strings.Repeat("SELECT u.id, u.name, COUNT(o.id) AS orders FROM users u "+
		"LEFT JOIN orders o ON o.user_id = u.id WHERE u.created_at > $1 -- recent\n"+
		"GROUP BY u.id, u.name HAVING COUNT(o.id) > 5 ORDER BY orders DESC LIMIT 10;\n", 10)
	b.ReportAllocs()
	b.SetBytes(int64(len(sql)))
	for i := 0; i < b.N; i++ {
		_ = Spans(sql)
	}
}

func BenchmarkHTML(b *testing.B) {
	sql := strings.Repeat("SELECT a, 'b' FROM t WHERE c = 1;\n", 50)
	spans := Spans(sql)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = HTML(sql, spans, HTMLOptions{})
	}
}
