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

package formatter

import (
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// renderJoin formats every statement of sql compactly and re-attaches its
// comments with JoinWithComments.
func renderJoin(t *testing.T, sql string, layout CommentLayout) (string, error) {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.TokenizeString(sql)
	if err != nil {
		t.Fatalf("tokenize %q: %v", sql, err)
	}
	p := parser.GetParser()
	defer parser.PutParser(p)
	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("parse %q: %v", sql, err)
	}
	defer ast.ReleaseAST(tree)

	style := ast.CompactStyle()
	style.AddSemicolon = false
	stmts := make([]string, len(tree.Statements))
	for i, s := range tree.Statements {
		stmts[i] = FormatStatement(s, style)
	}
	return JoinWithComments(stmts, tokens, tkz.Comments, layout)
}

func TestJoinWithComments(t *testing.T) {
	layout := CommentLayout{Terminator: ";", Gap: "\n"}
	tests := []struct {
		name string
		sql  string
		want string
	}{
		{"no comments", "select a from t; select b from u", "SELECT a FROM t;\nSELECT b FROM u"},
		{"leading line comment", "-- who\nselect a from t", "-- who\nSELECT a FROM t"},
		{"trailing line comment", "select a from t -- why", "SELECT a FROM t -- why"},
		{"trailing comment after semicolon stays with its statement",
			"select a from t; -- one\nselect b from u", "SELECT a FROM t; -- one\nSELECT b FROM u"},
		{"comment between statements goes before the next",
			"select a from t;\n-- two\nselect b from u", "SELECT a FROM t;\n-- two\nSELECT b FROM u"},
		{"comment after the last statement on its own line",
			"select a from t;\n-- end", "SELECT a FROM t\n-- end"},
		{"inner comment moves above its statement",
			"select a, /* b is new */ b from t", "/* b is new */\nSELECT a, b FROM t"},
		{"inner line comment moves above its statement",
			"select a, -- first\n b from t", "-- first\nSELECT a, b FROM t"},
		{"hint after first keyword stays", "select /*+ FULL(t) */ a from t", "SELECT /*+ FULL(t) */ a FROM t"},
		{"hint plus comment", "select /*+ FULL(t) */ a from t -- note", "SELECT /*+ FULL(t) */ a FROM t -- note"},
		{"hint on insert", "insert /*+ APPEND */ into t (a) values (1)", "INSERT /*+ APPEND */ INTO t (a) VALUES (1)"},
		{"hint in subquery", "select * from (select /*+ x */ 1) s", "SELECT * FROM (SELECT /*+ x */ 1) s"},
		{"hint in union branch", "select 1 union select /*+ x */ 2", "SELECT 1 union SELECT /*+ x */ 2"},
		{"hint inside a CTE body",
			"with c as (select /*+ MATERIALIZE */ * from big where f = 'select') select count(*) from c",
			"WITH c AS (SELECT /*+ MATERIALIZE */ * FROM big WHERE f = 'select') SELECT count(*) FROM c"},
		{"hints on the CTE and the main query",
			"with c as (select /*+ a */ 1) select /*+ b */ * from c",
			"WITH c AS (SELECT /*+ a */ 1) SELECT /*+ b */ * FROM c"},
		{"two hints on one keyword keep their order", "select /*+ a */ /*+ b */ 1", "SELECT /*+ a */ /*+ b */ 1"},
		{"hint on second statement", "select 1; select /*+ x */ 2", "SELECT 1;\nSELECT /*+ x */ 2"},
		{"executable comment statement kept with its semicolon",
			"/*!40101 SET x = 1 */;\nselect 1", "/*!40101 SET x = 1 */;\nSELECT 1"},
		{"comment-only statement between statements",
			"select 1;\n/*!40101 SET x = 1 */;\nselect 2", "SELECT 1;\n/*!40101 SET x = 1 */;\nSELECT 2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := renderJoin(t, tt.sql, layout)
			if err != nil {
				t.Fatalf("JoinWithComments: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

func TestJoinWithComments_RefusesWhatItCannotPlace(t *testing.T) {
	layout := CommentLayout{Terminator: ";", Gap: "\n"}
	for name, sql := range map[string]string{
		"hint after from":        "select a from /*+ x */ t",
		"executable in stmt":     "select 1 /*!50000 + 1 */",
		"executable before stmt": "/*!40101 SET x = 1 */ select 1",
		"oracle line hint":       "select --+ FULL(t)\n a from t",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := renderJoin(t, sql, layout)
			if !errors.Is(err, ErrUnplaceableComment) {
				t.Fatalf("err = %v (output %q), want ErrUnplaceableComment", err, got)
			}
		})
	}
}

func TestJoinWithComments_NeverLosesAComment(t *testing.T) {
	inputs := []string{
		"-- a\nselect 1 -- b\n; /* c */ select 2 /* d */ -- e\n-- f",
		"select /* x */ 1, /* y */ 2 from /* z */ t where a = 1 -- w",
		";;-- only\n;select 1",
		"select 1;\n\n\n/* t1 */\n/* t2 */",
	}
	for _, sql := range inputs {
		for _, layout := range []CommentLayout{
			{Terminator: ";", Gap: "\n"},
			{Terminator: ";", Gap: "\n\n"},
			{Terminator: ";", Gap: " "},
		} {
			got, err := renderJoin(t, sql, layout)
			if err != nil {
				t.Fatalf("%q: %v", sql, err)
			}
			if a, b := commentTexts(t, sql), commentTexts(t, got); strings.Join(a, "|") != strings.Join(b, "|") {
				t.Errorf("comments differ for %q (layout %+v)\n in:  %q\n out: %q\n got: %q", sql, layout, a, b, got)
			}
			// A line comment must never swallow SQL that follows it.
			if _, err := reparseCount(t, got); err != nil {
				t.Errorf("output %q does not parse: %v", got, err)
			}
		}
	}
}

func commentTexts(t *testing.T, sql string) []string {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	if _, err := tkz.TokenizeString(sql); err != nil {
		t.Fatalf("tokenize %q: %v", sql, err)
	}
	out := make([]string, 0, len(tkz.Comments))
	for _, c := range tkz.Comments {
		out = append(out, c.Text)
	}
	sort.Strings(out)
	return out
}

func reparseCount(t *testing.T, sql string) (int, error) {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.TokenizeString(sql)
	if err != nil {
		return 0, err
	}
	p := parser.GetParser()
	defer parser.PutParser(p)
	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		return 0, err
	}
	defer ast.ReleaseAST(tree)
	return len(tree.Statements), nil
}

func TestJoinWithComments_Fallback(t *testing.T) {
	// A statement count that does not match the semicolon-separated runs of
	// tokens (here: the caller passes one fewer rendered statement) puts the
	// comments in front of the first statement instead of losing them.
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.TokenizeString("select 1; -- two\nselect 2")
	if err != nil {
		t.Fatal(err)
	}
	got, err := JoinWithComments([]string{"SELECT 1"}, tokens, tkz.Comments, CommentLayout{Terminator: ";", Gap: "\n"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "-- two\nSELECT 1"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestJoinWithComments_NoComments(t *testing.T) {
	got, err := JoinWithComments([]string{"A", "B", "C"}, nil, nil, CommentLayout{Terminator: ";", Gap: " "})
	if err != nil || got != "A; B; C" {
		t.Fatalf("got %q, %v", got, err)
	}
	got, _ = JoinWithComments([]string{"A;", "B;"}, nil, nil, CommentLayout{Gap: "\n"})
	if got != "A;\nB;" {
		t.Fatalf("got %q", got)
	}
}

// TestInsertHints_RefusesWhenKeywordMoved checks that a hint on a nested
// keyword is only placed when the rendered statement has the same number of
// that keyword, so it can never land on a different one.
func TestInsertHints_RefusesWhenKeywordMoved(t *testing.T) {
	h := []placedHint{{text: "/*+ x */", keyword: "SELECT", ordinal: 1, total: 2}}
	tests := []struct {
		name string
		stmt string
		want string
		ok   bool
	}{
		{"same count", "WITH c AS (SELECT 1) SELECT 2", "WITH c AS (SELECT 1) SELECT /*+ x */ 2", true},
		{"words in strings and comments are skipped", "WITH c AS (SELECT 'select') /* select */ SELECT 2", "WITH c AS (SELECT 'select') /* select */ SELECT /*+ x */ 2", true},
		{"quoted names are skipped", `WITH "select" AS (SELECT 1) SELECT 2`, `WITH "select" AS (SELECT 1) SELECT /*+ x */ 2`, true},
		{"fewer keywords", "SELECT 2", "", false},
		{"more keywords", "SELECT 1 UNION SELECT 2 UNION SELECT 3", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := insertHints(tc.stmt, h)
			if !tc.ok {
				if !errors.Is(err, ErrUnplaceableComment) {
					t.Fatalf("err = %v (output %q), want ErrUnplaceableComment", err, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("insertHints = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// TestOccMatcher checks how a nested hint finds its keyword in the
// rendered statement: by ordinal when the occurrences keep their order, by
// signature when the renderer reordered them, and not at all when the
// occurrences cannot be told apart or were rendered differently.
func TestOccMatcher(t *testing.T) {
	occ := func(sigs ...string) []wordOcc {
		out := make([]wordOcc, len(sigs))
		for i, s := range sigs {
			out[i] = wordOcc{end: (i + 1) * 10, sig: s}
		}
		return out
	}
	tests := []struct {
		name    string
		sigs    []string
		ordinal int
		occs    []wordOcc
		want    int
		ok      bool
	}{
		{"same order", []string{"a", "b", "c"}, 1, occ("a", "b", "c"), 20, true},
		{"reordered, unique", []string{"a", "b", "c"}, 1, occ("a", "c", "b"), 30, true},
		{"reordered, duplicate signature", []string{"a", "b", "b", "c"}, 1, occ("a", "c", "b", "b"), 0, false},
		{"hinted occurrence rendered differently", []string{"a", "b", "c"}, 1, occ("a", "x", "c"), 0, false},
		{"other occurrence rendered differently", []string{"a", "b", "c"}, 1, occ("x", "c", "b"), 30, true},
		{"duplicate signature in the output", []string{"a", "b", "c"}, 1, occ("b", "c", "b"), 0, false},
		{"unchecked", nil, 1, occ("a", "x"), 20, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := placedHint{text: "/*+ h */", keyword: "SELECT", ordinal: tc.ordinal, total: len(tc.occs), sigs: tc.sigs}
			got, ok := newOccMatcher(h.sigs, tc.occs).match(h, tc.occs)
			if ok != tc.ok || (ok && got != tc.want) {
				t.Fatalf("match = %d, %v; want %d, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestJoinWithComments_FollowsParserBatches checks that the comment layer
// splits the source at the GO separators the parser reported in
// CommentLayout.Batches, and falls back to putting comments in front when
// the rendered statements and the source batches do not line up.
func TestJoinWithComments_FollowsParserBatches(t *testing.T) {
	const src = "SELECT 1 -- one\nGO\n-- two\nSELECT 2"
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tkz.SetDialect(keywords.DialectSQLServer)
	tokens, err := tkz.TokenizeString(src)
	if err != nil {
		t.Fatal(err)
	}
	comments := tkz.Comments
	var goPos models.Location
	for _, tok := range tokens {
		if tok.Token.Value == "GO" {
			goPos = tok.Start
		}
	}
	tests := []struct {
		name    string
		stmts   []string
		batches []models.Location
		want    string
	}{
		{"parser positions", []string{"SELECT 1", "GO", "SELECT 2"}, []models.Location{goPos}, "SELECT 1;\n-- one\nGO\n-- two\nSELECT 2"},
		{"recognized from tokens", []string{"SELECT 1", "GO", "SELECT 2"}, nil, "SELECT 1;\n-- one\nGO\n-- two\nSELECT 2"},
		{"parser saw no separator", []string{"SELECT 1", "GO", "SELECT 2"}, []models.Location{}, "-- one\n-- two\nSELECT 1;\nGO\nSELECT 2"},
		{"rendered kinds differ", []string{"SELECT 1", "SELECT 9", "SELECT 2"}, []models.Location{goPos}, "-- one\n-- two\nSELECT 1;\nSELECT 9;\nSELECT 2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			layout := CommentLayout{Dialect: "sqlserver", Terminator: ";", Gap: "\n", Batches: tc.batches}
			got, err := JoinWithComments(tc.stmts, tokens, comments, layout)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

// renderJoinDialect is renderJoin in a dialect, with the parser's statement
// starts and GO positions in the layout, as the formatting entry points pass
// them.
func renderJoinDialect(t *testing.T, sql string, dialect keywords.SQLDialect, layout CommentLayout) (string, error) {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tkz.SetDialect(dialect)
	tokens, err := tkz.TokenizeString(sql)
	if err != nil {
		t.Fatalf("tokenize %q: %v", sql, err)
	}
	p := parser.GetParser()
	defer parser.PutParser(p)
	p.ApplyOptions(parser.WithDialect(string(dialect)))
	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("parse %q: %v", sql, err)
	}
	defer ast.ReleaseAST(tree)

	style := ast.CompactStyle()
	style.AddSemicolon = false
	style.Dialect = string(dialect)
	stmts := make([]string, len(tree.Statements))
	for i, s := range tree.Statements {
		stmts[i] = FormatStatement(s, style)
	}
	layout.Dialect = string(dialect)
	layout.Batches = BatchPositions(tree)
	layout.Starts = StatementPositions(tree)
	return JoinWithComments(stmts, tokens, tkz.Comments, layout)
}

// TestJoinWithComments_FollowsParserStatementStarts checks that comments stay
// with their statements when a statement holds ';' (a procedure or trigger
// body) or statements are not separated by ';' (T-SQL): the source is cut at
// the parser's statement starts, not at every ';'.
func TestJoinWithComments_FollowsParserStatementStarts(t *testing.T) {
	layout := CommentLayout{Terminator: ";", Gap: "\n"}
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    string
	}{
		{"t-sql without ';' before a procedure body", keywords.DialectSQLServer,
			"-- A\nSELECT 1\nSELECT 2;\n-- B: the proc\nCREATE PROC p AS BEGIN SELECT 1; END;\n",
			"-- A\nSELECT 1;\nSELECT 2;\n-- B: the proc\nCREATE PROC p AS BEGIN SELECT 1; END"},
		{"trigger body", keywords.DialectMySQL,
			"-- Section one\nSELECT 1 FROM users;\n-- Section two: trigger\nCREATE TRIGGER t AFTER INSERT ON x FOR EACH ROW BEGIN SELECT 1; SELECT 2; END;\n-- Section three\nSELECT 3 FROM orders;\n",
			"-- Section one\nSELECT 1 FROM users;\n-- Section two: trigger\nCREATE TRIGGER t AFTER INSERT ON x FOR EACH ROW BEGIN SELECT 1; SELECT 2; END;\n-- Section three\nSELECT 3 FROM orders"},
		{"comment inside a body moves above its statement", keywords.DialectMySQL,
			"SELECT 0;\nCREATE TRIGGER t AFTER INSERT ON x FOR EACH ROW BEGIN SELECT 1; -- inner\nSELECT 2; END; -- after\nSELECT 3",
			"SELECT 0;\n-- inner\nCREATE TRIGGER t AFTER INSERT ON x FOR EACH ROW BEGIN SELECT 1; SELECT 2; END; -- after\nSELECT 3"},
		// As without starts: a comment after a stray ';' leads the next
		// statement.
		{"stray semicolons stay empty statements", keywords.DialectPostgreSQL,
			"SELECT 1;; -- one\n;\n-- two\nSELECT 2",
			"SELECT 1;\n-- one\n-- two\nSELECT 2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := renderJoinDialect(t, tc.sql, tc.dialect, layout)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

// TestJoinWithComments_StartsDisagree checks that statement starts that do
// not line up with the source fall back to hoisting every comment instead of
// attaching one to the wrong statement.
func TestJoinWithComments_StartsDisagree(t *testing.T) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.TokenizeString("select 1; -- one\nselect 2;\n-- two\nselect 3")
	if err != nil {
		t.Fatal(err)
	}
	var starts []models.Location
	for _, tok := range tokens {
		if strings.EqualFold(tok.Token.Value, "select") {
			starts = append(starts, tok.Start)
		}
	}
	stmts := []string{"SELECT 1", "SELECT 2", "SELECT 3"}
	tests := []struct {
		name   string
		starts []models.Location
		want   string
	}{
		{"agree", starts, "SELECT 1; -- one\nSELECT 2;\n-- two\nSELECT 3"},
		{"one missing", starts[:2], "-- one\n-- two\nSELECT 1;\nSELECT 2;\nSELECT 3"},
		{"shifted", []models.Location{starts[0], {Line: starts[1].Line, Column: starts[1].Column + 1}, starts[2]}, "-- one\n-- two\nSELECT 1;\nSELECT 2;\nSELECT 3"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := JoinWithComments(stmts, tokens, tkz.Comments, CommentLayout{Terminator: ";", Gap: "\n", Starts: tc.starts})
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

// TestJoinWithComments_ScalesLinearly guards against the quadratic hint
// placement and comment lookup: thousands of hints in one statement and
// thousands of commented statements must format quickly. The bounds are
// generous so that the race detector and slow CI machines pass; the
// quadratic versions took seconds.
func TestJoinWithComments_ScalesLinearly(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	tests := []struct {
		name string
		sql  string
		hint int // hints expected in the output
	}{
		{"hints", strings.Repeat("SELECT /*+ H */ 1 UNION ALL ", 3000) + "SELECT /*+ H */ 1", 3001},
		{"comments", strings.Repeat("SELECT 1; -- c\n", 20000), 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			got, err := renderJoinDialect(t, tc.sql, keywords.DialectPostgreSQL, CommentLayout{Terminator: ";", Gap: "\n"})
			elapsed := time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			if n := strings.Count(got, "SELECT /*+ H */ 1"); n != tc.hint {
				t.Errorf("%d hints in place, want %d", n, tc.hint)
			}
			if limit := 3 * time.Second; elapsed > limit {
				t.Errorf("took %v, want under %v", elapsed, limit)
			}
		})
	}
}
