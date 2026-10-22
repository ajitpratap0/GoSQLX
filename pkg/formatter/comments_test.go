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

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
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
		"hint in subquery":       "select * from (select /*+ x */ 1) s",
		"hint after from":        "select a from /*+ x */ t",
		"hint in union branch":   "select 1 union select /*+ x */ 2",
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
