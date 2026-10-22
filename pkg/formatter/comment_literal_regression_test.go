// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestNestedHintSkipsDialectQuotedText(t *testing.T) {
	tests := []struct {
		name, source, rendered, want string
		dialect                      keywords.SQLDialect
	}{
		{"postgres backslash", `SELECT 'abc\' AS a, (SELECT /*+ H */ 1) AS b, 'SELECT' AS c`, `SELECT 'abc\' AS a, (SELECT 1) AS b, 'SELECT' AS c`, `SELECT 'abc\' AS a, (SELECT /*+ H */ 1) AS b, 'SELECT' AS c`, keywords.DialectPostgreSQL},
		{"sqlserver bracket", `SELECT [SELECT] AS a, (SELECT /*+ H */ 1) AS b`, `SELECT [SELECT] AS a, (SELECT 1) AS b`, `SELECT [SELECT] AS a, (SELECT /*+ H */ 1) AS b`, keywords.DialectSQLServer},
		{"postgres dollar", `SELECT $$SELECT$$ AS a, (SELECT /*+ H */ 1) AS b`, `SELECT $$SELECT$$ AS a, (SELECT 1) AS b`, `SELECT $$SELECT$$ AS a, (SELECT /*+ H */ 1) AS b`, keywords.DialectPostgreSQL},
		{"oracle q quote", `SELECT q'[SELECT]' AS a, (SELECT /*+ H */ 1) AS b`, `SELECT q'[SELECT]' AS a, (SELECT 1) AS b`, `SELECT q'[SELECT]' AS a, (SELECT /*+ H */ 1) AS b`, keywords.DialectOracle},
		{"mysql national", `SELECT N'SELECT' AS a, (SELECT /*+ H */ 1) AS b`, `SELECT N'SELECT' AS a, (SELECT 1) AS b`, `SELECT N'SELECT' AS a, (SELECT /*+ H */ 1) AS b`, keywords.DialectMySQL},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)
			tkz.SetDialect(tc.dialect)
			tokens, err := tkz.TokenizeString(tc.source)
			if err != nil {
				t.Fatal(err)
			}
			got, err := JoinWithComments([]string{tc.rendered}, tokens, tkz.Comments, CommentLayout{Dialect: string(tc.dialect)})
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSQLServerBatchJoinKeepsGoOnOwnLine(t *testing.T) {
	layout := CommentLayout{Dialect: string(keywords.DialectSQLServer), Terminator: ";", Gap: " "}
	got, err := JoinWithComments([]string{"SELECT 1", "GO 2", "SELECT 2"}, nil, nil, layout)
	if err != nil || got != "SELECT 1;\nGO 2\nSELECT 2" {
		t.Fatalf("plain join = %q, %v", got, err)
	}

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tkz.SetDialect(keywords.DialectSQLServer)
	tokens, err := tkz.TokenizeString("SELECT 1\nGO -- batch\nSELECT /*+ H */ 2")
	if err != nil {
		t.Fatal(err)
	}
	got, err = JoinWithComments([]string{"SELECT 1", "GO", "SELECT 2"}, tokens, tkz.Comments, layout)
	if err != nil || got != "SELECT 1;\nGO -- batch\nSELECT /*+ H */ 2" {
		t.Fatalf("comment join = %q, %v", got, err)
	}

	tokens, err = tkz.TokenizeString("SELECT 1\nGO 3 -- repeat\nGO\nSELECT 2")
	if err != nil {
		t.Fatal(err)
	}
	got, err = JoinWithComments([]string{"SELECT 1", "GO 3", "GO", "SELECT 2"}, tokens, tkz.Comments, layout)
	if err != nil || got != "SELECT 1;\nGO 3 -- repeat\nGO\nSELECT 2" {
		t.Fatalf("repeat and consecutive join = %q, %v", got, err)
	}

	tokens, err = tkz.TokenizeString("SELECT 1;\nGO\n;SELECT 2 -- hi")
	if err != nil {
		t.Fatal(err)
	}
	got, err = JoinWithComments([]string{"SELECT 1", "GO", "SELECT 2"}, tokens, tkz.Comments, layout)
	if err != nil || got != "SELECT 1;\nGO\nSELECT 2 -- hi" {
		t.Fatalf("empty semicolon after GO join = %q, %v", got, err)
	}

	other := layout
	other.Dialect = string(keywords.DialectPostgreSQL)
	got, err = JoinWithComments([]string{"SELECT 1", "GO", "SELECT 2"}, nil, nil, other)
	if err != nil || got != "SELECT 1; GO; SELECT 2" {
		t.Fatalf("other dialect join = %q, %v", got, err)
	}
}
