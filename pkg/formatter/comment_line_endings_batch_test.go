// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestCommentsCRLF(t *testing.T) {
	for _, input := range []string{"-- leading\r\nSELECT 1 -- trailing\r\n", "SELECT /* multi\r\nline */ 1", "SELECT /*+ hint\r\ntext */ 1"} {
		out, err := renderJoinDialect(t, input, keywords.DialectPostgreSQL, CommentLayout{Gap: "\n", Terminator: ";"})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "\r") {
			t.Fatalf("CR retained in output: %q", out)
		}
	}
}

func TestCommentsCRLFHoisted(t *testing.T) {
	comments := []models.Comment{{Text: "-- leading\r"}, {Text: "/* multi\r\nline */"}}
	out, err := JoinWithComments([]string{"SELECT 1"}, nil, comments, CommentLayout{})
	if err != nil {
		t.Fatal(err)
	}
	if out != "-- leading\n/* multi\nline */\nSELECT 1" {
		t.Fatalf("hoisted comments = %q", out)
	}
}

func TestCommentsStayOnTheirSideOfGO(t *testing.T) {
	for _, input := range []string{
		"SELECT 1\n-- before go\nGO\n-- after go\nSELECT 2",
		"SELECT 1\n-- before go\nGO 2 -- on go\n-- after go\nSELECT 2",
	} {
		for _, gap := range []string{"\n", " "} {
			out, err := renderJoinDialect(t, input, keywords.DialectSQLServer, CommentLayout{Gap: gap, Terminator: ";"})
			if err != nil {
				t.Fatal(err)
			}
			rest := out
			for _, piece := range []string{"SELECT 1", "-- before go", "GO", "-- after go", "SELECT 2"} {
				i := strings.Index(rest, piece)
				if i < 0 {
					t.Fatalf("missing or misplaced %q in %q", piece, out)
				}
				rest = rest[i+len(piece):]
			}
		}
	}
}
