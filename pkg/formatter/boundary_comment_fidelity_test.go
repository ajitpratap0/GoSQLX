// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestBoundaryCommentFidelity(t *testing.T) {
	cases := []struct{ name, input, want string }{
		{"statement trailing", "SELECT 1 -- t1\nGO\nSELECT 2 -- t2\n", "SELECT 1; -- t1\nGO\nSELECT 2 -- t2"},
		{"standalone", "SELECT 1\n-- before go\nGO\n-- after go\nSELECT 2\n", "SELECT 1;\n-- before go\nGO\n-- after go\nSELECT 2"},
		{"block trailing", "SELECT 1 /* b */\nGO\nSELECT 2\n", "SELECT 1; /* b */\nGO\nSELECT 2"},
		{"GO trailing", "SELECT 1\nGO -- trailing\nSELECT 2\n", "SELECT 1;\nGO -- trailing\nSELECT 2"},
		{"last GO trailing", "SELECT 1\nGO\nSELECT 2 -- t2\nGO -- g2\n", "SELECT 1;\nGO\nSELECT 2; -- t2\nGO -- g2"},
		{"repeat block", "SELECT 1\nGO 2 /* c */\nSELECT 2\n", "SELECT 1;\nGO 2 /* c */\nSELECT 2"},
		{"repeat line", "SELECT 1\nGO 2 -- c\nSELECT 2\n", "SELECT 1;\nGO 2 -- c\nSELECT 2"},
		{"repeat both", "SELECT 1\nGO 2 /* c */ -- d\nSELECT 2\n", "SELECT 1;\nGO 2 /* c */ -- d\nSELECT 2"},
		{"without GO", "SELECT 1 -- t1\nSELECT 2 -- t2\n", "SELECT 1; -- t1\nSELECT 2 -- t2"},
		{"internal", "SELECT /* inside */ 1\nGO\nSELECT 2", "/* inside */\nSELECT 1;\nGO\nSELECT 2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := keywords.DialectSQLServer
			out, err := gosqlx.FormatWithDialect(tc.input, gosqlx.DefaultFormatOptions(), d)
			if err != nil || out != tc.want {
				t.Errorf("FormatWithDialect = %q, %v; want %q", out, err, tc.want)
			}
			// ReadableStyle and Formatter terminate the final SQL statement as well.
			want := tc.want
			if !strings.Contains(tc.name, "last GO") {
				if strings.HasSuffix(want, " -- t2") {
					want = strings.TrimSuffix(want, " -- t2") + "; -- t2"
				} else {
					want += ";"
				}
			}
			out, err = formatter.New(formatter.Options{Dialect: string(d), Uppercase: true}).Format(tc.input)
			if err != nil || out != want {
				t.Errorf("Formatter = %q, %v; want %q", out, err, want)
			}
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)
			tkz.SetDialect(d)
			if _, err := tkz.TokenizeString(tc.input); err != nil {
				t.Fatal(err)
			}
			tree, err := gosqlx.ParseWithDialect(tc.input, d)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			tree.Comments = append([]models.Comment(nil), tkz.Comments...)
			opts := ast.ReadableStyle()
			out, err = formatter.FormatASTChecked(tree, opts)
			if err != nil || out != want {
				t.Errorf("FormatAST = %q, %v; want %q", out, err, want)
			}
			if strings.Contains(tc.name, "repeat") {
				again, err := gosqlx.ParseWithDialect(out, d)
				if err != nil {
					t.Fatal(err)
				}
				defer ast.ReleaseAST(again)
				sep, ok := again.Statements[1].(*ast.BatchSeparator)
				if !ok || sep.RepeatCount != 2 {
					t.Fatalf("repeat not preserved: %#v", again.Statements[1])
				}
			}
		})
	}
}
