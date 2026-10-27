// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package batch_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/batch"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestCommentedLines(t *testing.T) {
	for _, tc := range []struct {
		text string
		want bool
	}{
		{"GO", true}, {"go", true}, {"GO 2", true}, {"GO 2 -- c", true},
		{"GO -- c", true}, {"GO /* c */", true}, {"GO 2 /* c */", true},
		{"GO /* multi\nline */", true}, {"GO 0", false}, {"GO x", false},
		{"GO 2 /* c */ x", false}, {"GO /* c */ 2", true},
		{"GO /* outer /* inner */ x */", false},
	} {
		for _, ending := range []string{"\n", "\r\n"} {
			t.Run(tc.text+ending, func(t *testing.T) {
				src := tc.text + ending + "SELECT 1"
				_, got := batch.TextEnd(src, 2)
				if got != tc.want {
					t.Errorf("TextEnd(%q) = %v, want %v", src, got, tc.want)
				}
				tkz := tokenizer.GetTokenizer()
				defer tokenizer.PutTokenizer(tkz)
				tkz.SetDialect(keywords.DialectSQLServer)
				tokens, err := tkz.TokenizeString(src)
				if err != nil {
					t.Fatal(err)
				}
				if _, got := batch.End(tokens, 0); got != tc.want {
					t.Errorf("End(%q) = %v, want %v", src, got, tc.want)
				}
			})
		}
	}
}
