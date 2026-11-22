// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package batch_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/batch"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestEnd(t *testing.T) {
	for _, tc := range []struct {
		name, sql string
		want      bool
	}{
		{"bare", "GO", true},
		{"repeat", "go 3 -- repeat\nSELECT 1", true},
		{"quoted", "[GO]", false},
		{"double quoted", `"GO"`, false},
		{"string", "'GO'", false},
		{"fraction", "GO 1.5", false},
		{"zero", "GO 0", false},
		{"trailing word", "GO SELECT 1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)
			tkz.SetDialect(keywords.DialectSQLServer)
			tokens, err := tkz.TokenizeString(tc.sql)
			if err != nil {
				t.Fatal(err)
			}
			if _, got := batch.End(tokens, 0); got != tc.want {
				t.Errorf("End(%q) = %v, want %v", tc.sql, got, tc.want)
			}
			for i := range tokens {
				tokens[i].Start.Line = 0
				tokens[i].End.Line = 0
			}
			if _, got := batch.End(tokens, 0); got {
				t.Error("tokens without spans must not form batch separators")
			}
		})
	}
}
