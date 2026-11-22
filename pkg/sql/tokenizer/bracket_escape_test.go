// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package tokenizer

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestSQLServerBracketEscapes(t *testing.T) {
	for _, tc := range []struct{ sql, want string }{{`[a]]b]`, `a]b`}, {`[]]]`, `]`}, {`[a]]]]b]`, `a]]b`}} {
		got := lexAll(t, keywords.DialectSQLServer, tc.sql)
		if len(got) != 1 || got[0].typ != models.TokenTypeIdentifier || got[0].val != tc.want {
			t.Errorf("%s: %v", tc.sql, got)
		}
	}
	tk, err := NewWithDialect(keywords.DialectSQLServer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tk.TokenizeString(`[a]]`); err == nil {
		t.Fatal("expected unterminated identifier error")
	}
}
