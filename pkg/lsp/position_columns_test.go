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

package lsp

import (
	stderrors "errors"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// A diagnostic's range starts at the offending character as an editor counts it:
// one column per tab, and after any comment that precedes the token (#797).
func TestDiagnosticPosition_TabsAndComments(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantLine int
		wantChar int // 0-based, as LSP clients count
		wantText string
	}{
		{"tab before the error", "SELECT 1 FROM t\tWHERE x = = 1", 0, 26, "="},
		{"comment before the error", "SELECT * FROM t WHERE x = 1 /* x */ )", 0, 36, ")"},
		{"indented second line", "SELECT a\n\tFROM t\n\t\tWHERE ) x", 2, 8, ")"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := gosqlx.Parse(tt.content)
			if err == nil {
				t.Fatalf("expected a parse error for %q", tt.content)
			}
			var se *errors.Error
			if !stderrors.As(err, &se) {
				t.Fatalf("expected a structured error, got %T: %v", err, err)
			}
			lines := strings.Split(tt.content, "\n")
			diag := createDiagnosticFromError(tt.content, lines, se, 0)

			if diag.Range.Start.Line != tt.wantLine || diag.Range.Start.Character != tt.wantChar {
				t.Fatalf("diagnostic starts at %d:%d, want %d:%d",
					diag.Range.Start.Line, diag.Range.Start.Character, tt.wantLine, tt.wantChar)
			}
			if got := string(lines[tt.wantLine][tt.wantChar]); got != tt.wantText {
				t.Errorf("character at the diagnostic start is %q, want %q", got, tt.wantText)
			}
		})
	}
}

// Semantic tokens are encoded with the character offsets editors use, so a tab
// and a comment before a token do not shift it.
func TestSemanticTokens_TabAndCommentOffsets(t *testing.T) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.Tokenize([]byte("a\tb /* x */ c"))
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}
	data := encodeSemanticTokens(tokens)

	// [deltaLine, deltaStartChar, length, type, modifiers] per identifier.
	type enc struct{ dLine, dStart, length uint32 }
	var got []enc
	for i := 0; i+4 < len(data); i += 5 {
		got = append(got, enc{data[i], data[i+1], data[i+2]})
	}
	want := []enc{{0, 0, 1}, {0, 2, 1}, {0, 10, 1}} // a at 0, b at 2, c at 12
	if len(got) != len(want) {
		t.Fatalf("got %d semantic tokens, want %d: %v", len(got), len(want), data)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("token %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
