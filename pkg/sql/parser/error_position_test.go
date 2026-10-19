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

package parser

import (
	stderrors "errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Parse errors are reported at the offending token: a tab is one column, and
// comments or whitespace before the token do not move the position (#797).
func TestParseError_PositionIsTheOffendingToken(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		line int
		col  int
		// text is what the editor shows at the reported position.
		text string
	}{
		{
			name: "tab before the error",
			sql:  "SELECT 1 FROM t\tWHERE x = = 1",
			line: 1, col: 27, text: "=",
		},
		{
			name: "block comment before the error",
			sql:  "SELECT * FROM t WHERE x = 1 /* x */ )",
			line: 1, col: 37, text: ")",
		},
		{
			name: "tab and comments before the error",
			sql:  "SELECT 1\tFROM t WHERE x = 1 /* a */ /* b */ )",
			line: 1, col: 45, text: ")",
		},
		{
			name: "multi-line with indentation and comments",
			sql:  "SELECT a\n\tFROM t -- note\n\t/* more\n\tlines */ WHERE ) x",
			line: 4, col: 17, text: ")",
		},
		{
			name: "multi-byte characters before the error count their bytes",
			sql:  "SELECT 'é' /* ü */ FROM t WHERE ) x",
			line: 1, col: 35, text: ")",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)
			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("tokenize: %v", err)
			}
			p := NewParser()
			defer p.Release()
			_, err = p.ParseFromModelTokens(tokens)
			if err == nil {
				t.Fatalf("expected a parse error for %q", tt.sql)
			}

			var se *errors.Error
			if !stderrors.As(err, &se) {
				t.Fatalf("expected a structured error, got %T: %v", err, err)
			}
			want := models.Location{Line: tt.line, Column: tt.col}
			if se.Location != want {
				t.Errorf("location = %+v, want %+v (error: %v)", se.Location, want, err)
			}
			if msg := fmt.Sprintf("line %d, column %d", tt.line, tt.col); !strings.Contains(err.Error(), msg) {
				t.Errorf("message %q does not say %q", err.Error(), msg)
			}

			// The reported byte is the token the error is about.
			if got := byteAt(tt.sql, want); got != tt.text {
				t.Errorf("text at %+v is %q, want %q", want, got, tt.text)
			}
		})
	}
}

// byteAt returns the one-byte string at loc, where Column counts bytes from 1.
func byteAt(sql string, loc models.Location) string {
	line, start := 1, 0
	for i := 0; i < len(sql) && line < loc.Line; i++ {
		if sql[i] == '\n' {
			line++
			start = i + 1
		}
	}
	i := start + loc.Column - 1
	if i < 0 || i >= len(sql) {
		return ""
	}
	return sql[i : i+1]
}
