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

package cmd

import "testing"

// TestFormatSQL_StringEscapesByDialect checks the CLI formatter on string
// literals whose backslashes mean different things per dialect. Without
// --dialect the escape cannot be interpreted, so the input is refused rather
// than rewritten (it used to come back with every backslash doubled, which
// PostgreSQL reads as a different value). A NUL escape is written back as \0
// instead of being dropped.
func TestFormatSQL_StringEscapesByDialect(t *testing.T) {
	tests := []struct {
		name    string
		dialect string
		in      string
		want    string
		wantErr bool
	}{
		{name: "no dialect path", in: `SELECT 'C:\dir', 'x\.y' FROM t`, wantErr: true},
		{name: "no dialect NUL", in: `SELECT 'a\0b'`, wantErr: true},
		{name: "no dialect known escapes", in: `SELECT 'a\nb', 'c\\d'`, want: `SELECT 'a\nb', 'c\\d'`},
		{name: "postgresql path", dialect: "postgresql", in: `SELECT 'C:\dir', 'x\.y' FROM t`, want: `SELECT 'C:\dir', 'x\.y' FROM t`},
		{name: "mysql NUL", dialect: "mysql", in: `SELECT 'a\0b'`, want: `SELECT 'a\0b'`},
		{name: "snowflake unknown escape", dialect: "snowflake", in: `SELECT 'C:\temp\q'`, want: "SELECT 'C:\temp" + `q'`},
		{name: "snowflake incomplete hex", dialect: "snowflake", in: `SELECT 'C:\temp\x'`, wantErr: true},
		{name: "postgresql leading quote", dialect: "postgresql", in: `SELECT '''a' FROM t`, want: `SELECT '''a' FROM t`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := formatWith(tc.in, CLIFormatterOptions{Compact: true, Uppercase: true, Dialect: tc.dialect})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("formatSQL(%q) = %q, want an error", tc.in, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("formatSQL(%q): %v", tc.in, err)
			}
			if out != tc.want {
				t.Fatalf("formatSQL(%q) = %q, want %q", tc.in, out, tc.want)
			}
		})
	}
}
