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

package formatter_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// formatWithDialect parses sql in dialect d and formats it with style.
func formatWithDialect(t *testing.T, sql string, d keywords.SQLDialect, style ast.FormatOptions) string {
	t.Helper()
	tree, err := parser.ParseWithDialect(sql, d)
	if err != nil {
		t.Fatalf("ParseWithDialect(%q, %s): %v", sql, d, err)
	}
	defer ast.ReleaseAST(tree)
	return formatter.FormatAST(tree, style)
}

// TestFormatAST_MySQLPipesKeepSpelling_Issue781 checks that formatting MySQL
// or MariaDB SQL keeps ||. The parser reads it as logical OR (the server
// default), but a server running with PIPES_AS_CONCAT reads it as
// concatenation; writing OR back would change the meaning there, so the
// formatter must emit the source spelling.
func TestFormatAST_MySQLPipesKeepSpelling_Issue781(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"select_list_chain",
			"SELECT first_name || ' ' || last_name AS fullname FROM users",
			"SELECT first_name || ' ' || last_name AS fullname FROM users"},
		{"where_mixed_spellings",
			"SELECT * FROM t WHERE a = 1 || b = 2 OR c = 3",
			"SELECT * FROM t WHERE a = 1 || b = 2 OR c = 3"},
		{"keyword_or_unchanged",
			"SELECT * FROM t WHERE a = 1 OR b = 2",
			"SELECT * FROM t WHERE a = 1 OR b = 2"},
	}
	styles := map[string]ast.FormatOptions{
		"compact": ast.CompactStyle(),
		"lower": func() ast.FormatOptions {
			s := ast.CompactStyle()
			s.KeywordCase = ast.KeywordLower
			return s
		}(),
	}
	for _, d := range []keywords.SQLDialect{keywords.DialectMySQL, keywords.DialectMariaDB} {
		for _, tc := range cases {
			t.Run(string(d)+"/"+tc.name, func(t *testing.T) {
				got := formatWithDialect(t, tc.in, d, styles["compact"])
				if got != tc.want {
					t.Fatalf("FormatAST(%q) = %q, want %q", tc.in, got, tc.want)
				}
				// Formatting is a fixpoint.
				if again := formatWithDialect(t, got, d, styles["compact"]); again != got {
					t.Fatalf("re-format of %q = %q", got, again)
				}
				// Keyword case never rewrites the || spelling.
				lower := formatWithDialect(t, tc.in, d, styles["lower"])
				if wantPipes, gotPipes := countPipes(tc.in), countPipes(lower); wantPipes != gotPipes {
					t.Fatalf("lower-case format %q has %d ||, want %d", lower, gotPipes, wantPipes)
				}
			})
		}
	}
}

func countPipes(s string) int {
	n := 0
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '|' && s[i+1] == '|' {
			n++
			i++
		}
	}
	return n
}
