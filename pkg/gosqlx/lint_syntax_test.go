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

package gosqlx

import (
	"errors"
	"testing"

	sqlkeywords "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// lintTolerant runs Lint for tests that exercise the rules on SQL the parser
// does not accept: the syntax error is expected, the violations are what is
// being checked.
func lintTolerant(sql string) (*LintResult, error) {
	res, err := Lint(sql)
	if err != nil && res != nil && (errors.Is(err, ErrSyntax) || errors.Is(err, ErrTokenize)) {
		return res, nil
	}
	return res, err
}

func TestLint_SyntaxErrorsAreReported(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		dialect sqlkeywords.SQLDialect
		wantErr error
	}{
		{"misspelled keyword", "SELEC FROM", "", ErrSyntax},
		{"incomplete statement", "SELECT FROM WHERE (", "", ErrSyntax},
		{"unterminated string", "SELECT 'abc", "", ErrTokenize},
		{"dialect: syntax error", "SELEC FROM", sqlkeywords.DialectPostgreSQL, ErrSyntax},
		{"dialect: tokenize error", "SELECT 'abc", sqlkeywords.DialectMySQL, ErrTokenize},
		{"valid SQL", "SELECT id FROM users WHERE id = 1", "", nil},
		{"valid SQL with dialect", "SELECT TOP 5 id FROM users", sqlkeywords.DialectSQLServer, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				res *LintResult
				err error
			)
			if tt.dialect == "" {
				res, err = Lint(tt.sql)
			} else {
				res, err = LintWithDialect(tt.sql, tt.dialect)
			}
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want it to wrap %v", err, tt.wantErr)
			}
			if res == nil {
				t.Fatal("result is nil; the violations of the text and token rules must still be returned")
			}
		})
	}
}

func TestLint_SyntaxErrorKeepsTextRuleViolations(t *testing.T) {
	// L001 (trailing whitespace) is a text rule and must still fire on SQL
	// that does not parse.
	res, err := Lint("SELEC FROM   \n")
	if !errors.Is(err, ErrSyntax) {
		t.Fatalf("err = %v, want ErrSyntax", err)
	}
	if res == nil || !hasRule(res, "L001") {
		t.Fatalf("expected L001 alongside the syntax error, got %+v", res)
	}
}
