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

package bridge

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

type bridgeInput struct{ sql, dialect string }

func bridgeCorpusInputs(t *testing.T) []bridgeInput {
	t.Helper()
	var inputs []bridgeInput
	for _, stmt := range goldens.Corpus(t) {
		half := len(stmt.SQL) / 2
		for half > 0 && !utf8.RuneStart(stmt.SQL[half]) {
			half--
		}
		for _, d := range []string{stmt.Dialect, "", "sqlserver"} {
			for _, sql := range []string{stmt.SQL, stmt.SQL[:half], stmt.SQL + " )"} {
				inputs = append(inputs, bridgeInput{sql, d})
			}
		}
	}
	for _, sql := range []string{"", "   ", "-- c", "/* c */", "SELECT 'abc", "SELECT /* x", "SELEC 1", "SELECT TOP 5 * FROM t", "SELECT a FROM t LIMIT 1"} {
		for _, d := range []string{"", "postgresql", "sqlserver", "mysql", "oracle"} {
			inputs = append(inputs, bridgeInput{sql, d})
		}
	}
	return inputs
}

func TestValidate_Dialect(t *testing.T) {
	for _, tc := range []struct {
		sql, dialect string
		valid        bool
	}{
		{"SELECT TOP 5 * FROM t", "sqlserver", true},
		{"SELECT TOP 5 * FROM t", "", false},
		{"SELECT TOP 5 * FROM t", "mysql", false},
		{"SELECT a FROM t LIMIT 1", "sqlserver", false},
		{"SELECT a FROM t LIMIT 1", "oracle", false},
		{"SELECT a FROM t LIMIT 1", "", true},
		{"SELECT a FROM t LIMIT 1", "postgresql", true},
		{"SELECT a FROM t LIMIT 1", "unknown", true},
	} {
		t.Run(tc.dialect+tc.sql, func(t *testing.T) {
			err := Validate(tc.sql, tc.dialect)
			if (err == nil) != tc.valid {
				t.Fatalf("Validate=%v valid=%v", err, tc.valid)
			}
			if err != nil && (!errors.Is(err, gosqlx.ErrSyntax) || !strings.HasPrefix(err.Error(), "gosqlx: syntax error: ")) {
				t.Fatalf("unexpected syntax error %v", err)
			}
		})
	}
	for _, d := range []string{"", "postgresql", "sqlserver", "mysql", "oracle", "unknown"} {
		if got, want := Validate("", d), gosqlx.Validate(""); got == nil || got.Error() != want.Error() {
			t.Errorf("blank %q: got %v want %v", d, got, want)
		}
	}
}

func TestValidate_ConsistentWithParse(t *testing.T) {
	inputs := bridgeCorpusInputs(t)
	goldens.Parallel(len(inputs), func(i int) {
		in := inputs[i]
		tree, parseErr := Parse(in.sql, in.dialect)
		if tree != nil {
			ast.ReleaseAST(tree)
		}
		validateErr := Validate(in.sql, in.dialect)
		if (parseErr == nil) != (validateErr == nil) {
			t.Errorf("Validate/Parse divergence sql=%q dialect=%q: Validate=%v Parse=%v", in.sql, in.dialect, validateErr, parseErr)
		}
		if noStatementTokens(in.sql, in.dialect) && (parseErr == nil || validateErr == nil) {
			t.Errorf("no-statements input sql=%q dialect=%q: Validate=%v Parse=%v", in.sql, in.dialect, validateErr, parseErr)
		}
	})
}
