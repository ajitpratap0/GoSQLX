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

package ast_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestReservedNameWordsRejectedBare guards the static reserved-name list in
// quote_names.go: every word must be rejected bare by the parser in every
// position it is listed for, in every dialect, so quoting it on output always
// reproduces the source. The double-quoted form must parse and its SQL()
// must re-parse. If this test fails because the parser started accepting a
// word bare, remove that word from reservedNameWords (or demote it from
// true to false when it is now accepted only as a table name).
func TestReservedNameWordsRejectedBare(t *testing.T) {
	words := ast.ReservedNameWordsForTest()
	if len(words) == 0 {
		t.Fatal("reserved name word list is empty")
	}
	type form struct {
		name  string
		tmpl  string // %s is the name
		table bool   // only checked for words reserved in table positions
	}
	forms := []form{
		{"from_table", "SELECT a FROM %s", true},
		{"cte_column", "WITH c (%s) AS (SELECT 1) SELECT * FROM c", false},
		{"view_column", "CREATE VIEW v (%s) AS SELECT 1", false},
		// A CTE name takes the same words as a table name.
		{"cte_name", "WITH %s AS (SELECT 1) SELECT * FROM x", true},
	}
	for word, inAll := range words {
		w := strings.ToLower(word)
		for _, f := range forms {
			if f.table && !inAll {
				continue
			}
			for _, d := range quotedRenderDialects {
				bare := fmt.Sprintf(f.tmpl, w)
				if tree, err := gosqlx.ParseWithDialect(bare, d); err == nil {
					ast.ReleaseAST(tree)
					t.Errorf("%s/%s: bare %q parsed; remove %s from reservedNameWords", f.name, d, bare, word)
					continue
				}
				quoted := fmt.Sprintf(f.tmpl, `"`+w+`"`)
				tree, err := gosqlx.ParseWithDialect(quoted, d)
				if err != nil {
					t.Errorf("%s/%s: quoted %q does not parse: %v", f.name, d, quoted, err)
					continue
				}
				out := tree.SQL()
				ast.ReleaseAST(tree)
				if !strings.Contains(out, `"`+w+`"`) {
					t.Errorf("%s/%s: SQL() of %q lost the quotes: %s", f.name, d, quoted, out)
				}
				tree2, err := gosqlx.ParseWithDialect(out, d)
				if err != nil {
					t.Errorf("%s/%s: SQL() %q does not re-parse: %v", f.name, d, out, err)
					continue
				}
				ast.ReleaseAST(tree2)
			}
		}
	}
}

// TestKeywordFunctionNames guards keywordFunctionNames in quote_names.go: a
// reserved word the parser accepts bare as a function name must be listed
// (so SQL() keeps IF(a, b, c) bare), and every other reserved word must be
// rejected bare as a scalar or table function name in every dialect, so the quoted
// "select"(x) that SQL() writes for it is the only spelling that re-parses.
func TestKeywordFunctionNames(t *testing.T) {
	allowed := ast.KeywordFunctionNamesForTest()
	for word, inAll := range ast.ReservedNameWordsForTest() {
		if !inAll {
			continue
		}
		w := strings.ToLower(word)
		parsedAsCall := false
		for _, d := range quotedRenderDialects {
			// As a scalar function in the select list.
			if tree, err := gosqlx.ParseWithDialect("SELECT "+w+"(1) FROM t", d); err == nil {
				if sel, ok := tree.Statements[0].(*ast.SelectStatement); ok && len(sel.Columns) == 1 {
					if fc, ok := sel.Columns[0].(*ast.FunctionCall); ok && strings.EqualFold(fc.Name, word) {
						parsedAsCall = true
					}
				}
				ast.ReleaseAST(tree)
			}
			// As a table function in FROM.
			if tree, err := gosqlx.ParseWithDialect("SELECT * FROM "+w+"(1)", d); err == nil {
				if sel, ok := tree.Statements[0].(*ast.SelectStatement); ok && len(sel.From) == 1 &&
					sel.From[0].TableFunc != nil && strings.EqualFold(sel.From[0].TableFunc.Name, word) {
					parsedAsCall = true
				}
				ast.ReleaseAST(tree)
			}
		}
		if parsedAsCall != allowed[word] {
			t.Errorf("%s: parsed bare as a function call = %v, but keywordFunctionNames[%s] = %v", word, parsedAsCall, word, allowed[word])
		}
	}
	for word := range allowed {
		if inAll, ok := ast.ReservedNameWordsForTest()[word]; !ok || !inAll {
			t.Errorf("keywordFunctionNames lists %s, which is not reserved in every name position", word)
		}
	}
}
