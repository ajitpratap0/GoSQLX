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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// constraintNameAccepted reports whether every dialect parses w bare as a
// table constraint name.
func constraintNameAccepted(w string) bool {
	for _, d := range quotedRenderDialects {
		tree, err := gosqlx.ParseWithDialect("CREATE TABLE t (a INT, CONSTRAINT "+w+" PRIMARY KEY (a))", d)
		if err != nil {
			return false
		}
		ct, ok := tree.Statements[0].(*ast.CreateTableStatement)
		ok = ok && len(ct.Constraints) == 1 && ct.Constraints[0].Name == w
		ast.ReleaseAST(tree)
		if !ok {
			return false
		}
	}
	return true
}

// TestConstraintNameWords guards constraintNameWords in quote_names.go: a
// lower-case keyword that some dialect rejects bare as a table constraint
// name must be written quoted by QuoteConstraintName, and every word the list
// adds beyond reservedNameWords must really be rejected bare (otherwise
// remove it). The double-quoted form of each must round-trip.
func TestConstraintNameWords(t *testing.T) {
	cands := map[string]bool{}
	for w := range ast.ReservedNameWordsForTest() {
		cands[w] = true
	}
	for w := range ast.ConstraintNameWordsForTest() {
		cands[w] = true
	}
	for _, d := range keywords.AllDialects() {
		for _, k := range keywords.DialectKeywords(d) {
			cands[k.Word] = true
		}
	}
	for _, list := range [][]keywords.Keyword{keywords.RESERVED_FOR_TABLE_ALIAS, keywords.ADDITIONAL_KEYWORDS} {
		for _, k := range list {
			cands[k.Word] = true
		}
	}
	extra := ast.ConstraintNameWordsForTest()
	for word := range cands {
		w := strings.ToLower(word)
		if strings.ContainsAny(w, " ") {
			continue
		}
		accepted := constraintNameAccepted(w)
		quoted := ast.QuoteConstraintName(w) != w
		if !accepted && !quoted {
			t.Errorf("%q is rejected bare as a constraint name but QuoteConstraintName leaves it bare; add %s to constraintNameWords", w, word)
		}
		if accepted && extra[word] {
			t.Errorf("%q is accepted bare as a constraint name; remove %s from constraintNameWords", w, word)
		}
		if !accepted {
			in := `CREATE TABLE t (a INT, CONSTRAINT "` + w + `" PRIMARY KEY (a))`
			tree, err := gosqlx.Parse(in)
			if err != nil {
				t.Errorf("quoted %q does not parse: %v", in, err)
				continue
			}
			out := tree.SQL()
			ast.ReleaseAST(tree)
			if !strings.Contains(out, `CONSTRAINT "`+w+`"`) {
				t.Errorf("SQL() of %q = %q, want the name quoted", in, out)
			}
		}
	}
	for _, c := range []struct{ in, want string }{
		{"pk_users", "pk_users"},
		{"MixedCase", `"MixedCase"`},
		{"1x", `"1x"`},
		{"#x", `"#x"`},
		{"x y", `"x y"`},
		{`a"b`, `"a""b"`},
	} {
		if got := ast.QuoteConstraintName(c.in); got != c.want {
			t.Errorf("QuoteConstraintName(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}
