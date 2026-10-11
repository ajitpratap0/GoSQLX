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

package security

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func parseForScan(t *testing.T, sql string) *ast.AST {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenize %q: %v", sql, err)
	}
	p := parser.NewParser()
	defer p.Release()
	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("parse %q: %v", sql, err)
	}
	return tree
}

// Regression for #519: grouping parentheses are now preserved as
// ast.ParenthesizedExpression; the AST scanner must look through them so that
// wrapping a payload in parentheses does not hide it.
func TestScan_ParenthesizedExpressionsAreTransparent(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		pattern PatternType
	}{
		{"paren tautology", "SELECT a FROM t WHERE (1 = 1)", PatternTautology},
		{"or paren tautology", "SELECT a FROM t WHERE id = 1 OR (1 = 1)", PatternTautology},
		{"paren operands tautology", "SELECT a FROM t WHERE id = 1 OR (1) = (1)", PatternTautology},
		{"paren dangerous func", "SELECT a FROM t WHERE (pg_sleep(5) IS NULL)", PatternTimeBased},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := parseForScan(t, tt.sql)
			defer ast.ReleaseAST(tree)
			res := NewScanner().Scan(tree)
			for _, f := range res.Findings {
				if f.Pattern == tt.pattern {
					return
				}
			}
			t.Errorf("expected %s finding for %q, got %+v", tt.pattern, tt.sql, res.Findings)
		})
	}
}
