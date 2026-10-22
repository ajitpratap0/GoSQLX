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
	"context"
	"fmt"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestEntryPoints_ASTOutlivesTokenizerReuse checks every entry point that
// tokenizes into the pooled tokenizer's scratch buffer: the AST it returns
// must stay intact after the same tokenizer is reused by every other such
// entry point, i.e. nothing in the AST may point into the scratch tokens.
func TestEntryPoints_ASTOutlivesTokenizerReuse(t *testing.T) {
	const sql = `/* lead */ SELECT "Mixed", b AS x, COUNT(*) FROM s."T" t ` +
		`LEFT JOIN u ON t.id = u.id WHERE c > 1 AND d = 'v' GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 5`
	ctx := context.Background()
	tests := []struct {
		name  string
		parse func() (*ast.AST, error)
	}{
		{"Parse", func() (*ast.AST, error) { return Parse(sql) }},
		{"ParseBytes", func() (*ast.AST, error) { return ParseBytes([]byte(sql)) }},
		{"ParseWithContext", func() (*ast.AST, error) { return ParseWithContext(ctx, sql) }},
		{"ParseWithDialect", func() (*ast.AST, error) { return ParseWithDialect(sql, "postgresql") }},
		{"ParseMultiple", func() (*ast.AST, error) {
			trees, err := ParseMultiple([]string{sql})
			if err != nil {
				return nil, err
			}
			return trees[0], nil
		}},
		{"ParseTree", func() (*ast.AST, error) {
			tree, err := ParseTree(ctx, sql, WithDialect("postgresql"), WithComments())
			if err != nil {
				return nil, err
			}
			return tree.Raw(), nil
		}},
		{"ParseTreeRecovery", func() (*ast.AST, error) {
			tree, err := ParseTree(ctx, sql, WithRecovery())
			if err != nil {
				return nil, err
			}
			return tree.Raw(), nil
		}},
		{"ParseWithRecovery", func() (*ast.AST, error) {
			stmts, errs := ParseWithRecovery(sql)
			if len(errs) > 0 {
				return nil, errs[0]
			}
			return &ast.AST{Statements: stmts}, nil
		}},
	}
	churn := func(i int) error {
		other := fmt.Sprintf("SELECT zz%d, yy FROM qq%d -- c%d\nWHERE ww = 'v%d'", i, i, i, i)
		if err := Validate(other); err != nil {
			return err
		}
		if err := ValidateMultiple([]string{other, other}); err != nil {
			return err
		}
		if _, err := Format(other, DefaultFormatOptions()); err != nil {
			return err
		}
		for _, tc := range tests {
			if _, err := tc.parse(); err != nil {
				return err
			}
		}
		return nil
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := tc.parse()
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			want := FormatAST(tree)
			for i := 0; i < 20; i++ {
				if err := churn(i); err != nil {
					t.Fatalf("churn %d: %v", i, err)
				}
			}
			if got := FormatAST(tree); got != want {
				t.Errorf("AST changed after tokenizer reuse:\n got %s\nwant %s", got, want)
			}
		})
	}
}

// TestFormat_CommentsWithScratchTokens checks that Format, which reads the
// scratch tokens again after parsing to place comments, keeps placing them
// the same way when the tokenizer is reused between calls.
func TestFormat_CommentsWithScratchTokens(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{"leading", "-- head\nSELECT a FROM t"},
		{"between statements", "SELECT a FROM t; /* mid */ SELECT b FROM u"},
		{"trailing", "SELECT a FROM t -- tail"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			first, err := Format(tc.sql, DefaultFormatOptions())
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			for i := 0; i < 5; i++ {
				if _, err := Format(fmt.Sprintf("SELECT x%d /* c */ FROM y", i), DefaultFormatOptions()); err != nil {
					t.Fatalf("Format churn: %v", err)
				}
				again, err := Format(tc.sql, DefaultFormatOptions())
				if err != nil {
					t.Fatalf("Format: %v", err)
				}
				if again != first {
					t.Errorf("Format changed on reuse:\n got %q\nwant %q", again, first)
				}
			}
		})
	}
}
