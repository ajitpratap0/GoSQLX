// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package gosqlx

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// Retaining every tree while other goroutines churn tokenizer/parser pools
// checks both scratch-token ownership and premature pooled-node reuse.
func TestConcurrentRetainedASTs(t *testing.T) {
	tests := []struct {
		name  string
		parse func(string) (*ast.AST, error)
		tail  string
	}{
		{"Parse", Parse, ""},
		{"ParseBytes", func(s string) (*ast.AST, error) { return ParseBytes([]byte(s)) }, ""},
		{"ParseWithContext", func(s string) (*ast.AST, error) { return ParseWithContext(context.Background(), s) }, ""},
		{"ParseWithDialect", func(s string) (*ast.AST, error) { return ParseWithDialect(s, keywords.DialectSQLServer) }, " FOR JSON PATH"},
		{"ParserBytesWithDialect", func(s string) (*ast.AST, error) {
			return parser.ParseBytesWithDialect([]byte(s), keywords.DialectSQLServer)
		}, " FOR JSON PATH"},
		{"ParseTree", func(s string) (*ast.AST, error) {
			tree, err := ParseTree(context.Background(), s, WithDialect("sqlserver"), WithComments())
			if err != nil {
				return nil, err
			}
			return tree.Raw(), nil
		}, " FOR JSON PATH"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			type snapshot struct {
				tree *ast.AST
				json string
				sql  string
			}
			const workers, retained, churn = 8, 16, 64
			var ready, done sync.WaitGroup
			start := make(chan struct{})
			ready.Add(workers)
			done.Add(workers)
			for worker := 0; worker < workers; worker++ {
				go func() {
					defer done.Done()
					var held []snapshot
					defer func() {
						for _, s := range held {
							ast.ReleaseAST(s.tree)
						}
					}()
					query := func(i int) string {
						return fmt.Sprintf(`/* worker %d query %d */ SELECT "Mixed%d", N'o''clock%d', COUNT(*) OVER (PARTITION BY g ORDER BY id) FROM "Table%d" WHERE a IS NOT NULL ORDER BY id`, worker, i, i, i, worker) + tc.tail
					}
					for i := 0; i < retained; i++ {
						tree, err := tc.parse(query(i))
						if err != nil {
							t.Errorf("retain worker %d: %v", worker, err)
							break
						}
						data, err := json.Marshal(tree)
						if err != nil {
							ast.ReleaseAST(tree)
							t.Errorf("snapshot: %v", err)
							break
						}
						held = append(held, snapshot{tree, string(data), FormatAST(tree)})
					}
					ready.Done()
					<-start
					for i := 0; i < churn; i++ {
						tree, err := tc.parse(query(i + retained))
						if err != nil {
							t.Errorf("churn worker %d: %v", worker, err)
							return
						}
						ast.ReleaseAST(tree)
						if err := Validate(fmt.Sprintf("SELECT churn%d FROM other%d WHERE a = 'fresh'", i, worker)); err != nil {
							t.Errorf("validate churn: %v", err)
							return
						}
					}
					for i, s := range held {
						data, err := json.Marshal(s.tree)
						if err != nil {
							t.Errorf("marshal retained AST: %v", err)
							continue
						}
						if string(data) != s.json || FormatAST(s.tree) != s.sql {
							t.Errorf("retained AST %d in worker %d changed after concurrent pool reuse", i, worker)
						}
					}
				}()
			}
			ready.Wait()
			close(start)
			done.Wait()
		})
	}
}
