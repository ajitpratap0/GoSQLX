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
	"context"
	"reflect"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// TestStatementStarts checks that the parser records where every top-level
// statement (GO separators included) begins, also for statements whose body
// holds ';' and T-SQL statements without ';' between them, and that a pooled
// AST does not carry the starts of an earlier parse.
func TestStatementStarts(t *testing.T) {
	loc := func(line, col int) models.Location { return models.Location{Line: line, Column: col} }
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    []models.Location
	}{
		{"single", "", "SELECT 1", []models.Location{loc(1, 1)}},
		{"semicolons", "", ";  SELECT 1;;\n  SELECT 2", []models.Location{loc(1, 4), loc(2, 3)}},
		{"t-sql without semicolons and GO", keywords.DialectSQLServer,
			"SELECT 1\nSELECT 2\nGO\nCREATE PROC p AS BEGIN SELECT 1; END",
			[]models.Location{loc(1, 1), loc(2, 1), loc(3, 1), loc(4, 1)}},
		{"trigger body", keywords.DialectMySQL,
			"SELECT 1;\nCREATE TRIGGER t AFTER INSERT ON x FOR EACH ROW BEGIN SELECT 1; SELECT 2; END;\nSELECT 3",
			[]models.Location{loc(1, 1), loc(2, 1), loc(3, 1)}},
	}
	for _, tc := range tests {
		for _, withCtx := range []bool{false, true} {
			name := tc.name
			if withCtx {
				name += "/context"
			}
			t.Run(name, func(t *testing.T) {
				tkz := tokenizer.GetTokenizer()
				defer tokenizer.PutTokenizer(tkz)
				if tc.dialect != "" {
					tkz.SetDialect(tc.dialect)
				}
				tokens, err := tkz.TokenizeString(tc.sql)
				if err != nil {
					t.Fatal(err)
				}
				p := GetParser()
				defer PutParser(p)
				if tc.dialect != "" {
					p.ApplyOptions(WithDialect(string(tc.dialect)))
				}
				var tree *ast.AST
				if withCtx {
					tree, err = p.ParseContextFromModelTokens(context.Background(), tokens)
				} else {
					tree, err = p.ParseFromModelTokens(tokens)
				}
				if err != nil {
					t.Fatal(err)
				}
				defer ast.ReleaseAST(tree)
				if len(tree.StatementStarts) != len(tree.Statements) {
					t.Fatalf("%d starts for %d statements", len(tree.StatementStarts), len(tree.Statements))
				}
				if !reflect.DeepEqual(tree.StatementStarts, tc.want) {
					t.Fatalf("starts = %v, want %v", tree.StatementStarts, tc.want)
				}
			})
		}
	}
}
