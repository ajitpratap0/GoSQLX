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

package performance

import (
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// ImplicitCrossJoinRule (L023) flags queries that reference multiple tables in
// the FROM clause without explicit JOIN syntax.
// Comma-separated tables create an implicit cross join (Cartesian product) which is
// almost always unintentional and produces an explosive result set.
type ImplicitCrossJoinRule struct{ linter.BaseRule }

// NewImplicitCrossJoinRule creates a new L023 rule instance.
func NewImplicitCrossJoinRule() *ImplicitCrossJoinRule {
	return &ImplicitCrossJoinRule{
		BaseRule: linter.NewBaseRule(
			"L023",
			"Implicit Cross Join",
			"Comma-separated tables in FROM create an implicit cross join",
			linter.SeverityWarning,
			false,
		),
	}
}

// Check walks the AST for SELECT statements with multiple FROM tables and no
// JOINs at any nesting level. Implicit cross joins buried in subqueries or CTE
// bodies are just as dangerous as top-level ones.
func (r *ImplicitCrossJoinRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	for _, stmt := range ctx.AST.Statements {
		ast.Inspect(stmt, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectStatement)
			if !ok {
				return true
			}
			// Multiple tables in FROM without any JOIN clause = implicit cross join
			if len(sel.From) >= 2 && len(sel.Joins) == 0 {
				tableNames := make([]string, 0, len(sel.From))
				for _, ref := range sel.From {
					if ref.Name != "" {
						tableNames = append(tableNames, ref.Name)
					}
				}
				if len(tableNames) >= 2 {
					violations = append(violations, linter.Violation{
						Rule:       r.ID(),
						RuleName:   r.Name(),
						Severity:   r.Severity(),
						Message:    "Comma-separated tables in FROM clause create an implicit cross join",
						Location:   sel.Pos,
						Suggestion: "Use explicit JOIN syntax with an ON condition instead of comma-separated tables",
					})
				}
			}
			return true
		})
	}
	return violations, nil
}

// Fix is a no-op: converting implicit cross join to explicit JOIN requires intent.
func (r *ImplicitCrossJoinRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
