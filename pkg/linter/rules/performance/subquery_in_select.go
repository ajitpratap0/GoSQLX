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

// SubqueryInSelectRule (L020) flags correlated subqueries in the SELECT column list.
// A subquery in the SELECT list is executed once per row — this is the classic N+1 problem.
type SubqueryInSelectRule struct{ linter.BaseRule }

// NewSubqueryInSelectRule creates a new L020 rule instance.
func NewSubqueryInSelectRule() *SubqueryInSelectRule {
	return &SubqueryInSelectRule{
		BaseRule: linter.NewBaseRule(
			"L020",
			"Correlated Subquery in SELECT",
			"Subquery in SELECT column list executes once per row (N+1 problem)",
			linter.SeverityWarning,
			false,
		),
	}
}

// Check inspects the AST for subqueries used as SELECT column expressions.
func (r *SubqueryInSelectRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	for _, stmt := range ctx.AST.Statements {
		sel, ok := stmt.(*ast.SelectStatement)
		if !ok {
			continue
		}
		for _, col := range sel.Columns {
			if sub, ok := col.(*ast.SubqueryExpression); ok {
				violations = append(violations, linter.Violation{
					Rule:       r.ID(),
					RuleName:   r.Name(),
					Severity:   r.Severity(),
					Message:    "Scalar subquery in SELECT column list executes once per row",
					Location:   sub.Pos,
					Suggestion: "Rewrite as a JOIN or use a lateral join to avoid per-row execution",
				})
			}
			// Also check aliased subqueries: (SELECT ...) AS col
			if alias, ok := col.(*ast.AliasedExpression); ok {
				if sub, ok := alias.Expr.(*ast.SubqueryExpression); ok {
					violations = append(violations, linter.Violation{
						Rule:       r.ID(),
						RuleName:   r.Name(),
						Severity:   r.Severity(),
						Message:    "Scalar subquery in SELECT column list executes once per row",
						Location:   sub.Pos,
						Suggestion: "Rewrite as a JOIN or use a lateral join to avoid per-row execution",
					})
				}
			}
		}
	}
	return violations, nil
}

// Fix is a no-op: refactoring N+1 requires schema/query redesign.
func (r *SubqueryInSelectRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
