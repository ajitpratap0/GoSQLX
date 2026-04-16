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

package naming

import (
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// SubqueryCanBeJoinRule (L029) flags correlated EXISTS/IN subqueries in WHERE clauses
// that could be expressed more efficiently as a JOIN.
// EXISTS (SELECT ...) and IN (SELECT ...) can often be replaced with a JOIN or
// LEFT JOIN ... IS NULL for better performance and readability.
type SubqueryCanBeJoinRule struct{ linter.BaseRule }

// NewSubqueryCanBeJoinRule creates a new L029 rule instance.
func NewSubqueryCanBeJoinRule() *SubqueryCanBeJoinRule {
	return &SubqueryCanBeJoinRule{
		BaseRule: linter.NewBaseRule(
			"L029",
			"Subquery Can Be JOIN",
			"EXISTS/IN subquery in WHERE may be rewritable as a JOIN for better performance",
			linter.SeverityWarning,
			false,
		),
	}
}

// subqueryJoinVisitor checks WHERE clauses for EXISTS or IN subqueries.
type subqueryJoinVisitor struct {
	rule       *SubqueryCanBeJoinRule
	violations *[]linter.Violation
	inWhere    bool
}

func (v *subqueryJoinVisitor) Visit(node ast.Node) (ast.Visitor, error) {
	if node == nil {
		return nil, nil
	}
	// SelectStatement: manually dispatch so we can track which children are in
	// "WHERE context" (flag EXISTS/IN here) vs "non-WHERE context" (recurse
	// for nested SELECTs but do not flag). Returning nil tells Walk to skip
	// default child traversal; we walk every child ourselves to preserve
	// full nested coverage across CTEs, FROM subqueries, JOINs, etc.
	if sel, ok := node.(*ast.SelectStatement); ok {
		whereV := &subqueryJoinVisitor{rule: v.rule, violations: v.violations, inWhere: true}
		nonWhereV := &subqueryJoinVisitor{rule: v.rule, violations: v.violations, inWhere: false}

		if sel.Where != nil {
			if err := ast.Walk(whereV, sel.Where); err != nil {
				return nil, err
			}
		}
		if sel.With != nil {
			if err := ast.Walk(nonWhereV, sel.With); err != nil {
				return nil, err
			}
		}
		for _, col := range sel.Columns {
			if err := ast.Walk(nonWhereV, col); err != nil {
				return nil, err
			}
		}
		for i := range sel.From {
			if err := ast.Walk(nonWhereV, &sel.From[i]); err != nil {
				return nil, err
			}
		}
		for i := range sel.Joins {
			if err := ast.Walk(nonWhereV, &sel.Joins[i]); err != nil {
				return nil, err
			}
		}
		if sel.Having != nil {
			// HAVING is also a filter context, but this rule intentionally
			// only applies to WHERE — keep behavior, recurse as non-WHERE.
			if err := ast.Walk(nonWhereV, sel.Having); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}

	if !v.inWhere {
		return v, nil
	}

	// Check for EXISTS (subquery) in WHERE
	if _, ok := node.(*ast.ExistsExpression); ok {
		*v.violations = append(*v.violations, linter.Violation{
			Rule:       v.rule.ID(),
			RuleName:   v.rule.Name(),
			Severity:   v.rule.Severity(),
			Message:    "EXISTS subquery in WHERE may be rewritable as an INNER JOIN",
			Location:   models.Location{Line: 1, Column: 1},
			Suggestion: "Consider rewriting EXISTS (...) as an INNER JOIN or LEFT JOIN ... IS NULL for better readability",
		})
	}

	// Check for IN (subquery) in WHERE
	if inExpr, ok := node.(*ast.InExpression); ok {
		if inExpr.Subquery != nil && !inExpr.Not {
			*v.violations = append(*v.violations, linter.Violation{
				Rule:       v.rule.ID(),
				RuleName:   v.rule.Name(),
				Severity:   v.rule.Severity(),
				Message:    "IN (subquery) in WHERE may be rewritable as an INNER JOIN",
				Location:   inExpr.Pos,
				Suggestion: "Consider rewriting col IN (SELECT ...) as an INNER JOIN for better performance",
			})
		}
	}
	return v, nil
}

// Check walks the AST looking for EXISTS/IN subqueries in WHERE clauses.
func (r *SubqueryCanBeJoinRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	v := &subqueryJoinVisitor{rule: r, violations: &violations, inWhere: false}
	for _, stmt := range ctx.AST.Statements {
		if err := ast.Walk(v, stmt); err != nil {
			return nil, err
		}
	}
	return violations, nil
}

// Fix is a no-op: rewriting subqueries as JOINs requires semantic understanding.
func (r *SubqueryCanBeJoinRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
