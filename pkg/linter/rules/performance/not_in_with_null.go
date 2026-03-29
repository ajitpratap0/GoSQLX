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

// NotInWithNullRule (L019) flags NOT IN (subquery) patterns.
// If the subquery returns any NULL value, the entire NOT IN expression evaluates to
// UNKNOWN (never true), silently returning zero rows — a common SQL trap.
type NotInWithNullRule struct{ linter.BaseRule }

// NewNotInWithNullRule creates a new L019 rule instance.
func NewNotInWithNullRule() *NotInWithNullRule {
	return &NotInWithNullRule{
		BaseRule: linter.NewBaseRule(
			"L019",
			"NOT IN With NULL Risk",
			"NOT IN (subquery) returns empty result if subquery contains any NULL",
			linter.SeverityWarning,
			false,
		),
	}
}

// notInVisitor traverses the AST looking for NOT IN expressions with subqueries.
type notInVisitor struct {
	rule       *NotInWithNullRule
	violations *[]linter.Violation
}

func (v *notInVisitor) Visit(node ast.Node) (ast.Visitor, error) {
	if node == nil {
		return nil, nil
	}
	inExpr, ok := node.(*ast.InExpression)
	if !ok {
		return v, nil
	}
	if inExpr.Not && inExpr.Subquery != nil {
		*v.violations = append(*v.violations, linter.Violation{
			Rule:       v.rule.ID(),
			RuleName:   v.rule.Name(),
			Severity:   v.rule.Severity(),
			Message:    "NOT IN (subquery) returns empty result if the subquery contains any NULL value",
			Location:   inExpr.Pos,
			Suggestion: "Use NOT EXISTS (...) instead, which handles NULLs correctly",
		})
	}
	return v, nil
}

// Check walks the AST looking for NOT IN (subquery) patterns.
func (r *NotInWithNullRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	v := &notInVisitor{rule: r, violations: &violations}
	for _, stmt := range ctx.AST.Statements {
		if err := ast.Walk(v, stmt); err != nil {
			return nil, err
		}
	}
	return violations, nil
}

// Fix is a no-op: changing NOT IN to NOT EXISTS requires semantic understanding.
func (r *NotInWithNullRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
