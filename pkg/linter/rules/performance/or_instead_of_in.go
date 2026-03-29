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
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// OrInsteadOfInRule (L021) detects repeated equality conditions on the same column
// joined by OR (e.g., col = A OR col = B OR col = C) and suggests using IN instead.
// Multiple ORs on the same column can prevent index use and are harder to read.
type OrInsteadOfInRule struct{ linter.BaseRule }

// NewOrInsteadOfInRule creates a new L021 rule instance.
func NewOrInsteadOfInRule() *OrInsteadOfInRule {
	return &OrInsteadOfInRule{
		BaseRule: linter.NewBaseRule(
			"L021",
			"OR Instead of IN",
			"Multiple equality conditions on same column with OR should use IN",
			linter.SeverityWarning,
			false,
		),
	}
}

// orInsteadOfInVisitor walks the AST looking for OR chains on the same column.
type orInsteadOfInVisitor struct {
	rule       *OrInsteadOfInRule
	violations *[]linter.Violation
}

func (v *orInsteadOfInVisitor) Visit(node ast.Node) (ast.Visitor, error) {
	if node == nil {
		return nil, nil
	}
	binExpr, ok := node.(*ast.BinaryExpression)
	if !ok {
		return v, nil
	}
	if strings.ToUpper(binExpr.Operator) != "OR" {
		return v, nil
	}
	// Collect all equality comparisons in this OR chain
	cols := collectEqColumns(binExpr)
	if len(cols) >= 3 {
		// Check if all comparisons are on the same column
		first := cols[0]
		allSame := true
		for _, c := range cols[1:] {
			if c != first {
				allSame = false
				break
			}
		}
		if allSame && first != "" {
			*v.violations = append(*v.violations, linter.Violation{
				Rule:       v.rule.ID(),
				RuleName:   v.rule.Name(),
				Severity:   v.rule.Severity(),
				Message:    "Multiple OR conditions on column '" + first + "' can be replaced with IN (...)",
				Location:   binExpr.Pos,
				Suggestion: "Replace: " + first + " = a OR " + first + " = b ... with: " + first + " IN (a, b, ...)",
			})
		}
	}
	return v, nil
}

// collectEqColumns extracts the left-hand column names from an OR chain of = comparisons.
func collectEqColumns(expr ast.Expression) []string {
	binExpr, ok := expr.(*ast.BinaryExpression)
	if !ok {
		return nil
	}
	op := strings.ToUpper(binExpr.Operator)
	if op == "OR" {
		left := collectEqColumns(binExpr.Left)
		right := collectEqColumns(binExpr.Right)
		return append(left, right...)
	}
	if op == "=" {
		if ident, ok := binExpr.Left.(*ast.Identifier); ok {
			return []string{ident.Name}
		}
	}
	return nil
}

// Check walks the AST looking for OR-based equality chains on the same column.
func (r *OrInsteadOfInRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	v := &orInsteadOfInVisitor{rule: r, violations: &violations}
	for _, stmt := range ctx.AST.Statements {
		if err := ast.Walk(v, stmt); err != nil {
			return nil, err
		}
	}
	return violations, nil
}

// Fix is a no-op: refactoring OR to IN requires careful SQL manipulation.
func (r *OrInsteadOfInRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
