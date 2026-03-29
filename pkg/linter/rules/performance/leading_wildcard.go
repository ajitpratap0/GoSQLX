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
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// LeadingWildcardRule (L018) flags LIKE patterns with a leading wildcard (% or _).
// A leading wildcard forces a full table scan — it cannot use a B-tree index.
type LeadingWildcardRule struct{ linter.BaseRule }

// NewLeadingWildcardRule creates a new L018 rule instance.
func NewLeadingWildcardRule() *LeadingWildcardRule {
	return &LeadingWildcardRule{
		BaseRule: linter.NewBaseRule(
			"L018",
			"Leading Wildcard LIKE",
			"LIKE pattern with leading wildcard forces a full table scan",
			linter.SeverityWarning,
			false,
		),
	}
}

// leadingWildcardVisitor traverses the AST looking for LIKE BinaryExpressions
// whose right-hand side is a string literal starting with % or _.
type leadingWildcardVisitor struct {
	rule       *LeadingWildcardRule
	violations *[]linter.Violation
}

func (v *leadingWildcardVisitor) Visit(node ast.Node) (ast.Visitor, error) {
	if node == nil {
		return nil, nil
	}
	binExpr, ok := node.(*ast.BinaryExpression)
	if !ok {
		return v, nil
	}
	upperOp := strings.ToUpper(binExpr.Operator)
	if upperOp != "LIKE" && upperOp != "ILIKE" {
		return v, nil
	}
	// Check if the pattern is a LiteralValue starting with % or _
	if lit, ok := binExpr.Right.(*ast.LiteralValue); ok {
		pattern := fmt.Sprintf("%v", lit.Value)
		if strings.HasPrefix(pattern, "%") || strings.HasPrefix(pattern, "_") {
			*v.violations = append(*v.violations, linter.Violation{
				Rule:       v.rule.ID(),
				RuleName:   v.rule.Name(),
				Severity:   v.rule.Severity(),
				Message:    "LIKE pattern '" + pattern + "' has a leading wildcard — full table scan",
				Location:   binExpr.Pos,
				Suggestion: "Consider full-text search (MATCH AGAINST) or reverse-index the column for suffix searches",
			})
		}
	}
	return v, nil
}

// Check walks the AST looking for LIKE patterns with leading wildcards.
func (r *LeadingWildcardRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	v := &leadingWildcardVisitor{rule: r, violations: &violations}
	for _, stmt := range ctx.AST.Statements {
		if err := ast.Walk(v, stmt); err != nil {
			return nil, err
		}
	}
	return violations, nil
}

// Fix is a no-op: leading wildcard removal requires schema/query redesign.
func (r *LeadingWildcardRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
