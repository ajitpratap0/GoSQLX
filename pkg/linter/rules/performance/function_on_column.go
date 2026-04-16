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

// knownIndexBreakingFunctions is the set of functions commonly applied to indexed
// columns in WHERE clauses, preventing the query planner from using B-tree indexes.
var knownIndexBreakingFunctions = map[string]bool{
	"YEAR":       true,
	"MONTH":      true,
	"DAY":        true,
	"DATE":       true,
	"DATEPART":   true,
	"EXTRACT":    true,
	"UPPER":      true,
	"LOWER":      true,
	"TRIM":       true,
	"LTRIM":      true,
	"RTRIM":      true,
	"LENGTH":     true,
	"LEN":        true,
	"COALESCE":   true,
	"IFNULL":     true,
	"ISNULL":     true,
	"NVL":        true,
	"TO_CHAR":    true,
	"TO_DATE":    true,
	"TO_NUMBER":  true,
	"SUBSTR":     true,
	"SUBSTRING":  true,
	"CONVERT":    true,
	"CAST":       false, // CAST is covered by CastExpression, skip here
	"DATE_TRUNC": true,
	"DATE_PART":  true,
	"FLOOR":      true,
	"CEIL":       true,
	"CEILING":    true,
	"ABS":        true,
	"ROUND":      true,
}

// FunctionOnColumnRule (L022) detects function calls wrapped around column
// references in WHERE clauses (e.g., YEAR(created_at) = 2024).
// Wrapping a column in a function prevents the query planner from using indexes.
type FunctionOnColumnRule struct{ linter.BaseRule }

// NewFunctionOnColumnRule creates a new L022 rule instance.
func NewFunctionOnColumnRule() *FunctionOnColumnRule {
	return &FunctionOnColumnRule{
		BaseRule: linter.NewBaseRule(
			"L022",
			"Function on Indexed Column",
			"Function applied to a column in WHERE prevents index use",
			linter.SeverityWarning,
			false,
		),
	}
}

// functionOnColVisitor walks the AST looking for function(column) = value in WHERE.
type functionOnColVisitor struct {
	rule       *FunctionOnColumnRule
	violations *[]linter.Violation
	inWhere    bool
}

func (v *functionOnColVisitor) Visit(node ast.Node) (ast.Visitor, error) {
	if node == nil {
		return nil, nil
	}
	// Track that we're inside a WHERE or HAVING clause
	if sel, ok := node.(*ast.SelectStatement); ok {
		child := &functionOnColVisitor{rule: v.rule, violations: v.violations, inWhere: false}
		filterVisitor := &functionOnColVisitor{rule: v.rule, violations: v.violations, inWhere: true}

		// Walk WHERE with inWhere=true
		if sel.Where != nil {
			if err := ast.Walk(filterVisitor, sel.Where); err != nil {
				return nil, err
			}
		}
		// Walk HAVING with inWhere=true (same index-breaking concern)
		if sel.Having != nil {
			if err := ast.Walk(filterVisitor, sel.Having); err != nil {
				return nil, err
			}
		}
		// Walk CTEs to catch nested queries
		if sel.With != nil {
			for i := range sel.With.CTEs {
				if sel.With.CTEs[i].Statement != nil {
					if err := ast.Walk(v, sel.With.CTEs[i].Statement); err != nil {
						return nil, err
					}
				}
			}
		}
		// Walk FROM table references so that derived-table subqueries are
		// traversed (e.g. FROM (SELECT ... WHERE fn(col) = X)).
		for i := range sel.From {
			if err := ast.Walk(child, &sel.From[i]); err != nil {
				return nil, err
			}
		}
		// Walk the rest normally (not in WHERE/HAVING)
		for _, col := range sel.Columns {
			if err := ast.Walk(child, col); err != nil {
				return nil, err
			}
		}
		for i := range sel.Joins {
			if err := ast.Walk(child, &sel.Joins[i]); err != nil {
				return nil, err
			}
		}
		return nil, nil // We've handled children manually
	}

	if !v.inWhere {
		return v, nil
	}

	// In WHERE context: look for BinaryExpression where left is a FunctionCall
	binExpr, ok := node.(*ast.BinaryExpression)
	if !ok {
		return v, nil
	}

	fn, isFn := binExpr.Left.(*ast.FunctionCall)
	if !isFn {
		return v, nil
	}

	// Check if the function is in our known list
	if !knownIndexBreakingFunctions[strings.ToUpper(fn.Name)] {
		return v, nil
	}

	// Only flag if the function argument is a simple column reference
	if len(fn.Arguments) == 0 {
		return v, nil
	}
	if _, isIdent := fn.Arguments[0].(*ast.Identifier); !isIdent {
		return v, nil
	}

	*v.violations = append(*v.violations, linter.Violation{
		Rule:       v.rule.ID(),
		RuleName:   v.rule.Name(),
		Severity:   v.rule.Severity(),
		Message:    "Function " + fn.Name + "() applied to a column in WHERE prevents index use",
		Location:   fn.Pos,
		Suggestion: "Rewrite the condition to avoid wrapping the column in a function (e.g., use range conditions instead of YEAR(col) = N)",
	})
	return v, nil
}

// Check walks the AST looking for function-on-column patterns in WHERE clauses.
func (r *FunctionOnColumnRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	v := &functionOnColVisitor{rule: r, violations: &violations, inWhere: false}
	for _, stmt := range ctx.AST.Statements {
		if err := ast.Walk(v, stmt); err != nil {
			return nil, err
		}
	}
	return violations, nil
}

// Fix is a no-op: rewriting function-on-column requires domain knowledge.
func (r *FunctionOnColumnRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
