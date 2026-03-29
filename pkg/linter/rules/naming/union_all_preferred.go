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
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// UnionAllPreferredRule (L027) flags UNION (deduplicating) when the caller likely
// meant UNION ALL. UNION performs a sort+dedup pass which is significantly more
// expensive than UNION ALL. If duplicates are intentionally removed, this is fine,
// but it should be an explicit choice.
type UnionAllPreferredRule struct{ linter.BaseRule }

// NewUnionAllPreferredRule creates a new L027 rule instance.
func NewUnionAllPreferredRule() *UnionAllPreferredRule {
	return &UnionAllPreferredRule{
		BaseRule: linter.NewBaseRule(
			"L027",
			"UNION Instead of UNION ALL",
			"UNION deduplicates results with an expensive sort; consider UNION ALL if duplicates are acceptable",
			linter.SeverityWarning,
			false,
		),
	}
}

// unionAllVisitor walks the AST looking for SetOperation nodes with UNION (not UNION ALL).
type unionAllVisitor struct {
	rule       *UnionAllPreferredRule
	violations *[]linter.Violation
}

func (v *unionAllVisitor) Visit(node ast.Node) (ast.Visitor, error) {
	if node == nil {
		return nil, nil
	}
	setOp, ok := node.(*ast.SetOperation)
	if !ok {
		return v, nil
	}
	if strings.ToUpper(setOp.Operator) == "UNION" && !setOp.All {
		*v.violations = append(*v.violations, linter.Violation{
			Rule:       v.rule.ID(),
			RuleName:   v.rule.Name(),
			Severity:   v.rule.Severity(),
			Message:    "UNION performs duplicate elimination with a sort; use UNION ALL if duplicates are acceptable",
			Location:   models.Location{Line: 1, Column: 1},
			Suggestion: "Replace UNION with UNION ALL to avoid the deduplication overhead, or add a comment explaining why dedup is needed",
		})
	}
	return v, nil
}

// Check walks the AST looking for UNION without ALL.
func (r *UnionAllPreferredRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	v := &unionAllVisitor{rule: r, violations: &violations}
	for _, stmt := range ctx.AST.Statements {
		if err := ast.Walk(v, stmt); err != nil {
			return nil, err
		}
	}
	return violations, nil
}

// Fix is a no-op: changing UNION to UNION ALL changes query semantics.
func (r *UnionAllPreferredRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
