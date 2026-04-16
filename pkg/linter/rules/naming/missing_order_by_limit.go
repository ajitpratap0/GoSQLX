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
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// MissingOrderByLimitRule (L028) flags queries that use LIMIT/OFFSET without ORDER BY.
// Without ORDER BY, the rows returned by LIMIT are non-deterministic — different
// executions may return different rows, making pagination unreliable.
type MissingOrderByLimitRule struct{ linter.BaseRule }

// NewMissingOrderByLimitRule creates a new L028 rule instance.
func NewMissingOrderByLimitRule() *MissingOrderByLimitRule {
	return &MissingOrderByLimitRule{
		BaseRule: linter.NewBaseRule(
			"L028",
			"Missing ORDER BY with LIMIT",
			"LIMIT without ORDER BY produces non-deterministic results",
			linter.SeverityWarning,
			false,
		),
	}
}

// Check walks the AST for SELECT statements with LIMIT/OFFSET but no ORDER BY
// at any nesting level. A subquery like (SELECT ... LIMIT 10) without ORDER BY
// is non-deterministic just like at the top level.
func (r *MissingOrderByLimitRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
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
			hasLimit := sel.Limit != nil || sel.Fetch != nil
			if !hasLimit {
				return true
			}
			hasOffset := sel.Offset != nil || (sel.Fetch != nil && sel.Fetch.OffsetValue != nil)
			hasOrderBy := len(sel.OrderBy) > 0
			if !hasOrderBy {
				msg := "LIMIT without ORDER BY produces non-deterministic results"
				if hasOffset {
					msg = "LIMIT/OFFSET without ORDER BY produces non-deterministic pagination"
				}
				violations = append(violations, linter.Violation{
					Rule:       r.ID(),
					RuleName:   r.Name(),
					Severity:   r.Severity(),
					Message:    msg,
					Location:   sel.Pos,
					Suggestion: "Add ORDER BY to ensure deterministic row selection with LIMIT",
				})
			}
			return true
		})
	}
	return violations, nil
}

// Fix is a no-op: choosing the right ORDER BY requires business logic.
func (r *MissingOrderByLimitRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
