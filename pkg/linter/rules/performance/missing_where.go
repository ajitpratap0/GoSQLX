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

// MissingWhereRule (L017) flags SELECT statements with no WHERE clause and no LIMIT
// on queries that reference at least one table — indicating a potential full table scan.
type MissingWhereRule struct{ linter.BaseRule }

// NewMissingWhereRule creates a new L017 rule instance.
func NewMissingWhereRule() *MissingWhereRule {
	return &MissingWhereRule{
		BaseRule: linter.NewBaseRule(
			"L017",
			"Missing WHERE on Full Scan",
			"SELECT on a table without WHERE or LIMIT may cause a full table scan",
			linter.SeverityWarning,
			false,
		),
	}
}

// Check walks the AST for SELECT statements without WHERE/LIMIT on tables.
// Fires at any nesting level — subqueries and CTE bodies that scan a table
// without filtering are just as expensive as top-level scans.
func (r *MissingWhereRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
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
			// Only flag if there is at least one table reference and no WHERE or LIMIT
			if len(sel.From) == 0 {
				return true
			}
			if sel.Where != nil {
				return true
			}
			if sel.Limit != nil {
				return true
			}
			if sel.Fetch != nil {
				return true
			}
			violations = append(violations, linter.Violation{
				Rule:       r.ID(),
				RuleName:   r.Name(),
				Severity:   r.Severity(),
				Message:    "SELECT has no WHERE clause and no LIMIT — may cause a full table scan",
				Location:   sel.Pos,
				Suggestion: "Add a WHERE clause to filter rows, or add LIMIT to bound the result set",
			})
			return true
		})
	}
	return violations, nil
}

// Fix is a no-op: adding WHERE/LIMIT requires understanding business logic.
func (r *MissingWhereRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
