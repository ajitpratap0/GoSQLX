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

package safety

import (
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// DeleteWithoutWhereRule (L011) flags DELETE statements that have no WHERE clause.
// Unfiltered DELETEs remove all rows from a table and are almost always a mistake.
type DeleteWithoutWhereRule struct{ linter.BaseRule }

// NewDeleteWithoutWhereRule creates a new L011 rule instance.
func NewDeleteWithoutWhereRule() *DeleteWithoutWhereRule {
	return &DeleteWithoutWhereRule{
		BaseRule: linter.NewBaseRule(
			"L011",
			"Delete Without WHERE",
			"DELETE statement has no WHERE clause and will remove all rows",
			linter.SeverityError,
			false,
		),
	}
}

// Check walks the AST for DELETE statements without a WHERE clause. Fires at
// any nesting level — a DELETE in a CTE body (data-modifying CTE) without a
// WHERE clause is just as dangerous as a top-level DELETE.
func (r *DeleteWithoutWhereRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	for _, stmt := range ctx.AST.Statements {
		ast.Inspect(stmt, func(n ast.Node) bool {
			del, ok := n.(*ast.DeleteStatement)
			if !ok {
				return true
			}
			if del.Where == nil {
				violations = append(violations, linter.Violation{
					Rule:       r.ID(),
					RuleName:   r.Name(),
					Severity:   r.Severity(),
					Message:    "DELETE statement has no WHERE clause",
					Location:   del.Pos,
					Suggestion: "Add a WHERE clause to restrict which rows are deleted, or use TRUNCATE TABLE for full-table removal",
				})
			}
			return true
		})
	}
	return violations, nil
}

// Fix is a no-op: it is unsafe to auto-fix a missing WHERE clause.
func (r *DeleteWithoutWhereRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
