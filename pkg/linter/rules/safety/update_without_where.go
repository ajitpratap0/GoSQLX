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

// UpdateWithoutWhereRule (L012) flags UPDATE statements that have no WHERE clause.
// Unfiltered UPDATEs modify all rows in a table and are almost always a mistake.
type UpdateWithoutWhereRule struct{ linter.BaseRule }

// NewUpdateWithoutWhereRule creates a new L012 rule instance.
func NewUpdateWithoutWhereRule() *UpdateWithoutWhereRule {
	return &UpdateWithoutWhereRule{
		BaseRule: linter.NewBaseRule(
			"L012",
			"Update Without WHERE",
			"UPDATE statement has no WHERE clause and will modify all rows",
			linter.SeverityError,
			false,
		),
	}
}

// Check inspects the AST for UPDATE statements without a WHERE clause.
func (r *UpdateWithoutWhereRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	for _, stmt := range ctx.AST.Statements {
		upd, ok := stmt.(*ast.UpdateStatement)
		if !ok {
			continue
		}
		if upd.Where == nil {
			violations = append(violations, linter.Violation{
				Rule:       r.ID(),
				RuleName:   r.Name(),
				Severity:   r.Severity(),
				Message:    "UPDATE statement has no WHERE clause",
				Location:   upd.Pos,
				Suggestion: "Add a WHERE clause to restrict which rows are updated",
			})
		}
	}
	return violations, nil
}

// Fix is a no-op: it is unsafe to auto-fix a missing WHERE clause.
func (r *UpdateWithoutWhereRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
