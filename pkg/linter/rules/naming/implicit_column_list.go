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

// ImplicitColumnListRule (L026) flags INSERT statements without an explicit column list.
// INSERT INTO table VALUES (...) is fragile — it breaks when columns are added/reordered.
type ImplicitColumnListRule struct{ linter.BaseRule }

// NewImplicitColumnListRule creates a new L026 rule instance.
func NewImplicitColumnListRule() *ImplicitColumnListRule {
	return &ImplicitColumnListRule{
		BaseRule: linter.NewBaseRule(
			"L026",
			"Implicit Column List in INSERT",
			"INSERT without explicit column list is fragile and breaks on schema changes",
			linter.SeverityWarning,
			false,
		),
	}
}

// Check walks the AST for INSERT statements without an explicit column list at
// any nesting level (e.g., INSERT inside a data-modifying CTE).
func (r *ImplicitColumnListRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	for _, stmt := range ctx.AST.Statements {
		ast.Inspect(stmt, func(n ast.Node) bool {
			ins, ok := n.(*ast.InsertStatement)
			if !ok {
				return true
			}
			// If there are VALUES but no explicit column list, flag it
			if len(ins.Values) > 0 && len(ins.Columns) == 0 {
				violations = append(violations, linter.Violation{
					Rule:       r.ID(),
					RuleName:   r.Name(),
					Severity:   r.Severity(),
					Message:    "INSERT INTO " + ins.TableName + " has no explicit column list",
					Location:   ins.Pos,
					Suggestion: "Specify columns explicitly: INSERT INTO " + ins.TableName + " (col1, col2, ...) VALUES (...)",
				})
			}
			return true
		})
	}
	return violations, nil
}

// Fix is a no-op: adding column list requires schema knowledge.
func (r *ImplicitColumnListRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
