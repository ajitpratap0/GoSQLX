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
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// DropWithoutConditionRule (L013) flags DROP TABLE/VIEW/INDEX without IF EXISTS.
// Without IF EXISTS, a DROP on a non-existent object raises a fatal error in most databases.
type DropWithoutConditionRule struct{ linter.BaseRule }

// NewDropWithoutConditionRule creates a new L013 rule instance.
func NewDropWithoutConditionRule() *DropWithoutConditionRule {
	return &DropWithoutConditionRule{
		BaseRule: linter.NewBaseRule(
			"L013",
			"Drop Without IF EXISTS",
			"DROP statement is missing IF EXISTS, which causes errors on non-existent objects",
			linter.SeverityWarning,
			false,
		),
	}
}

// Check inspects the AST for DROP statements without IF EXISTS.
func (r *DropWithoutConditionRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	for _, stmt := range ctx.AST.Statements {
		drop, ok := stmt.(*ast.DropStatement)
		if !ok {
			continue
		}
		if !drop.IfExists {
			objType := strings.ToUpper(drop.ObjectType)
			name := ""
			if len(drop.Names) > 0 {
				name = drop.Names[0]
			}
			violations = append(violations, linter.Violation{
				Rule:       r.ID(),
				RuleName:   r.Name(),
				Severity:   r.Severity(),
				Message:    "DROP " + objType + " " + name + " is missing IF EXISTS",
				Location:   models.Location{Line: 1, Column: 1},
				Suggestion: "Use DROP " + objType + " IF EXISTS " + name,
			})
		}
	}
	return violations, nil
}

// Fix is a no-op: adding IF EXISTS requires careful SQL manipulation.
func (r *DropWithoutConditionRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
