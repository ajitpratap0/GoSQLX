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

// TruncateTableRule (L014) warns when TRUNCATE TABLE is used.
// TRUNCATE is irreversible and bypasses row-level triggers — dangerous in application code.
type TruncateTableRule struct{ linter.BaseRule }

// NewTruncateTableRule creates a new L014 rule instance.
func NewTruncateTableRule() *TruncateTableRule {
	return &TruncateTableRule{
		BaseRule: linter.NewBaseRule(
			"L014",
			"Truncate Table",
			"TRUNCATE TABLE is irreversible and bypasses row-level triggers",
			linter.SeverityWarning,
			false,
		),
	}
}

// Check inspects the AST for TRUNCATE TABLE statements.
func (r *TruncateTableRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	for _, stmt := range ctx.AST.Statements {
		trunc, ok := stmt.(*ast.TruncateStatement)
		if !ok {
			continue
		}
		tableName := ""
		if len(trunc.Tables) > 0 {
			tableName = strings.Join(trunc.Tables, ", ")
		}
		violations = append(violations, linter.Violation{
			Rule:       r.ID(),
			RuleName:   r.Name(),
			Severity:   r.Severity(),
			Message:    "TRUNCATE TABLE " + tableName + " is irreversible and bypasses triggers",
			Location:   models.Location{Line: 1, Column: 1},
			Suggestion: "Prefer DELETE FROM " + tableName + " WHERE ... for reversible partial deletes, or ensure TRUNCATE is intentional in migration scripts",
		})
	}
	return violations, nil
}

// Fix is a no-op: converting TRUNCATE to DELETE requires human intent.
func (r *TruncateTableRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
