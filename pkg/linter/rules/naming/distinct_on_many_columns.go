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
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

const distinctColumnThreshold = 5

// DistinctOnManyColumnsRule (L030) warns when DISTINCT is used with many columns.
// DISTINCT on many columns is often a sign of a missing GROUP BY or denormalized
// data. It also forces a sort over all projected columns, which is expensive.
type DistinctOnManyColumnsRule struct{ linter.BaseRule }

// NewDistinctOnManyColumnsRule creates a new L030 rule instance.
func NewDistinctOnManyColumnsRule() *DistinctOnManyColumnsRule {
	return &DistinctOnManyColumnsRule{
		BaseRule: linter.NewBaseRule(
			"L030",
			"Distinct on Many Columns",
			"DISTINCT on many columns suggests a missing GROUP BY or data quality issue",
			linter.SeverityWarning,
			false,
		),
	}
}

// Check inspects SELECT statements for DISTINCT with many columns.
func (r *DistinctOnManyColumnsRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	for _, stmt := range ctx.AST.Statements {
		sel, ok := stmt.(*ast.SelectStatement)
		if !ok {
			continue
		}
		if !sel.Distinct {
			continue
		}
		colCount := len(sel.Columns)
		if colCount >= distinctColumnThreshold {
			violations = append(violations, linter.Violation{
				Rule:       r.ID(),
				RuleName:   r.Name(),
				Severity:   r.Severity(),
				Message:    fmt.Sprintf("DISTINCT on %d columns is expensive and may indicate a missing GROUP BY or join issue", colCount),
				Location:   sel.Pos,
				Suggestion: "Consider using GROUP BY with aggregate functions, or investigate whether the query structure can be simplified",
			})
		}
	}
	return violations, nil
}

// Fix is a no-op: replacing DISTINCT with GROUP BY requires semantic understanding.
func (r *DistinctOnManyColumnsRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
