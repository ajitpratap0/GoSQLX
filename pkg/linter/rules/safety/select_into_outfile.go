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
)

// SelectIntoOutfileRule (L015) flags SELECT ... INTO OUTFILE / INTO DUMPFILE patterns.
// These operations write data to the server filesystem — a significant security risk.
// This rule works at the text level since SELECT INTO OUTFILE is a MySQL extension
// that may not always produce a full AST node.
type SelectIntoOutfileRule struct{ linter.BaseRule }

// NewSelectIntoOutfileRule creates a new L015 rule instance.
func NewSelectIntoOutfileRule() *SelectIntoOutfileRule {
	return &SelectIntoOutfileRule{
		BaseRule: linter.NewBaseRule(
			"L015",
			"Select Into Outfile",
			"SELECT INTO OUTFILE/DUMPFILE writes data to the server filesystem",
			linter.SeverityError,
			false,
		),
	}
}

// Check scans the SQL text for SELECT ... INTO OUTFILE or INTO DUMPFILE patterns.
func (r *SelectIntoOutfileRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	var violations []linter.Violation
	upper := strings.ToUpper(ctx.SQL)
	if strings.Contains(upper, "INTO OUTFILE") || strings.Contains(upper, "INTO DUMPFILE") {
		violations = append(violations, linter.Violation{
			Rule:       r.ID(),
			RuleName:   r.Name(),
			Severity:   r.Severity(),
			Message:    "SELECT INTO OUTFILE/DUMPFILE writes data to the server filesystem",
			Location:   models.Location{Line: 1, Column: 1},
			Suggestion: "Use application-layer export instead of server-side file write",
		})
	}
	return violations, nil
}

// Fix is a no-op: removing OUTFILE requires understanding export intent.
func (r *SelectIntoOutfileRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
