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

// SelectStarRule (L016) flags SELECT * usage.
// SELECT * fetches all columns, preventing index-only scans and over-fetching data.
type SelectStarRule struct{ linter.BaseRule }

// NewSelectStarRule creates a new L016 rule instance.
func NewSelectStarRule() *SelectStarRule {
	return &SelectStarRule{
		BaseRule: linter.NewBaseRule(
			"L016",
			"Select Star",
			"SELECT * fetches all columns and prevents index-only scans",
			linter.SeverityWarning,
			false,
		),
	}
}

// Check inspects the AST for SELECT * usage.
func (r *SelectStarRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	for _, stmt := range ctx.AST.Statements {
		sel, ok := stmt.(*ast.SelectStatement)
		if !ok {
			continue
		}
		for _, col := range sel.Columns {
			ident, ok := col.(*ast.Identifier)
			if ok && ident.Name == "*" {
				violations = append(violations, linter.Violation{
					Rule:       r.ID(),
					RuleName:   r.Name(),
					Severity:   r.Severity(),
					Message:    "SELECT * fetches all columns; specify only needed columns",
					Location:   ident.Pos,
					Suggestion: "Replace SELECT * with an explicit column list: SELECT id, name, ...",
				})
			}
		}
	}
	return violations, nil
}

// Fix is a no-op: cannot auto-fix without schema knowledge.
func (r *SelectStarRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
