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

// TableAliasRequiredRule (L024) flags multi-table queries where any table has no alias.
// Unaliased tables in multi-table queries make column references ambiguous and harder to read.
type TableAliasRequiredRule struct{ linter.BaseRule }

// NewTableAliasRequiredRule creates a new L024 rule instance.
func NewTableAliasRequiredRule() *TableAliasRequiredRule {
	return &TableAliasRequiredRule{
		BaseRule: linter.NewBaseRule(
			"L024",
			"Table Alias Required",
			"Tables in multi-table queries should have aliases for clarity",
			linter.SeverityWarning,
			false,
		),
	}
}

// Check walks the AST for SELECT statements with multiple tables and missing
// aliases at any nesting level. Subqueries and CTE bodies are equally affected
// by ambiguous unaliased tables.
func (r *TableAliasRequiredRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
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
			// Only apply when there are multiple tables (FROM + JOINs, or multiple FROM)
			totalTables := len(sel.From) + len(sel.Joins)
			if totalTables < 2 {
				return true
			}
			// Check FROM tables
			for _, ref := range sel.From {
				if ref.Name != "" && ref.Alias == "" {
					violations = append(violations, linter.Violation{
						Rule:       r.ID(),
						RuleName:   r.Name(),
						Severity:   r.Severity(),
						Message:    "Table '" + ref.Name + "' has no alias in a multi-table query",
						Location:   sel.Pos,
						Suggestion: "Add an alias: FROM " + ref.Name + " AS " + abbreviate(ref.Name),
					})
				}
			}
			// Check JOIN tables
			for _, join := range sel.Joins {
				if join.Right.Name != "" && join.Right.Alias == "" {
					violations = append(violations, linter.Violation{
						Rule:       r.ID(),
						RuleName:   r.Name(),
						Severity:   r.Severity(),
						Message:    "Table '" + join.Right.Name + "' has no alias in a JOIN",
						Location:   join.Pos,
						Suggestion: "Add an alias: JOIN " + join.Right.Name + " AS " + abbreviate(join.Right.Name),
					})
				}
			}
			return true
		})
	}
	return violations, nil
}

// abbreviate returns a simple single-letter abbreviation for a table name.
func abbreviate(name string) string {
	if len(name) > 0 {
		return string([]rune(name)[0:1])
	}
	return "t"
}

// Fix is a no-op: alias naming is a style decision.
func (r *TableAliasRequiredRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
