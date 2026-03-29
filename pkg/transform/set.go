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

package transform

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// identifierName extracts the column name string from an Expression that is
// expected to be an *ast.Identifier. Returns empty string for other types.
func identifierName(expr ast.Expression) string {
	if id, ok := expr.(*ast.Identifier); ok {
		return id.Name
	}
	return ""
}

// parseValueExpr parses a SQL value expression string using the
// "SELECT * FROM _t WHERE _col = <valueSQL>" trick, returning the right-hand
// side of the equality. This handles literals, function calls, identifiers, etc.
func parseValueExpr(valueSQL string) (ast.Expression, error) {
	expr, err := parseCondition(fmt.Sprintf("_col = %s", valueSQL))
	if err != nil {
		return nil, fmt.Errorf("parse value %q: %w", valueSQL, err)
	}
	if bin, ok := expr.(*ast.BinaryExpression); ok {
		return bin.Right, nil
	}
	return expr, nil
}

// AddSetClause returns a Rule that appends a new assignment to the SET clause
// of an UPDATE statement. If a column with the same name already exists (case-
// insensitive), its value is overwritten rather than duplicated.
//
// Parameters:
//   - column: the column name to set
//   - valueSQL: a SQL expression string for the new value (e.g., "'active'", "NOW()", "42")
//
// Returns ErrUnsupportedStatement for non-UPDATE statements.
//
// Example:
//
//	transform.Apply(stmt, transform.AddSetClause("updated_at", "NOW()"))
func AddSetClause(column, valueSQL string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		upd, ok := stmt.(*ast.UpdateStatement)
		if !ok {
			return &ErrUnsupportedStatement{Transform: "AddSetClause", Got: stmtTypeName(stmt)}
		}

		valueExpr, err := parseValueExpr(valueSQL)
		if err != nil {
			return fmt.Errorf("AddSetClause: %w", err)
		}

		// Replace existing assignment for the same column (case-insensitive).
		for i, a := range upd.Assignments {
			if strings.EqualFold(identifierName(a.Column), column) {
				upd.Assignments[i].Value = valueExpr
				return nil
			}
		}

		// Append a new assignment.
		upd.Assignments = append(upd.Assignments, ast.UpdateExpression{
			Column: &ast.Identifier{Name: column},
			Value:  valueExpr,
		})
		return nil
	})
}

// SetClause is an alias for AddSetClause. It sets the value of a column in the
// UPDATE SET clause, adding it if not present or replacing it if already there.
//
// Example:
//
//	transform.Apply(stmt, transform.SetClause("status", "'active'"))
func SetClause(column, valueSQL string) Rule {
	return AddSetClause(column, valueSQL)
}

// RemoveSetClause returns a Rule that removes a column from the UPDATE SET clause.
// If the column is not found the statement is left unchanged (no error).
// The comparison is case-insensitive.
//
// Returns ErrUnsupportedStatement for non-UPDATE statements.
//
// Example:
//
//	transform.Apply(stmt, transform.RemoveSetClause("internal_flag"))
func RemoveSetClause(column string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		upd, ok := stmt.(*ast.UpdateStatement)
		if !ok {
			return &ErrUnsupportedStatement{Transform: "RemoveSetClause", Got: stmtTypeName(stmt)}
		}

		filtered := upd.Assignments[:0]
		for _, a := range upd.Assignments {
			if !strings.EqualFold(identifierName(a.Column), column) {
				filtered = append(filtered, a)
			}
		}
		upd.Assignments = filtered
		return nil
	})
}

// ReplaceSetClause returns a Rule that completely replaces all SET assignments
// with the ones provided in the map. Keys are column names, values are SQL
// expression strings. This is useful for wholesale rewrites of the SET clause.
//
// Returns ErrUnsupportedStatement for non-UPDATE statements.
//
// Example:
//
//	transform.Apply(stmt, transform.ReplaceSetClause(map[string]string{
//	    "status":     "'active'",
//	    "updated_at": "NOW()",
//	}))
func ReplaceSetClause(assignments map[string]string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		upd, ok := stmt.(*ast.UpdateStatement)
		if !ok {
			return &ErrUnsupportedStatement{Transform: "ReplaceSetClause", Got: stmtTypeName(stmt)}
		}

		newAssignments := make([]ast.UpdateExpression, 0, len(assignments))
		for col, valueSQL := range assignments {
			valueExpr, err := parseValueExpr(valueSQL)
			if err != nil {
				return fmt.Errorf("ReplaceSetClause: column %q: %w", col, err)
			}
			newAssignments = append(newAssignments, ast.UpdateExpression{
				Column: &ast.Identifier{Name: col},
				Value:  valueExpr,
			})
		}
		upd.Assignments = newAssignments
		return nil
	})
}
