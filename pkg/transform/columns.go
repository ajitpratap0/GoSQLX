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

func getSelect(stmt ast.Statement, transform string) (*ast.SelectStatement, error) {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return nil, &ErrUnsupportedStatement{Transform: transform, Got: stmtTypeName(stmt)}
	}
	return sel, nil
}

// AddColumn returns a Rule that appends a column expression to the SELECT list of
// a SELECT statement. The expression may be any valid AST expression node such as
// *ast.Identifier, *ast.AliasedExpression, or *ast.FunctionCall.
//
// Parameters:
//   - expr: The column expression to append to the SELECT list
//
// Returns ErrUnsupportedStatement for non-SELECT statements.
func AddColumn(expr ast.Expression) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "AddColumn")
		if err != nil {
			return err
		}
		sel.Columns = append(sel.Columns, expr)
		return nil
	})
}

// RemoveColumn returns a Rule that removes the first column in the SELECT list that
// matches name. Matching is case-insensitive and checks both identifier names and
// expression aliases.
//
// Returns an error if no column matching name is found, or ErrUnsupportedStatement
// for non-SELECT statements.
func RemoveColumn(name string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "RemoveColumn")
		if err != nil {
			return err
		}
		filtered := make([]ast.Expression, 0, len(sel.Columns))
		found := false
		for _, col := range sel.Columns {
			if columnMatches(col, name) {
				found = true
			} else {
				filtered = append(filtered, col)
			}
		}
		if !found {
			return fmt.Errorf("column %q not found", name)
		}
		sel.Columns = filtered
		return nil
	})
}

// ReplaceColumn returns a Rule that replaces every column in the SELECT list that
// matches oldName with a bare *ast.Identifier for newName. Matching is
// case-insensitive against both identifier names and aliases.
//
// Parameters:
//   - oldName: Name or alias of the column to replace
//   - newName: Replacement identifier name
//
// Returns ErrUnsupportedStatement for non-SELECT statements.
func ReplaceColumn(oldName, newName string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "ReplaceColumn")
		if err != nil {
			return err
		}
		for i, col := range sel.Columns {
			if columnMatches(col, oldName) {
				sel.Columns[i] = &ast.Identifier{Name: newName}
			}
		}
		return nil
	})
}

// AddSelectStar returns a Rule that appends a wildcard * column to the SELECT list
// of a SELECT statement. This is a convenience wrapper around AddColumn with an
// *ast.Identifier{Name: "*"} argument.
//
// Returns ErrUnsupportedStatement for non-SELECT statements.
func AddSelectStar() Rule {
	return AddColumn(&ast.Identifier{Name: "*"})
}

// columnMatches checks if a column expression matches the given name.
func columnMatches(expr ast.Expression, name string) bool {
	lower := strings.ToLower(name)
	switch e := expr.(type) {
	case *ast.Identifier:
		return strings.ToLower(e.Name) == lower
	case *ast.AliasedExpression:
		if strings.ToLower(e.Alias) == lower {
			return true
		}
		return columnMatches(e.Expr, name)
	default:
		return false
	}
}
