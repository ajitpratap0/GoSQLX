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
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// AddOrderBy returns a Rule that appends an ORDER BY expression to a SELECT
// statement. Multiple calls append additional sort keys in the order they are applied.
//
// Parameters:
//   - column: Name of the column (or expression alias) to sort by
//   - desc: When true the sort direction is DESC; when false it is ASC
//
// Returns ErrUnsupportedStatement for non-SELECT statements.
func AddOrderBy(column string, desc bool) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "AddOrderBy")
		if err != nil {
			return err
		}
		sel.OrderBy = append(sel.OrderBy, ast.OrderByExpression{
			Expression: &ast.Identifier{Name: column},
			Ascending:  !desc,
		})
		return nil
	})
}

// RemoveOrderBy returns a Rule that removes the ORDER BY clause entirely from a
// SELECT statement, leaving the result set in an unspecified (engine-dependent)
// order. This is useful when rewriting queries for intermediate stages in a
// pipeline where ordering should be deferred to the final step, or when
// performance is preferred over a stable row order.
//
// Returns ErrUnsupportedStatement for non-SELECT statements.
func RemoveOrderBy() Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "RemoveOrderBy")
		if err != nil {
			return err
		}
		sel.OrderBy = nil
		return nil
	})
}
