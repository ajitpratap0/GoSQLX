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

// AddOrderBy returns a Rule that adds an ORDER BY expression to a SELECT statement.
// If desc is true, the order is descending; otherwise ascending.
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

// RemoveOrderBy returns a Rule that removes the ORDER BY clause entirely from a SELECT statement.
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
