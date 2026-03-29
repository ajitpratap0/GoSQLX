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

package rules

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// PgSerialToAutoIncrement rewrites PostgreSQL SERIAL / BIGSERIAL / SMALLSERIAL
// column types to the MySQL equivalent (INT / BIGINT with AUTO_INCREMENT).
//
// PostgreSQL: id SERIAL PRIMARY KEY
// MySQL:      id INT AUTO_INCREMENT PRIMARY KEY
func PgSerialToAutoIncrement(stmt ast.Statement) error {
	ct, ok := stmt.(*ast.CreateTableStatement)
	if !ok {
		return nil
	}
	for i := range ct.Columns {
		col := &ct.Columns[i]
		switch strings.ToUpper(col.Type) {
		case "SERIAL", "SMALLSERIAL":
			col.Type = "INT"
			col.Constraints = append(col.Constraints, ast.ColumnConstraint{AutoIncrement: true})
		case "BIGSERIAL":
			col.Type = "BIGINT"
			col.Constraints = append(col.Constraints, ast.ColumnConstraint{AutoIncrement: true})
		}
	}
	return nil
}

// PgDoubleQuoteToBacktick is a no-op: the GoSQLX AST stores raw (unquoted)
// identifier names.  The formatter uses the target dialect's quoting style.
func PgDoubleQuoteToBacktick(_ ast.Statement) error {
	return nil
}

// PgILikeToLower rewrites PostgreSQL ILIKE to a LOWER() … LIKE LOWER() pair
// that is compatible with MySQL.
//
// PostgreSQL: col ILIKE '%alice%'
// MySQL:      LOWER(col) LIKE LOWER('%alice%')
func PgILikeToLower(stmt ast.Statement) error {
	return ast.Walk(&ilikeLowerer{}, stmt)
}

type ilikeLowerer struct{}

func (v *ilikeLowerer) Visit(node ast.Node) (ast.Visitor, error) {
	if node == nil {
		return nil, nil
	}
	bin, ok := node.(*ast.BinaryExpression)
	if !ok {
		return v, nil
	}
	if !strings.EqualFold(bin.Operator, "ILIKE") {
		return v, nil
	}
	// Rewrite: left ILIKE right  →  LOWER(left) LIKE LOWER(right)
	bin.Operator = "LIKE"
	bin.Left = &ast.FunctionCall{
		Name:      "LOWER",
		Arguments: []ast.Expression{bin.Left},
	}
	bin.Right = &ast.FunctionCall{
		Name:      "LOWER",
		Arguments: []ast.Expression{bin.Right},
	}
	// Return nil so we do not recurse into the newly-created LOWER() wrappers.
	return nil, nil
}
