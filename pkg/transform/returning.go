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

// getReturning returns a pointer to the Returning slice for supported DML
// statements (INSERT, UPDATE, DELETE). Returns ErrUnsupportedStatement for
// SELECT or DDL statements.
func getReturning(stmt ast.Statement) (*[]ast.Expression, error) {
	switch s := stmt.(type) {
	case *ast.InsertStatement:
		return &s.Returning, nil
	case *ast.UpdateStatement:
		return &s.Returning, nil
	case *ast.DeleteStatement:
		return &s.Returning, nil
	default:
		return nil, &ErrUnsupportedStatement{Transform: "RETURNING", Got: stmtTypeName(stmt)}
	}
}

// AddReturning returns a Rule that appends one or more column names to the
// RETURNING clause of an INSERT, UPDATE, or DELETE statement. This is the
// standard PostgreSQL extension for returning row data from DML operations.
// SQL Server users can achieve a similar result with the OUTPUT clause (not
// yet covered by this transform).
//
// If the statement already has a RETURNING clause the new columns are appended
// to the existing list.
//
// Returns ErrUnsupportedStatement for SELECT or DDL statements.
//
// Example:
//
//	transform.Apply(stmt, transform.AddReturning("id", "created_at"))
func AddReturning(columns ...string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		ret, err := getReturning(stmt)
		if err != nil {
			return err
		}
		for _, col := range columns {
			*ret = append(*ret, &ast.Identifier{Name: col})
		}
		return nil
	})
}

// RemoveReturning returns a Rule that clears the entire RETURNING clause from
// an INSERT, UPDATE, or DELETE statement. If the clause is already empty the
// rule is a no-op (no error).
//
// Returns ErrUnsupportedStatement for SELECT or DDL statements.
//
// Example:
//
//	transform.Apply(stmt, transform.RemoveReturning())
func RemoveReturning() Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		ret, err := getReturning(stmt)
		if err != nil {
			return err
		}
		*ret = nil
		return nil
	})
}
