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

// getWhere returns a pointer to the WHERE field for supported statements.
func getWhere(stmt ast.Statement) (*ast.Expression, error) {
	switch s := stmt.(type) {
	case *ast.SelectStatement:
		return &s.Where, nil
	case *ast.UpdateStatement:
		return &s.Where, nil
	case *ast.DeleteStatement:
		return &s.Where, nil
	default:
		return nil, &ErrUnsupportedStatement{Transform: "WHERE", Got: stmtTypeName(stmt)}
	}
}

// AddWhere returns a Rule that appends a condition to the WHERE clause of a
// SELECT, UPDATE, or DELETE statement. If the statement already has a WHERE clause,
// the new condition is combined with AND. If there is no WHERE clause, the condition
// becomes the sole WHERE predicate.
//
// Use this when you have a pre-built AST expression. For raw SQL strings use
// AddWhereFromSQL instead.
//
// Parameters:
//   - condition: An AST expression node representing the filter predicate
//
// Returns ErrUnsupportedStatement for INSERT or DDL statements.
func AddWhere(condition ast.Expression) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		where, err := getWhere(stmt)
		if err != nil {
			return err
		}
		if *where == nil {
			*where = condition
		} else {
			*where = &ast.BinaryExpression{
				Left:     *where,
				Operator: "AND",
				Right:    condition,
			}
		}
		return nil
	})
}

// RemoveWhere returns a Rule that removes the WHERE clause from a SELECT, UPDATE,
// or DELETE statement. After the rule is applied, the statement will match all rows
// in the target table(s). Use with care in production to avoid unintentional full
// table scans or mass updates.
//
// Returns ErrUnsupportedStatement for INSERT or DDL statements.
func RemoveWhere() Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		where, err := getWhere(stmt)
		if err != nil {
			return err
		}
		*where = nil
		return nil
	})
}

// ReplaceWhere returns a Rule that unconditionally replaces the WHERE clause of a
// SELECT, UPDATE, or DELETE statement with the given condition. Unlike AddWhere,
// this discards any existing WHERE predicate instead of combining with AND.
//
// Parameters:
//   - condition: The new AST expression to use as the WHERE predicate
//
// Returns ErrUnsupportedStatement for INSERT or DDL statements.
func ReplaceWhere(condition ast.Expression) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		where, err := getWhere(stmt)
		if err != nil {
			return err
		}
		*where = condition
		return nil
	})
}

// AddWhereFromSQL returns a Rule that parses a SQL condition string and adds it
// as an AND condition to the existing WHERE clause.
//
// WARNING: sql parameter must not contain untrusted user input.
// This function parses raw SQL — passing unsanitized input could
// produce unintended query modifications. Use parameterized queries
// or construct AST nodes directly for untrusted input.
func AddWhereFromSQL(sql string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		condition, err := parseCondition(sql)
		if err != nil {
			return err
		}
		return AddWhere(condition).Apply(stmt)
	})
}
