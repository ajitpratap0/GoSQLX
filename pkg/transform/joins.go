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

// validJoinTypes is the set of supported JOIN types.
var validJoinTypes = map[string]bool{
	"INNER":   true,
	"LEFT":    true,
	"RIGHT":   true,
	"FULL":    true,
	"CROSS":   true,
	"NATURAL": true,
}

// AddJoin returns a Rule that adds a JOIN clause to a SELECT statement.
// joinType must be one of: INNER, LEFT, RIGHT, FULL, CROSS, NATURAL.
func AddJoin(joinType string, table string, condition ast.Expression) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		upper := strings.ToUpper(joinType)
		if !validJoinTypes[upper] {
			return fmt.Errorf("AddJoin: unknown join type %q (valid: INNER, LEFT, RIGHT, FULL, CROSS, NATURAL)", joinType)
		}
		sel, err := getSelect(stmt, "AddJoin")
		if err != nil {
			return err
		}
		sel.Joins = append(sel.Joins, ast.JoinClause{
			Type:      upper,
			Right:     ast.TableReference{Name: table},
			Condition: condition,
		})
		return nil
	})
}

// RemoveJoin returns a Rule that removes a JOIN by table name from a SELECT statement.
func RemoveJoin(tableName string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "RemoveJoin")
		if err != nil {
			return err
		}
		lower := strings.ToLower(tableName)
		filtered := make([]ast.JoinClause, 0, len(sel.Joins))
		for _, j := range sel.Joins {
			if strings.ToLower(j.Right.Name) != lower && strings.ToLower(j.Right.Alias) != lower {
				filtered = append(filtered, j)
			}
		}
		sel.Joins = filtered
		return nil
	})
}

// AddJoinFromSQL returns a Rule that parses a JOIN clause from SQL and adds it
// to a SELECT statement. The sql parameter should be a complete JOIN clause,
// e.g. "LEFT JOIN orders ON orders.user_id = users.id".
//
// WARNING: sql parameter must not contain untrusted user input.
// This function parses raw SQL — passing unsanitized input could
// produce unintended query modifications. Use parameterized queries
// or construct AST nodes directly for untrusted input.
func AddJoinFromSQL(sql string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		join, err := parseJoinClause(sql)
		if err != nil {
			return err
		}
		sel, err := getSelect(stmt, "AddJoinFromSQL")
		if err != nil {
			return err
		}
		sel.Joins = append(sel.Joins, *join)
		return nil
	})
}
