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

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// SetLimit returns a Rule that sets (or replaces) the LIMIT clause of a SELECT
// statement. Any existing LIMIT value is overwritten.
//
// Parameters:
//   - n: Number of rows to return; must be >= 0. Returns an error for negative values.
//
// Returns ErrUnsupportedStatement for non-SELECT statements.
func SetLimit(n int) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		if n < 0 {
			return fmt.Errorf("SetLimit: value must be non-negative, got %d", n)
		}
		sel, err := getSelect(stmt, "SetLimit")
		if err != nil {
			return err
		}
		sel.Limit = &n
		return nil
	})
}

// SetOffset returns a Rule that sets (or replaces) the OFFSET clause of a SELECT
// statement. Use together with SetLimit to implement pagination.
//
// Parameters:
//   - n: Number of rows to skip; must be >= 0. Returns an error for negative values.
//
// Returns ErrUnsupportedStatement for non-SELECT statements.
func SetOffset(n int) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		if n < 0 {
			return fmt.Errorf("SetOffset: value must be non-negative, got %d", n)
		}
		sel, err := getSelect(stmt, "SetOffset")
		if err != nil {
			return err
		}
		sel.Offset = &n
		return nil
	})
}

// RemoveLimit returns a Rule that removes the LIMIT clause from a SELECT statement,
// allowing the query to return an unbounded number of rows.
//
// Returns ErrUnsupportedStatement for non-SELECT statements.
func RemoveLimit() Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "RemoveLimit")
		if err != nil {
			return err
		}
		sel.Limit = nil
		return nil
	})
}

// RemoveOffset returns a Rule that removes the OFFSET clause from a SELECT statement,
// resetting pagination to start from the first row.
//
// Returns ErrUnsupportedStatement for non-SELECT statements.
func RemoveOffset() Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "RemoveOffset")
		if err != nil {
			return err
		}
		sel.Offset = nil
		return nil
	})
}
