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
	"strconv"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// SetLimit returns a Rule that sets or replaces the row limit of a SELECT,
// preserving an existing TOP or FETCH clause. PERCENT and WITH TIES are rejected.
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
		if err := checkPaginationModifiers(sel, "SetLimit"); err != nil {
			return err
		}
		switch {
		case sel.Top != nil:
			sel.Top.Count = &ast.LiteralValue{Value: strconv.Itoa(n), Type: "INTEGER"}
			sel.Limit = nil
		case sel.Fetch != nil:
			value := int64(n)
			sel.Fetch.FetchValue = &value
			sel.Fetch.FetchExpr = nil
			sel.Limit = nil
		default:
			sel.Limit = &n
		}
		if sel.Extras != nil {
			sel.Extras.LimitExpr = nil
			sel.Extras.LimitAll = false
		}
		return nil
	})
}

// SetOffset returns a Rule that sets (or replaces) the OFFSET clause of a SELECT
// statement. Use together with SetLimit to implement pagination. TOP and
// FETCH PERCENT or WITH TIES clauses are rejected.
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
		if err := checkPaginationModifiers(sel, "SetOffset"); err != nil {
			return err
		}
		if sel.Top != nil {
			return fmt.Errorf("SetOffset: cannot combine OFFSET with TOP")
		}
		sel.Offset = &n
		if sel.Fetch != nil {
			sel.Fetch.OffsetValue = nil
		}
		if sel.Extras != nil {
			sel.Extras.OffsetExpr = nil
		}
		return nil
	})
}

// RemoveLimit returns a Rule that removes LIMIT, TOP, or FETCH from a SELECT,
// allowing an unbounded number of rows. PERCENT and WITH TIES are rejected.
//
// Returns ErrUnsupportedStatement for non-SELECT statements.
func RemoveLimit() Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		sel, err := getSelect(stmt, "RemoveLimit")
		if err != nil {
			return err
		}
		if err := checkPaginationModifiers(sel, "RemoveLimit"); err != nil {
			return err
		}
		// Preserve the offset of ASTs constructed with the legacy FETCH field.
		if sel.Fetch != nil && sel.Fetch.OffsetValue != nil && sel.Offset == nil && sel.DialectExtras().OffsetExpr == nil {
			offset := int(*sel.Fetch.OffsetValue)
			sel.Offset = &offset
			sel.EnsureExtras().OffsetRows = true
		}
		sel.Limit = nil
		sel.Top = nil
		sel.Fetch = nil
		if sel.Extras != nil {
			sel.Extras.LimitExpr = nil
			sel.Extras.LimitAll = false
			sel.Extras.LimitWithTies = false
		}
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
		if sel.Fetch != nil {
			sel.Fetch.OffsetValue = nil
		}
		if sel.Extras != nil {
			sel.Extras.OffsetExpr = nil
			sel.Extras.OffsetRows = false
		}
		return nil
	})
}

// Percentages and ties change the meaning of a row count; reject them before mutation.
func checkPaginationModifiers(sel *ast.SelectStatement, operation string) error {
	if sel.Top != nil && (sel.Top.IsPercent || sel.Top.WithTies) {
		return fmt.Errorf("%s: TOP PERCENT or WITH TIES is not supported", operation)
	}
	if sel.Fetch != nil && (sel.Fetch.IsPercent || sel.Fetch.WithTies) {
		return fmt.Errorf("%s: FETCH PERCENT or WITH TIES is not supported", operation)
	}
	return nil
}
