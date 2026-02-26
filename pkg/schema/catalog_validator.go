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

package schema

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// CatalogValidator validates SQL queries against a full Catalog (multi-schema).
// It supports all the same checks as Validator plus cross-schema resolution.
//
// Example:
//
//	cat, _ := schema.LoadCatalogFromDDL(ddl)
//	cv := schema.NewCatalogValidator(cat)
//	errors, err := cv.Validate("SELECT id, name FROM users WHERE bogus = 1")
type CatalogValidator struct {
	Catalog *Catalog
}

// NewCatalogValidator creates a CatalogValidator for the given catalog.
func NewCatalogValidator(cat *Catalog) *CatalogValidator {
	return &CatalogValidator{Catalog: cat}
}

// Validate parses the SQL string and validates it against the catalog.
func (cv *CatalogValidator) Validate(sql string) ([]ValidationError, error) {
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SQL: %w", err)
	}
	return cv.ValidateAST(tree), nil
}

// ValidateAST validates a parsed AST against the catalog.
func (cv *CatalogValidator) ValidateAST(tree *ast.AST) []ValidationError {
	var errs []ValidationError
	for _, stmt := range tree.Statements {
		errs = append(errs, cv.validateStatement(stmt)...)
	}
	return errs
}

// ValidateQuery validates a pre-parsed AST against an explicit catalog.
// This is a convenience function for when the caller already has both.
func ValidateQuery(tree *ast.AST, cat *Catalog) []ValidationError {
	return NewCatalogValidator(cat).ValidateAST(tree)
}

// validateStatement dispatches based on statement type.
func (cv *CatalogValidator) validateStatement(stmt ast.Statement) []ValidationError {
	// Use the default schema as a single-schema validator for simple cases.
	defaultSchema, hasDefault := cv.Catalog.GetDefaultSchema()
	if !hasDefault && len(cv.Catalog.Schemas) > 0 {
		// Fall back to the alphabetically-first schema
		for _, name := range cv.Catalog.SchemaNames() {
			if s, ok := cv.Catalog.GetSchema(name); ok {
				defaultSchema = s
				break
			}
		}
	}
	if defaultSchema == nil {
		defaultSchema = NewSchema("empty")
	}

	// Delegate statement-level validation to the schema-level validator.
	sv := &Validator{Schema: defaultSchema}
	errs := sv.validateStatement(stmt)

	// Additionally validate ORDER BY and GROUP BY aggregate semantics.
	if sel, ok := stmt.(*ast.SelectStatement); ok {
		errs = append(errs, cv.validateSelectExtended(sel, sv)...)
	}

	return errs
}

// validateSelectExtended performs additional SELECT validations:
//  1. ORDER BY column references
//  2. GROUP BY aggregate rules (non-aggregate columns with GROUP BY,
//     aggregate functions without GROUP BY when non-aggregates also present)
func (cv *CatalogValidator) validateSelectExtended(s *ast.SelectStatement, sv *Validator) []ValidationError {
	var errs []ValidationError

	// Build tableMap the same way Validator.validateSelect does
	tableMap := getTableMap()
	defer putTableMap(tableMap)

	for _, ref := range s.From {
		if ref.Name == "" {
			continue
		}
		if ref.Alias != "" {
			tableMap[ref.Alias] = ref.Name
		} else {
			tableMap[ref.Name] = ref.Name
		}
	}
	for _, join := range s.Joins {
		if join.Right.Name == "" {
			continue
		}
		if join.Right.Alias != "" {
			tableMap[join.Right.Alias] = join.Right.Name
		} else {
			tableMap[join.Right.Name] = join.Right.Name
		}
		if join.Left.Name != "" {
			if join.Left.Alias != "" {
				tableMap[join.Left.Alias] = join.Left.Name
			} else {
				tableMap[join.Left.Name] = join.Left.Name
			}
		}
	}

	// 1. Validate ORDER BY column references
	errs = append(errs, validateOrderBy(sv, s.OrderBy, tableMap, s.Columns)...)

	// 2. GROUP BY aggregate validation
	errs = append(errs, validateGroupByAggregates(sv, s, tableMap)...)

	return errs
}

// ---------------------------------------------------------------------------
// ORDER BY validation
// ---------------------------------------------------------------------------

// validateOrderBy checks that ORDER BY expressions reference valid columns.
// ORDER BY items can be:
//   - An integer position (1-based) — always valid
//   - An alias defined in SELECT — valid
//   - A qualified/unqualified column in scope — validated against schema
func validateOrderBy(sv *Validator, orderBy []ast.OrderByExpression, tableMap map[string]string, selectCols []ast.Expression) []ValidationError {
	if len(orderBy) == 0 {
		return nil
	}

	// Collect SELECT aliases
	selectAliases := collectSelectAliases(selectCols)

	var errs []ValidationError
	for _, ob := range orderBy {
		if ob.Expression == nil {
			continue
		}
		// Integer position literals are valid (e.g., ORDER BY 1)
		if lit, ok := ob.Expression.(*ast.LiteralValue); ok {
			if _, isNum := lit.Value.(int); isNum {
				continue
			}
			if _, isNum := lit.Value.(int64); isNum {
				continue
			}
			if _, isNum := lit.Value.(float64); isNum {
				continue
			}
		}
		// Column alias from SELECT — valid
		if ident, ok := ob.Expression.(*ast.Identifier); ok && ident.Table == "" {
			if selectAliases[strings.ToLower(ident.Name)] {
				continue
			}
		}
		// Validate as a column reference
		errs = append(errs, sv.validateExpressionColumns(ob.Expression, tableMap)...)
	}
	return errs
}

// collectSelectAliases returns a set of alias names (lowercase) defined in SELECT.
func collectSelectAliases(cols []ast.Expression) map[string]bool {
	aliases := make(map[string]bool, len(cols))
	for _, col := range cols {
		if ae, ok := col.(*ast.AliasedExpression); ok && ae.Alias != "" {
			aliases[strings.ToLower(ae.Alias)] = true
		}
	}
	return aliases
}

// ---------------------------------------------------------------------------
// GROUP BY aggregate validation
// ---------------------------------------------------------------------------

// aggregateFunctions is the set of SQL aggregate function names.
var aggregateFunctions = map[string]bool{
	"count":        true,
	"sum":          true,
	"avg":          true,
	"min":          true,
	"max":          true,
	"array_agg":    true,
	"string_agg":   true,
	"listagg":      true,
	"group_concat": true,
	"first":        true,
	"last":         true,
	"stddev":       true,
	"variance":     true,
	"bit_and":      true,
	"bit_or":       true,
	"bool_and":     true,
	"bool_or":      true,
	"every":        true,
	"json_agg":     true,
	"jsonb_agg":    true,
	"percentile_cont": true,
	"percentile_disc": true,
}

// isAggregateExpr returns true if the expression is or contains an aggregate function.
func isAggregateExpr(expr ast.Expression) bool {
	if expr == nil {
		return false
	}
	switch e := expr.(type) {
	case *ast.FunctionCall:
		if aggregateFunctions[strings.ToLower(e.Name)] {
			return true
		}
		for _, arg := range e.Arguments {
			if isAggregateExpr(arg) {
				return true
			}
		}
	case *ast.AliasedExpression:
		return isAggregateExpr(e.Expr)
	case *ast.BinaryExpression:
		return isAggregateExpr(e.Left) || isAggregateExpr(e.Right)
	case *ast.UnaryExpression:
		return isAggregateExpr(e.Expr)
	case *ast.CaseExpression:
		for _, when := range e.WhenClauses {
			if isAggregateExpr(when.Result) {
				return true
			}
		}
		if isAggregateExpr(e.ElseClause) {
			return true
		}
	case *ast.CastExpression:
		return isAggregateExpr(e.Expr)
	}
	return false
}

// collectColumnRefs returns all simple column references (unqualified names) in expr.
func collectColumnRefs(expr ast.Expression) []string {
	if expr == nil {
		return nil
	}
	var refs []string
	switch e := expr.(type) {
	case *ast.Identifier:
		if e.Name != "*" && e.Table == "" {
			refs = append(refs, strings.ToLower(e.Name))
		}
		if e.Name != "*" && e.Table != "" {
			refs = append(refs, strings.ToLower(e.Table+"."+e.Name))
		}
	case *ast.AliasedExpression:
		refs = append(refs, collectColumnRefs(e.Expr)...)
	case *ast.BinaryExpression:
		refs = append(refs, collectColumnRefs(e.Left)...)
		refs = append(refs, collectColumnRefs(e.Right)...)
	case *ast.UnaryExpression:
		refs = append(refs, collectColumnRefs(e.Expr)...)
	case *ast.FunctionCall:
		for _, arg := range e.Arguments {
			refs = append(refs, collectColumnRefs(arg)...)
		}
	case *ast.CaseExpression:
		refs = append(refs, collectColumnRefs(e.Value)...)
		for _, when := range e.WhenClauses {
			refs = append(refs, collectColumnRefs(when.Condition)...)
			refs = append(refs, collectColumnRefs(when.Result)...)
		}
		refs = append(refs, collectColumnRefs(e.ElseClause)...)
	case *ast.CastExpression:
		refs = append(refs, collectColumnRefs(e.Expr)...)
	case *ast.BetweenExpression:
		refs = append(refs, collectColumnRefs(e.Expr)...)
		refs = append(refs, collectColumnRefs(e.Lower)...)
		refs = append(refs, collectColumnRefs(e.Upper)...)
	}
	return refs
}

// validateGroupByAggregates checks GROUP BY aggregate rules:
//  1. If SELECT has aggregates and non-aggregate columns but no GROUP BY → warning
//  2. If SELECT has GROUP BY, every non-aggregate SELECT column must appear in GROUP BY
func validateGroupByAggregates(sv *Validator, s *ast.SelectStatement, tableMap map[string]string) []ValidationError {
	// Skip if no explicit columns or using SELECT *
	if len(s.Columns) == 0 {
		return nil
	}

	// Collect GROUP BY column names (lowercase)
	groupByCols := make(map[string]bool, len(s.GroupBy))
	for _, gb := range s.GroupBy {
		for _, ref := range collectColumnRefs(gb) {
			groupByCols[ref] = true
		}
	}

	hasGroupBy := len(s.GroupBy) > 0

	// Classify SELECT columns into aggregate vs non-aggregate
	var aggCols, nonAggCols []string
	hasWildcard := false

	for _, col := range s.Columns {
		// Unwrap aliased expression
		inner := col
		if ae, ok := col.(*ast.AliasedExpression); ok {
			inner = ae.Expr
		}

		if ident, ok := inner.(*ast.Identifier); ok && ident.Name == "*" {
			hasWildcard = true
			continue
		}
		if isAggregateExpr(col) {
			aggCols = append(aggCols, "agg")
		} else {
			refs := collectColumnRefs(col)
			if len(refs) > 0 {
				nonAggCols = append(nonAggCols, refs...)
			}
		}
	}

	if hasWildcard {
		return nil // can't check * references
	}

	var errs []ValidationError

	// Rule 1: aggregate + non-aggregate columns but no GROUP BY
	if len(aggCols) > 0 && len(nonAggCols) > 0 && !hasGroupBy {
		errs = append(errs, ValidationError{
			Message: fmt.Sprintf(
				"non-aggregated column(s) (%s) mixed with aggregate functions in SELECT without GROUP BY",
				strings.Join(nonAggCols, ", "),
			),
			Severity:   "error",
			Suggestion: fmt.Sprintf("add GROUP BY %s or use aggregate functions for all columns", strings.Join(nonAggCols, ", ")),
		})
	}

	// Rule 2: GROUP BY present — every non-aggregate SELECT column must be in GROUP BY
	if hasGroupBy {
		for _, colRef := range nonAggCols {
			// colRef may be "table.col" or just "col" — check both
			inGroupBy := groupByCols[colRef]
			if !inGroupBy {
				// Try just the column part (strip table qualifier)
				if idx := strings.Index(colRef, "."); idx != -1 {
					inGroupBy = groupByCols[colRef[idx+1:]]
				}
			}
			if !inGroupBy {
				errs = append(errs, ValidationError{
					Message: fmt.Sprintf(
						"column %q must appear in GROUP BY or be used in an aggregate function",
						colRef,
					),
					Severity:   "error",
					Suggestion: fmt.Sprintf("add %q to the GROUP BY clause", colRef),
				})
			}
		}
	}

	return errs
}

// ---------------------------------------------------------------------------
// Validator enhancements — ORDER BY & GROUP BY plumbed into existing Validator
// ---------------------------------------------------------------------------

// ValidateSelectFull performs full SELECT validation including ORDER BY and
// GROUP BY aggregate semantics via the existing single-schema Validator.
// This makes the enhanced validation available without requiring a Catalog.
func (v *Validator) ValidateSelectFull(sql string) ([]ValidationError, error) {
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SQL: %w", err)
	}
	var errs []ValidationError
	for _, stmt := range tree.Statements {
		errs = append(errs, v.validateStatement(stmt)...)
		if sel, ok := stmt.(*ast.SelectStatement); ok {
			tableMap := getTableMap()
			for _, ref := range sel.From {
				if ref.Name == "" {
					continue
				}
				if ref.Alias != "" {
					tableMap[ref.Alias] = ref.Name
				} else {
					tableMap[ref.Name] = ref.Name
				}
			}
			for _, join := range sel.Joins {
				if join.Right.Name == "" {
					continue
				}
				if join.Right.Alias != "" {
					tableMap[join.Right.Alias] = join.Right.Name
				} else {
					tableMap[join.Right.Name] = join.Right.Name
				}
				if join.Left.Name != "" {
					if join.Left.Alias != "" {
						tableMap[join.Left.Alias] = join.Left.Name
					} else {
						tableMap[join.Left.Name] = join.Left.Name
					}
				}
			}
			errs = append(errs, validateOrderBy(v, sel.OrderBy, tableMap, sel.Columns)...)
			errs = append(errs, validateGroupByAggregates(v, sel, tableMap)...)
			putTableMap(tableMap)
		}
	}
	return errs, nil
}
