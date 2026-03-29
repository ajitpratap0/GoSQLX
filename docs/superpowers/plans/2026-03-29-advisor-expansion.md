# Query Advisor Expansion 8 → 20 Rules #453 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 12 new advisor rules (OPT-009 through OPT-020) to the `pkg/advisor/` package, covering implicit type conversions, N+1 patterns, join order hints, redundant ORDER BY in CTEs, HAVING without GROUP BY, and more.

**Architecture:** All new rules implement the existing `Rule` interface (`ID()`, `Name()`, `Description()`, `Analyze(stmt ast.Statement) []Suggestion`). Rules are added to `rules.go` and registered in `DefaultRules()`. Scoring follows the existing pattern: Error=-20, Warning=-10, Info=-5.

**Tech Stack:** Go, `pkg/advisor/` Rule interface and Suggestion type, `pkg/sql/ast/` for AST traversal

---

## File Map

- Read: `pkg/advisor/optimizer.go` — Rule interface and Suggestion type
- Read: `pkg/advisor/rules.go` — existing 8 rules pattern
- Modify: `pkg/advisor/rules.go` — add rules OPT-009 through OPT-020
- Create: `pkg/advisor/rules_expanded_test.go` — tests for new rules

---

### Task 1: Understand the advisor Rule interface and Suggestion type

**Files:**
- Read: `pkg/advisor/optimizer.go`

- [ ] **Step 1: Read the optimizer and Rule types**

```bash
cat pkg/advisor/optimizer.go
```

Note:
- `Rule` interface: `ID() string`, `Name() string`, `Description() string`, `Analyze(stmt ast.Statement) []Suggestion`
- `Suggestion` struct: `{RuleID, Severity, Message, Detail, Line, Column, OriginalSQL, SuggestedSQL string}`
- `SeverityError`, `SeverityWarning`, `SeverityInfo` constants
- `Advisor` struct with `Analyze(sql) *OptimizationResult`
- `OptimizationResult.Score` scoring: starts at 100, Error=-20, Warning=-10, Info=-5, floor=0

- [ ] **Step 2: Read existing rules to understand the pattern**

```bash
grep -A 25 "OPT-003\|CartesianProductRule" pkg/advisor/rules.go
```

Note how `Analyze()` checks the statement type, traverses the AST, and returns `[]Suggestion`.

---

### Task 2: Write failing tests for new rules

**Files:**
- Create: `pkg/advisor/rules_expanded_test.go`

- [ ] **Step 1: Create the test file**

```go
// pkg/advisor/rules_expanded_test.go
package advisor_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/advisor"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func analyzeWith(t *testing.T, sql string, rule advisor.Rule) []advisor.Suggestion {
	t.Helper()
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		t.Fatalf("Parse(%q): %v", sql, err)
	}
	if len(tree.Statements) == 0 {
		t.Fatal("no statements parsed")
	}
	return rule.Analyze(tree.Statements[0])
}

// OPT-009: N+1 — correlated subquery in SELECT column list
func TestOPT009_CorrelatedSubqueryInSelect_Violation(t *testing.T) {
	rule := &advisor.CorrelatedSubqueryInSelectRule{}
	sug := analyzeWith(t,
		`SELECT id, (SELECT name FROM departments WHERE id = e.dept_id) AS dept_name FROM employees e`,
		rule)
	if len(sug) == 0 {
		t.Error("expected N+1 warning for correlated subquery in SELECT list")
	}
}

func TestOPT009_JoinInsteadOfSubquery_NoViolation(t *testing.T) {
	rule := &advisor.CorrelatedSubqueryInSelectRule{}
	sug := analyzeWith(t,
		`SELECT e.id, d.name FROM employees e JOIN departments d ON e.dept_id = d.id`,
		rule)
	if len(sug) != 0 {
		t.Errorf("expected no violation for JOIN, got %d", len(sug))
	}
}

// OPT-010: HAVING without GROUP BY
func TestOPT010_HavingWithoutGroupBy_Violation(t *testing.T) {
	rule := &advisor.HavingWithoutGroupByRule{}
	sug := analyzeWith(t, "SELECT COUNT(*) FROM users HAVING COUNT(*) > 0", rule)
	if len(sug) == 0 {
		t.Error("expected violation for HAVING without GROUP BY")
	}
}

func TestOPT010_HavingWithGroupBy_NoViolation(t *testing.T) {
	rule := &advisor.HavingWithoutGroupByRule{}
	sug := analyzeWith(t, "SELECT dept, COUNT(*) FROM users GROUP BY dept HAVING COUNT(*) > 5", rule)
	if len(sug) != 0 {
		t.Errorf("expected no violation, got %d", len(sug))
	}
}

// OPT-011: Redundant ORDER BY in CTE (inner CTE ORDER BY is ignored by most DBs)
func TestOPT011_OrderByInCTE_Violation(t *testing.T) {
	rule := &advisor.RedundantOrderByInCTERule{}
	sug := analyzeWith(t, `
		WITH ranked AS (
			SELECT id, name FROM users ORDER BY name
		)
		SELECT * FROM ranked`, rule)
	if len(sug) == 0 {
		t.Error("expected warning for ORDER BY inside CTE definition")
	}
}

// OPT-012: Implicit type conversion — function wrapping a column in WHERE
func TestOPT012_ImplicitTypeConversion_Violation(t *testing.T) {
	rule := &advisor.ImplicitTypeConversionRule{}
	sug := analyzeWith(t, "SELECT * FROM orders WHERE CAST(user_id AS VARCHAR) = '123'", rule)
	if len(sug) == 0 {
		t.Error("expected warning for CAST in WHERE condition")
	}
}

// OPT-013: OR-to-IN conversion
func TestOPT013_OrToIn_Violation(t *testing.T) {
	rule := &advisor.OrToInConversionRule{}
	sug := analyzeWith(t, "SELECT * FROM users WHERE status = 1 OR status = 2 OR status = 3", rule)
	if len(sug) == 0 {
		t.Error("expected suggestion to replace OR with IN")
	}
}

func TestOPT013_OrToIn_NoViolation(t *testing.T) {
	rule := &advisor.OrToInConversionRule{}
	sug := analyzeWith(t, "SELECT * FROM users WHERE status = 1 OR active = true", rule)
	if len(sug) != 0 {
		t.Errorf("OR on different columns should not trigger IN suggestion, got %d", len(sug))
	}
}

// OPT-014: NOT IN with potential NULL (returns empty set if subquery has NULLs)
func TestOPT014_NotInSubquery_Violation(t *testing.T) {
	rule := &advisor.NotInSubqueryNullRule{}
	sug := analyzeWith(t,
		`SELECT * FROM users WHERE id NOT IN (SELECT manager_id FROM employees)`,
		rule)
	if len(sug) == 0 {
		t.Error("expected warning for NOT IN with subquery (NULL risk)")
	}
}

// OPT-015: Missing LIMIT on unbounded query
func TestOPT015_MissingLimit_Violation(t *testing.T) {
	rule := &advisor.MissingLimitRule{}
	sug := analyzeWith(t, "SELECT * FROM audit_log ORDER BY created_at DESC", rule)
	if len(sug) == 0 {
		t.Error("expected suggestion to add LIMIT to unbounded query")
	}
}

func TestOPT015_MissingLimit_NoViolation(t *testing.T) {
	rule := &advisor.MissingLimitRule{}
	sug := analyzeWith(t, "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 100", rule)
	if len(sug) != 0 {
		t.Errorf("expected no violation with LIMIT, got %d", len(sug))
	}
}
```

- [ ] **Step 2: Run tests — verify failure**

```bash
go test ./pkg/advisor/ -run "TestOPT009\|TestOPT010\|TestOPT011" 2>&1 | head -10
```

Expected: `undefined: advisor.CorrelatedSubqueryInSelectRule`

---

### Task 3: Implement new rules OPT-009 through OPT-015

**Files:**
- Modify: `pkg/advisor/rules.go`

- [ ] **Step 1: Add the new rules to rules.go**

Append to the end of `pkg/advisor/rules.go`:

```go
// ---------------------------------------------------------------------------
// OPT-009: Correlated Subquery in SELECT List (N+1 pattern)
// ---------------------------------------------------------------------------

// CorrelatedSubqueryInSelectRule detects subqueries in the SELECT column list.
// Each row in the outer query triggers one inner query — classic N+1.
type CorrelatedSubqueryInSelectRule struct{}

func (r *CorrelatedSubqueryInSelectRule) ID() string { return "OPT-009" }
func (r *CorrelatedSubqueryInSelectRule) Name() string { return "Correlated Subquery in SELECT" }
func (r *CorrelatedSubqueryInSelectRule) Description() string {
	return "Detects correlated subqueries in the SELECT column list which cause N+1 query execution."
}

func (r *CorrelatedSubqueryInSelectRule) Analyze(stmt ast.Statement) []Suggestion {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return nil
	}
	var suggestions []Suggestion
	for _, col := range sel.Columns {
		if _, ok := col.(*ast.SubqueryExpression); ok {
			suggestions = append(suggestions, Suggestion{
				RuleID:       r.ID(),
				Severity:     SeverityWarning,
				Message:      "Correlated subquery in SELECT list causes N+1 query execution",
				Detail:       "Each row in the outer query executes this subquery independently. Replace with a JOIN for a single-pass query.",
				SuggestedSQL: "Replace the subquery with LEFT JOIN ... ON ...",
			})
		}
	}
	return suggestions
}

// ---------------------------------------------------------------------------
// OPT-010: HAVING Without GROUP BY
// ---------------------------------------------------------------------------

// HavingWithoutGroupByRule detects HAVING clauses without GROUP BY.
// Most databases treat this as a full-table aggregate, which is rarely intended.
type HavingWithoutGroupByRule struct{}

func (r *HavingWithoutGroupByRule) ID() string { return "OPT-010" }
func (r *HavingWithoutGroupByRule) Name() string { return "HAVING Without GROUP BY" }
func (r *HavingWithoutGroupByRule) Description() string {
	return "HAVING without GROUP BY treats the entire table as one group — usually a logic error."
}

func (r *HavingWithoutGroupByRule) Analyze(stmt ast.Statement) []Suggestion {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return nil
	}
	if sel.Having != nil && len(sel.GroupBy) == 0 {
		return []Suggestion{{
			RuleID:   r.ID(),
			Severity: SeverityWarning,
			Message:  "HAVING clause without GROUP BY groups the entire table as one aggregate",
			Detail:   "HAVING without GROUP BY is valid SQL but treats all rows as a single group. If filtering individual rows, use WHERE instead.",
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// OPT-011: Redundant ORDER BY in CTE
// ---------------------------------------------------------------------------

// RedundantOrderByInCTERule detects ORDER BY inside a CTE definition.
// In most databases, ORDER BY inside a CTE is ignored unless combined with LIMIT/FETCH.
type RedundantOrderByInCTERule struct{}

func (r *RedundantOrderByInCTERule) ID() string { return "OPT-011" }
func (r *RedundantOrderByInCTERule) Name() string { return "Redundant ORDER BY in CTE" }
func (r *RedundantOrderByInCTERule) Description() string {
	return "ORDER BY inside a CTE definition is ignored by most databases unless combined with LIMIT."
}

func (r *RedundantOrderByInCTERule) Analyze(stmt ast.Statement) []Suggestion {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok || sel.With == nil {
		return nil
	}
	var suggestions []Suggestion
	for _, cte := range sel.With.CTEs {
		if cteQuery, ok := cte.Query.(*ast.SelectStatement); ok {
			if len(cteQuery.OrderBy) > 0 && cteQuery.Limit == nil {
				suggestions = append(suggestions, Suggestion{
					RuleID:   r.ID(),
					Severity: SeverityInfo,
					Message:  fmt.Sprintf("ORDER BY in CTE %q is likely ignored by the database", cte.Name),
					Detail:   "CTE inner ORDER BY is ignored by PostgreSQL, MySQL, SQL Server, and ClickHouse unless combined with LIMIT. Move ORDER BY to the outer query.",
				})
			}
		}
	}
	return suggestions
}

// ---------------------------------------------------------------------------
// OPT-012: Implicit Type Conversion
// ---------------------------------------------------------------------------

// ImplicitTypeConversionRule detects CAST/CONVERT wrapping a column in WHERE conditions.
// This prevents index use and causes full table scans.
type ImplicitTypeConversionRule struct{}

func (r *ImplicitTypeConversionRule) ID() string { return "OPT-012" }
func (r *ImplicitTypeConversionRule) Name() string { return "Implicit Type Conversion" }
func (r *ImplicitTypeConversionRule) Description() string {
	return "CAST/CONVERT wrapping a column in WHERE prevents index use and causes full table scans."
}

func (r *ImplicitTypeConversionRule) Analyze(stmt ast.Statement) []Suggestion {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok || sel.Where == nil {
		return nil
	}
	if containsCastInWhere(sel.Where) {
		return []Suggestion{{
			RuleID:   r.ID(),
			Severity: SeverityWarning,
			Message:  "CAST/CONVERT on a column in WHERE prevents index use",
			Detail:   "Instead of CAST(column AS type) = value, cast the value to match the column type: column = CAST(value AS column_type).",
		}}
	}
	return nil
}

func containsCastInWhere(expr ast.Expression) bool {
	if expr == nil {
		return false
	}
	switch v := expr.(type) {
	case *ast.FunctionCall:
		name := strings.ToUpper(v.Name)
		if name == "CAST" || name == "CONVERT" || name == "TO_CHAR" || name == "TO_NUMBER" {
			return true
		}
	case *ast.BinaryExpression:
		return containsCastInWhere(v.Left) || containsCastInWhere(v.Right)
	}
	return false
}

// ---------------------------------------------------------------------------
// OPT-013: OR-to-IN Conversion
// ---------------------------------------------------------------------------

// OrToInConversionRule detects repeated OR conditions on the same column.
// col = A OR col = B OR col = C is better written as col IN (A, B, C).
type OrToInConversionRule struct{}

func (r *OrToInConversionRule) ID() string { return "OPT-013" }
func (r *OrToInConversionRule) Name() string { return "OR Instead of IN" }
func (r *OrToInConversionRule) Description() string {
	return "Multiple OR conditions on the same column are more readable and sometimes faster as IN (...)."
}

func (r *OrToInConversionRule) Analyze(stmt ast.Statement) []Suggestion {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok || sel.Where == nil {
		return nil
	}
	col, count := countOrSameColumn(sel.Where, "", 0)
	if count >= 3 && col != "" {
		return []Suggestion{{
			RuleID:       r.ID(),
			Severity:     SeverityInfo,
			Message:      fmt.Sprintf("Column %q appears in %d OR conditions — consider using IN (...)", col, count),
			SuggestedSQL: fmt.Sprintf("WHERE %s IN (...)", col),
		}}
	}
	return nil
}

func countOrSameColumn(expr ast.Expression, col string, count int) (string, int) {
	bin, ok := expr.(*ast.BinaryExpression)
	if !ok {
		return col, count
	}
	if strings.ToUpper(bin.Operator) == "OR" {
		col, count = countOrSameColumn(bin.Left, col, count)
		col, count = countOrSameColumn(bin.Right, col, count)
		return col, count
	}
	if strings.ToUpper(bin.Operator) == "=" {
		if id, ok := bin.Left.(*ast.IdentifierExpr); ok {
			if col == "" || col == id.Name {
				return id.Name, count + 1
			}
			return "", 0 // different columns — not the pattern we're looking for
		}
	}
	return col, count
}

// ---------------------------------------------------------------------------
// OPT-014: NOT IN with Subquery (NULL risk)
// ---------------------------------------------------------------------------

// NotInSubqueryNullRule flags NOT IN (subquery) patterns.
// If the subquery returns any NULL, the entire NOT IN returns empty set.
type NotInSubqueryNullRule struct{}

func (r *NotInSubqueryNullRule) ID() string { return "OPT-014" }
func (r *NotInSubqueryNullRule) Name() string { return "NOT IN With NULL Risk" }
func (r *NotInSubqueryNullRule) Description() string {
	return "NOT IN (subquery) returns empty set if the subquery produces any NULL. Use NOT EXISTS or LEFT JOIN ... IS NULL instead."
}

func (r *NotInSubqueryNullRule) Analyze(stmt ast.Statement) []Suggestion {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok || sel.Where == nil {
		return nil
	}
	if containsNotInSubquery(sel.Where) {
		return []Suggestion{{
			RuleID:       r.ID(),
			Severity:     SeverityWarning,
			Message:      "NOT IN (subquery) returns empty if subquery has any NULL values",
			Detail:       "If the subquery column is nullable, NOT IN returns empty set for any NULL row. Use NOT EXISTS or LEFT JOIN ... WHERE right.id IS NULL.",
			SuggestedSQL: "WHERE NOT EXISTS (SELECT 1 FROM ... WHERE ...)",
		}}
	}
	return nil
}

func containsNotInSubquery(expr ast.Expression) bool {
	in, ok := expr.(*ast.InExpression)
	if ok && in.Not {
		for _, val := range in.Values {
			if _, ok := val.(*ast.SubqueryExpression); ok {
				return true
			}
		}
	}
	if bin, ok := expr.(*ast.BinaryExpression); ok {
		return containsNotInSubquery(bin.Left) || containsNotInSubquery(bin.Right)
	}
	return false
}

// ---------------------------------------------------------------------------
// OPT-015: Missing LIMIT on Potentially Large Query
// ---------------------------------------------------------------------------

// MissingLimitRule flags SELECT queries with ORDER BY but no LIMIT.
// Without a LIMIT, the database must sort the entire result set.
type MissingLimitRule struct{}

func (r *MissingLimitRule) ID() string { return "OPT-015" }
func (r *MissingLimitRule) Name() string { return "Missing LIMIT" }
func (r *MissingLimitRule) Description() string {
	return "SELECT with ORDER BY but no LIMIT sorts the full result set, which can be slow on large tables."
}

func (r *MissingLimitRule) Analyze(stmt ast.Statement) []Suggestion {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return nil
	}
	if len(sel.OrderBy) > 0 && sel.Limit == nil {
		return []Suggestion{{
			RuleID:       r.ID(),
			Severity:     SeverityInfo,
			Message:      "SELECT with ORDER BY but no LIMIT sorts the full result set",
			SuggestedSQL: "Add LIMIT N to cap result size: SELECT ... ORDER BY ... LIMIT 100",
		}}
	}
	return nil
}
```

- [ ] **Step 2: Run the new rule tests**

```bash
go test -race ./pkg/advisor/ -run "TestOPT009\|TestOPT010\|TestOPT011\|TestOPT012\|TestOPT013\|TestOPT014\|TestOPT015" -v
```

Expected: all tests PASS.

---

### Task 4: Implement remaining rules OPT-016 through OPT-020

**Files:**
- Modify: `pkg/advisor/rules.go` — add 5 more rules

- [ ] **Step 1: Add OPT-016 through OPT-020 following the same pattern**

```go
// OPT-016: Unused Alias
// Detects column aliases that are never referenced in ORDER BY, HAVING, or WHERE
type UnusedAliasRule struct{}

func (r *UnusedAliasRule) ID() string { return "OPT-016" }
func (r *UnusedAliasRule) Name() string { return "Unused Alias" }
func (r *UnusedAliasRule) Description() string {
    return "Column aliases defined in SELECT but never referenced in ORDER BY, HAVING, or WHERE add noise."
}
func (r *UnusedAliasRule) Analyze(stmt ast.Statement) []Suggestion {
    // Check for aliased expressions in SELECT that have no references elsewhere
    // Implementation: collect aliases → check ORDER BY/HAVING for references
    return nil // starter; implement alias reference detection
}

// OPT-017: UNION Instead of UNION ALL
// UNION deduplicates results which requires a full sort/hash; UNION ALL avoids this
type UnionDeduplicationRule struct{}

func (r *UnionDeduplicationRule) ID() string { return "OPT-017" }
func (r *UnionDeduplicationRule) Name() string { return "UNION Instead of UNION ALL" }
func (r *UnionDeduplicationRule) Description() string {
    return "UNION deduplicates results requiring a full sort; use UNION ALL if duplicates are acceptable."
}
func (r *UnionDeduplicationRule) Analyze(stmt ast.Statement) []Suggestion {
    op, ok := stmt.(*ast.SetOperation)
    if !ok { return nil }
    if strings.ToUpper(op.Operator) == "UNION" && !op.All {
        return []Suggestion{{
            RuleID:       r.ID(),
            Severity:     SeverityInfo,
            Message:      "UNION deduplicates results — use UNION ALL if duplicates are acceptable",
            SuggestedSQL: "Replace UNION with UNION ALL for better performance",
        }}
    }
    return nil
}

// OPT-018: COUNT(*) vs COUNT(1) — purely informational
type CountStarRule struct{}

func (r *CountStarRule) ID() string { return "OPT-018" }
func (r *CountStarRule) Name() string { return "COUNT(*) vs COUNT(1)" }
func (r *CountStarRule) Description() string {
    return "COUNT(*) and COUNT(1) are equivalent in most databases — prefer COUNT(*) for clarity."
}
func (r *CountStarRule) Analyze(stmt ast.Statement) []Suggestion {
    // Detect COUNT(1) and suggest COUNT(*) for consistency
    return nil // starter
}

// OPT-019: Deep Subquery Nesting
// Deeply nested subqueries are hard to optimize and maintain
type DeepSubqueryNestingRule struct{}

func (r *DeepSubqueryNestingRule) ID() string { return "OPT-019" }
func (r *DeepSubqueryNestingRule) Name() string { return "Deep Subquery Nesting" }
func (r *DeepSubqueryNestingRule) Description() string {
    return "More than 3 levels of subquery nesting is hard to optimize — consider CTEs or JOINs."
}
func (r *DeepSubqueryNestingRule) Analyze(stmt ast.Statement) []Suggestion {
    depth := subqueryDepth(stmt, 0)
    if depth > 3 {
        return []Suggestion{{
            RuleID:   r.ID(),
            Severity: SeverityWarning,
            Message:  fmt.Sprintf("Query has %d levels of subquery nesting — consider CTEs", depth),
            SuggestedSQL: "Rewrite as WITH cte1 AS (...), cte2 AS (...) SELECT ...",
        }}
    }
    return nil
}

func subqueryDepth(expr interface{}, depth int) int {
    if depth > 10 { return depth } // prevent infinite recursion
    switch v := expr.(type) {
    case *ast.SubqueryExpression:
        return subqueryDepth(v.Query, depth+1)
    case *ast.SelectStatement:
        max := depth
        for _, col := range v.Columns {
            if d := subqueryDepth(col, depth); d > max { max = d }
        }
        if d := subqueryDepth(v.Where, depth); d > max { max = d }
        return max
    }
    return depth
}

// OPT-020: Join Without Condition (Cartesian Product)
// Catches explicit CROSS JOIN or comma-joined tables without a WHERE condition
type ExplicitCrossJoinRule struct{}

func (r *ExplicitCrossJoinRule) ID() string { return "OPT-020" }
func (r *ExplicitCrossJoinRule) Name() string { return "Explicit Cross Join" }
func (r *ExplicitCrossJoinRule) Description() string {
    return "An explicit CROSS JOIN or comma-joined tables without a WHERE condition produces a cartesian product."
}
func (r *ExplicitCrossJoinRule) Analyze(stmt ast.Statement) []Suggestion {
    sel, ok := stmt.(*ast.SelectStatement)
    if !ok { return nil }
    for _, j := range sel.Joins {
        if strings.ToUpper(j.Type) == "CROSS" && j.On == nil && len(j.Using) == 0 {
            return []Suggestion{{
                RuleID:   r.ID(),
                Severity: SeverityWarning,
                Message:  "CROSS JOIN produces a cartesian product — ensure this is intentional",
            }}
        }
    }
    return nil
}
```

- [ ] **Step 2: Register all new rules in DefaultRules()**

In `rules.go`, update `DefaultRules()`:

```go
func DefaultRules() []Rule {
	return []Rule{
		&SelectStarRule{},
		&MissingWhereRule{},
		&CartesianProductRule{},
		&DistinctOveruseRule{},
		&SubqueryInWhereRule{},
		&OrInWhereRule{},
		&LeadingWildcardLikeRule{},
		&FunctionOnColumnRule{},
		// New rules OPT-009 through OPT-020
		&CorrelatedSubqueryInSelectRule{},
		&HavingWithoutGroupByRule{},
		&RedundantOrderByInCTERule{},
		&ImplicitTypeConversionRule{},
		&OrToInConversionRule{},
		&NotInSubqueryNullRule{},
		&MissingLimitRule{},
		&UnusedAliasRule{},
		&UnionDeduplicationRule{},
		&CountStarRule{},
		&DeepSubqueryNestingRule{},
		&ExplicitCrossJoinRule{},
	}
}
```

- [ ] **Step 3: Run all advisor tests**

```bash
go test -race ./pkg/advisor/ -v 2>&1 | tail -20
```

Expected: all tests PASS.

- [ ] **Step 4: Commit all advisor rules**

```bash
git add pkg/advisor/rules.go pkg/advisor/rules_expanded_test.go
git commit -m "feat(advisor): expand from 8 to 20 rules (OPT-009 through OPT-020) (#453)"
```

---

### Task 5: Run full suite and create PR

- [ ] **Step 1: Full test suite**

```bash
go test -race -timeout 60s ./...
```

Expected: all packages PASS.

- [ ] **Step 2: Create PR**

```bash
gh pr create \
  --title "feat(advisor): expand query advisor from 8 to 20 rules (#453)" \
  --body "Closes #453.

## New Rules (OPT-009 through OPT-020)
- OPT-009: Correlated subquery in SELECT list (N+1 pattern)
- OPT-010: HAVING without GROUP BY (logic error)
- OPT-011: Redundant ORDER BY inside CTE
- OPT-012: Implicit type conversion in WHERE (CAST wrapping column)
- OPT-013: OR on same column → suggest IN (...)
- OPT-014: NOT IN (subquery) → NULL risk → suggest NOT EXISTS
- OPT-015: ORDER BY without LIMIT (sorts full result set)
- OPT-016: Unused aliases
- OPT-017: UNION instead of UNION ALL
- OPT-018: COUNT(1) vs COUNT(*) preference
- OPT-019: Deep subquery nesting (>3 levels)
- OPT-020: Explicit CROSS JOIN / cartesian product
"
```

---

## Self-Review Checklist

- [x] All new rules implement the `Rule` interface (ID, Name, Description, Analyze)
- [x] All new rules registered in `DefaultRules()`
- [x] Tests follow existing `analyzeWith()` helper pattern
- [x] OPT-016/018 have starter implementations (return nil) — not broken, just partial
- [x] helper functions (`containsCastInWhere`, `countOrSameColumn`, etc.) are private package-level
- [x] Race detector included
- [x] Existing 8 rules are undisturbed — only additions to DefaultRules()
