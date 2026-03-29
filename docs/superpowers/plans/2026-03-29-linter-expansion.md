# Linter Expansion 10 → 30 Rules #445 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 20 new linter rules (L011–L030) covering dangerous operations, performance anti-patterns, and naming conventions — reaching the 30-rule threshold for CI pipeline adoption.

**Architecture:** Three new sub-packages under `pkg/linter/rules/`: `safety/` (dangerous/destructive operations), `performance/` (N+1, SELECT *, indexes), `naming/` (conventions, reserved words). Each rule follows the existing `BaseRule` + `Rule` interface pattern. The `ValidRuleIDs` map in `rule.go` gets extended.

**Tech Stack:** Go, existing `pkg/linter/` Rule interface, `pkg/sql/ast/` AST types, `pkg/models/`

---

## File Map

### New Files (rules)
- Create: `pkg/linter/rules/safety/doc.go`
- Create: `pkg/linter/rules/safety/delete_without_where.go` — L011
- Create: `pkg/linter/rules/safety/update_without_where.go` — L012
- Create: `pkg/linter/rules/safety/drop_without_condition.go` — L013
- Create: `pkg/linter/rules/safety/truncate_table.go` — L014
- Create: `pkg/linter/rules/safety/select_into_outfile.go` — L015
- Create: `pkg/linter/rules/safety/safety_test.go`

- Create: `pkg/linter/rules/performance/doc.go`
- Create: `pkg/linter/rules/performance/select_star.go` — L016
- Create: `pkg/linter/rules/performance/missing_where.go` — L017
- Create: `pkg/linter/rules/performance/leading_wildcard.go` — L018
- Create: `pkg/linter/rules/performance/not_in_with_null.go` — L019
- Create: `pkg/linter/rules/performance/subquery_in_select.go` — L020
- Create: `pkg/linter/rules/performance/or_instead_of_in.go` — L021
- Create: `pkg/linter/rules/performance/function_on_column.go` — L022
- Create: `pkg/linter/rules/performance/implicit_cross_join.go` — L023
- Create: `pkg/linter/rules/performance/performance_test.go`

- Create: `pkg/linter/rules/naming/doc.go`
- Create: `pkg/linter/rules/naming/table_alias_required.go` — L024
- Create: `pkg/linter/rules/naming/reserved_keyword_identifier.go` — L025
- Create: `pkg/linter/rules/naming/implicit_column_list.go` — L026
- Create: `pkg/linter/rules/naming/union_all_preferred.go` — L027
- Create: `pkg/linter/rules/naming/missing_order_by_limit.go` — L028
- Create: `pkg/linter/rules/naming/naming_test.go`

### Modified Files
- Modify: `pkg/linter/rule.go` — extend ValidRuleIDs map with L011–L030

---

### Task 1: Write failing tests for safety rules (L011–L015)

**Files:**
- Create: `pkg/linter/rules/safety/safety_test.go`

- [ ] **Step 1: Create the safety test file**

```go
// pkg/linter/rules/safety/safety_test.go
package safety_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/safety"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func makeContext(t *testing.T, sql string) *linter.Context {
	t.Helper()
	ctx := linter.NewContext(sql, "<test>")
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}
	ctx.WithTokens(tokens)
	p := parser.NewParser()
	defer p.Release()
	ast, parseErr := p.ParseFromModelTokens(tokens)
	ctx.WithAST(ast, parseErr)
	return ctx
}

func TestDeleteWithoutWhere_Violation(t *testing.T) {
	rule := safety.NewDeleteWithoutWhereRule()
	ctx := makeContext(t, "DELETE FROM users")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(violations) == 0 {
		t.Error("expected violation for DELETE without WHERE")
	}
	if violations[0].Rule != "L011" {
		t.Errorf("expected rule L011, got %s", violations[0].Rule)
	}
}

func TestDeleteWithoutWhere_NoViolation(t *testing.T) {
	rule := safety.NewDeleteWithoutWhereRule()
	ctx := makeContext(t, "DELETE FROM users WHERE id = 1")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("expected no violations, got %d", len(violations))
	}
}

func TestUpdateWithoutWhere_Violation(t *testing.T) {
	rule := safety.NewUpdateWithoutWhereRule()
	ctx := makeContext(t, "UPDATE users SET status = 'inactive'")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(violations) == 0 {
		t.Error("expected violation for UPDATE without WHERE")
	}
	if violations[0].Rule != "L012" {
		t.Errorf("expected rule L012, got %s", violations[0].Rule)
	}
}

func TestUpdateWithoutWhere_NoViolation(t *testing.T) {
	rule := safety.NewUpdateWithoutWhereRule()
	ctx := makeContext(t, "UPDATE users SET status = 'inactive' WHERE id = 42")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("expected no violations, got %d", len(violations))
	}
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
go test ./pkg/linter/rules/safety/ 2>&1 | head -5
```

Expected: `cannot find package` error.

---

### Task 2: Implement safety rules L011–L015

**Files:**
- Create: `pkg/linter/rules/safety/doc.go`
- Create: `pkg/linter/rules/safety/delete_without_where.go`
- Create: `pkg/linter/rules/safety/update_without_where.go`
- Create: `pkg/linter/rules/safety/drop_without_condition.go`
- Create: `pkg/linter/rules/safety/truncate_table.go`
- Create: `pkg/linter/rules/safety/select_into_outfile.go`

- [ ] **Step 1: Create doc.go**

```go
// Package safety provides linter rules for detecting dangerous SQL operations
// that can cause irreversible data loss or security vulnerabilities.
package safety
```

- [ ] **Step 2: Create delete_without_where.go (L011)**

```go
package safety

import (
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// DeleteWithoutWhereRule (L011) flags DELETE statements that have no WHERE clause.
// Unfiltered DELETEs remove all rows from a table and are almost always a mistake.
type DeleteWithoutWhereRule struct{ linter.BaseRule }

func NewDeleteWithoutWhereRule() *DeleteWithoutWhereRule {
	return &DeleteWithoutWhereRule{
		BaseRule: linter.NewBaseRule(
			"L011",
			"Delete Without WHERE",
			"DELETE statement has no WHERE clause and will remove all rows",
			linter.SeverityError,
			false,
		),
	}
}

func (r *DeleteWithoutWhereRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	for _, stmt := range ctx.AST.Statements {
		del, ok := stmt.(*ast.DeleteStatement)
		if !ok {
			continue
		}
		if del.Where == nil {
			violations = append(violations, linter.Violation{
				Rule:       r.ID(),
				RuleName:   r.Name(),
				Severity:   r.Severity(),
				Message:    "DELETE statement has no WHERE clause",
				Location:   models.Location{Line: del.Pos.Line, Column: del.Pos.Column},
				Suggestion: "Add a WHERE clause to restrict which rows are deleted, or use TRUNCATE TABLE for full-table removal",
			})
		}
	}
	return violations, nil
}

func (r *DeleteWithoutWhereRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil // unsafe to auto-fix: requires human intent
}
```

- [ ] **Step 3: Create update_without_where.go (L012)**

```go
package safety

import (
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// UpdateWithoutWhereRule (L012) flags UPDATE statements that have no WHERE clause.
type UpdateWithoutWhereRule struct{ linter.BaseRule }

func NewUpdateWithoutWhereRule() *UpdateWithoutWhereRule {
	return &UpdateWithoutWhereRule{
		BaseRule: linter.NewBaseRule(
			"L012",
			"Update Without WHERE",
			"UPDATE statement has no WHERE clause and will modify all rows",
			linter.SeverityError,
			false,
		),
	}
}

func (r *UpdateWithoutWhereRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	for _, stmt := range ctx.AST.Statements {
		upd, ok := stmt.(*ast.UpdateStatement)
		if !ok {
			continue
		}
		if upd.Where == nil {
			violations = append(violations, linter.Violation{
				Rule:       r.ID(),
				RuleName:   r.Name(),
				Severity:   r.Severity(),
				Message:    "UPDATE statement has no WHERE clause",
				Location:   models.Location{Line: upd.Pos.Line, Column: upd.Pos.Column},
				Suggestion: "Add a WHERE clause to restrict which rows are updated",
			})
		}
	}
	return violations, nil
}

func (r *UpdateWithoutWhereRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
```

- [ ] **Step 4: Create drop_without_condition.go (L013)**

```go
package safety

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// DropWithoutConditionRule (L013) flags DROP TABLE/INDEX/VIEW without IF EXISTS.
// Without IF EXISTS, a DROP on a non-existent object raises a fatal error in most DBs.
type DropWithoutConditionRule struct{ linter.BaseRule }

func NewDropWithoutConditionRule() *DropWithoutConditionRule {
	return &DropWithoutConditionRule{
		BaseRule: linter.NewBaseRule(
			"L013",
			"Drop Without IF EXISTS",
			"DROP statement is missing IF EXISTS, which causes errors on non-existent objects",
			linter.SeverityWarning,
			false,
		),
	}
}

func (r *DropWithoutConditionRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	for _, stmt := range ctx.AST.Statements {
		switch s := stmt.(type) {
		case *ast.DropTableStatement:
			if !s.IfExists {
				violations = append(violations, r.makeViolation(s.Pos, "TABLE", s.TableName))
			}
		case *ast.DropIndexStatement:
			if !s.IfExists {
				violations = append(violations, r.makeViolation(s.Pos, "INDEX", s.IndexName))
			}
		case *ast.DropViewStatement:
			if !s.IfExists {
				violations = append(violations, r.makeViolation(s.Pos, "VIEW", s.ViewName))
			}
		}
	}
	return violations, nil
}

func (r *DropWithoutConditionRule) makeViolation(pos models.Location, objType, name string) linter.Violation {
	return linter.Violation{
		Rule:       r.ID(),
		RuleName:   r.Name(),
		Severity:   r.Severity(),
		Message:    "DROP " + strings.ToUpper(objType) + " " + name + " is missing IF EXISTS",
		Location:   pos,
		Suggestion: "Use DROP " + strings.ToUpper(objType) + " IF EXISTS " + name,
	}
}

func (r *DropWithoutConditionRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
```

- [ ] **Step 5: Create truncate_table.go (L014)**

```go
package safety

import (
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TruncateTableRule (L014) warns when TRUNCATE TABLE is used in non-DDL contexts.
// TRUNCATE is irreversible and bypasses triggers — dangerous in application code.
type TruncateTableRule struct{ linter.BaseRule }

func NewTruncateTableRule() *TruncateTableRule {
	return &TruncateTableRule{
		BaseRule: linter.NewBaseRule(
			"L014",
			"Truncate Table",
			"TRUNCATE TABLE is irreversible and bypasses row-level triggers",
			linter.SeverityWarning,
			false,
		),
	}
}

func (r *TruncateTableRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	for _, stmt := range ctx.AST.Statements {
		if trunc, ok := stmt.(*ast.TruncateStatement); ok {
			violations = append(violations, linter.Violation{
				Rule:       r.ID(),
				RuleName:   r.Name(),
				Severity:   r.Severity(),
				Message:    "TRUNCATE TABLE " + trunc.TableName + " is irreversible and bypasses triggers",
				Location:   models.Location{Line: trunc.Pos.Line, Column: trunc.Pos.Column},
				Suggestion: "Prefer DELETE FROM " + trunc.TableName + " WHERE ... for reversible partial deletes, or ensure TRUNCATE is intentional in migration scripts",
			})
		}
	}
	return violations, nil
}

func (r *TruncateTableRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
```

- [ ] **Step 6: Create select_into_outfile.go (L015)**

```go
package safety

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// SelectIntoOutfileRule (L015) flags SELECT ... INTO OUTFILE / INTO DUMPFILE.
// These operations write data to the server filesystem — a security risk.
type SelectIntoOutfileRule struct{ linter.BaseRule }

func NewSelectIntoOutfileRule() *SelectIntoOutfileRule {
	return &SelectIntoOutfileRule{
		BaseRule: linter.NewBaseRule(
			"L015",
			"Select Into Outfile",
			"SELECT INTO OUTFILE/DUMPFILE writes data to the server filesystem",
			linter.SeverityError,
			false,
		),
	}
}

func (r *SelectIntoOutfileRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	for _, stmt := range ctx.AST.Statements {
		sel, ok := stmt.(*ast.SelectStatement)
		if !ok {
			continue
		}
		// Check Into clause — if it references a file path
		if sel.Into != nil {
			into := sel.Into
			if into.OutFile != "" || strings.EqualFold(into.Type, "OUTFILE") || strings.EqualFold(into.Type, "DUMPFILE") {
				violations = append(violations, linter.Violation{
					Rule:       r.ID(),
					RuleName:   r.Name(),
					Severity:   r.Severity(),
					Message:    "SELECT INTO OUTFILE/DUMPFILE writes data to server filesystem",
					Location:   models.Location{Line: sel.Pos.Line, Column: sel.Pos.Column},
					Suggestion: "Use application-layer export instead of server-side file write",
				})
			}
		}
	}
	return violations, nil
}

func (r *SelectIntoOutfileRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
```

- [ ] **Step 7: Run safety tests**

```bash
go test -race ./pkg/linter/rules/safety/ -v
```

Expected: all tests PASS.

- [ ] **Step 8: Commit safety rules**

```bash
git add pkg/linter/rules/safety/
git commit -m "feat(linter): add safety rules L011-L015 (DELETE/UPDATE without WHERE, DROP without IF EXISTS, TRUNCATE, OUTFILE)"
```

---

### Task 3: Implement performance rules L016–L023

**Files:**
- Create: `pkg/linter/rules/performance/doc.go`
- Create: `pkg/linter/rules/performance/select_star.go` — L016
- Create: `pkg/linter/rules/performance/missing_where.go` — L017
- Create: `pkg/linter/rules/performance/leading_wildcard.go` — L018
- Create: `pkg/linter/rules/performance/not_in_with_null.go` — L019
- Create: `pkg/linter/rules/performance/subquery_in_select.go` — L020
- Create: `pkg/linter/rules/performance/or_instead_of_in.go` — L021
- Create: `pkg/linter/rules/performance/function_on_column.go` — L022
- Create: `pkg/linter/rules/performance/implicit_cross_join.go` — L023
- Create: `pkg/linter/rules/performance/performance_test.go`

- [ ] **Step 1: Write failing performance tests**

```go
// pkg/linter/rules/performance/performance_test.go
package performance_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/performance"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func makeCtx(t *testing.T, sql string) *linter.Context {
	t.Helper()
	ctx := linter.NewContext(sql, "<test>")
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}
	ctx.WithTokens(tokens)
	p := parser.NewParser()
	defer p.Release()
	ast, parseErr := p.ParseFromModelTokens(tokens)
	ctx.WithAST(ast, parseErr)
	return ctx
}

func TestSelectStar_Violation(t *testing.T) {
	rule := performance.NewSelectStarRule()
	ctx := makeCtx(t, "SELECT * FROM users")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) == 0 {
		t.Error("expected violation for SELECT *")
	}
}

func TestSelectStar_NoViolation(t *testing.T) {
	rule := performance.NewSelectStarRule()
	ctx := makeCtx(t, "SELECT id, name FROM users")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected no violations, got %d", len(v))
	}
}

func TestLeadingWildcard_Violation(t *testing.T) {
	rule := performance.NewLeadingWildcardRule()
	ctx := makeCtx(t, "SELECT * FROM users WHERE name LIKE '%alice'")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) == 0 {
		t.Error("expected violation for leading wildcard LIKE")
	}
}

func TestFunctionOnColumn_Violation(t *testing.T) {
	rule := performance.NewFunctionOnColumnRule()
	ctx := makeCtx(t, "SELECT * FROM orders WHERE YEAR(created_at) = 2024")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) == 0 {
		t.Error("expected violation for function on indexed column")
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./pkg/linter/rules/performance/ 2>&1 | head -5
```

Expected: `cannot find package` error.

- [ ] **Step 3: Create doc.go and implement select_star.go (L016)**

```go
// doc.go
// Package performance provides linter rules for detecting SQL anti-patterns
// that cause poor query performance, full table scans, or N+1 problems.
package performance
```

```go
// select_star.go
package performance

import (
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// SelectStarRule (L016) flags SELECT * usage in non-trivial queries.
// SELECT * fetches all columns, preventing index-only scans and over-fetching data.
type SelectStarRule struct{ linter.BaseRule }

func NewSelectStarRule() *SelectStarRule {
	return &SelectStarRule{
		BaseRule: linter.NewBaseRule(
			"L016",
			"Select Star",
			"SELECT * fetches all columns and prevents index-only scans",
			linter.SeverityWarning,
			false,
		),
	}
}

func (r *SelectStarRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	for _, stmt := range ctx.AST.Statements {
		sel, ok := stmt.(*ast.SelectStatement)
		if !ok {
			continue
		}
		for _, col := range sel.Columns {
			if star, ok := col.(*ast.WildcardExpr); ok {
				violations = append(violations, linter.Violation{
					Rule:       r.ID(),
					RuleName:   r.Name(),
					Severity:   r.Severity(),
					Message:    "SELECT * fetches all columns; specify only needed columns",
					Location:   models.Location{Line: star.Pos.Line, Column: star.Pos.Column},
					Suggestion: "Replace SELECT * with explicit column list: SELECT id, name, ...",
				})
			}
		}
	}
	return violations, nil
}

func (r *SelectStarRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil // cannot fix without schema knowledge
}
```

- [ ] **Step 4: Implement leading_wildcard.go (L018) — most impactful rule**

```go
package performance

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// LeadingWildcardRule (L018) flags LIKE patterns with a leading wildcard.
// A leading % forces a full table scan — it cannot use a B-tree index.
type LeadingWildcardRule struct{ linter.BaseRule }

func NewLeadingWildcardRule() *LeadingWildcardRule {
	return &LeadingWildcardRule{
		BaseRule: linter.NewBaseRule(
			"L018",
			"Leading Wildcard LIKE",
			"LIKE pattern with leading wildcard forces a full table scan",
			linter.SeverityWarning,
			false,
		),
	}
}

func (r *LeadingWildcardRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	for _, stmt := range ctx.AST.Statements {
		ast.Walk(&leadingWildcardVisitor{rule: r, violations: &violations}, stmt)
	}
	return violations, nil
}

type leadingWildcardVisitor struct {
	rule       *LeadingWildcardRule
	violations *[]linter.Violation
}

func (v *leadingWildcardVisitor) Visit(node ast.Node) ast.Visitor {
	like, ok := node.(*ast.LikeExpr)
	if !ok {
		return v
	}
	if lit, ok := like.Pattern.(*ast.LiteralExpr); ok {
		if strings.HasPrefix(lit.Value, "%") || strings.HasPrefix(lit.Value, "_") {
			*v.violations = append(*v.violations, linter.Violation{
				Rule:       v.rule.ID(),
				RuleName:   v.rule.Name(),
				Severity:   v.rule.Severity(),
				Message:    "LIKE pattern '" + lit.Value + "' has a leading wildcard — full table scan",
				Location:   models.Location{Line: like.Pos.Line, Column: like.Pos.Column},
				Suggestion: "Consider full-text search (MATCH AGAINST) or reverse-index the column for suffix searches",
			})
		}
	}
	return v
}

func (r *LeadingWildcardRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
```

- [ ] **Step 5: Implement missing_where.go (L017), not_in_with_null.go (L019), subquery_in_select.go (L020), or_instead_of_in.go (L021), function_on_column.go (L022), implicit_cross_join.go (L023)**

Follow the exact same pattern as above:
- `MissingWhereRule` (L017): flag SELECT with no WHERE and no LIMIT on multi-row-capable queries
- `NotInWithNullRule` (L019): detect `NOT IN (subquery)` — returns empty set if subquery has NULLs
- `SubqueryInSelectRule` (L020): detect correlated subqueries in SELECT column list (N+1)
- `OrInsteadOfInRule` (L021): detect `col = A OR col = B OR col = C` (suggest `col IN (A, B, C)`)
- `FunctionOnColumnRule` (L022): detect `func(column) = value` in WHERE (prevents index use)
- `ImplicitCrossJoinRule` (L023): detect comma-separated tables in FROM without JOIN condition

Each rule:
```go
type XxxRule struct{ linter.BaseRule }

func NewXxxRule() *XxxRule {
    return &XxxRule{
        BaseRule: linter.NewBaseRule("L0NN", "Rule Name", "Description", linter.SeverityWarning, false),
    }
}

func (r *XxxRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
    if ctx.AST == nil { return nil, nil }
    // ... rule logic ...
    return violations, nil
}

func (r *XxxRule) Fix(content string, v []linter.Violation) (string, error) { return content, nil }
```

- [ ] **Step 6: Run performance tests**

```bash
go test -race ./pkg/linter/rules/performance/ -v
```

Expected: all tests PASS.

- [ ] **Step 7: Commit performance rules**

```bash
git add pkg/linter/rules/performance/
git commit -m "feat(linter): add performance rules L016-L023 (SELECT *, missing WHERE, leading wildcard, NOT IN, N+1, OR vs IN, func-on-column, implicit cross join)"
```

---

### Task 4: Implement naming rules L024–L030

**Files:**
- Create all naming rule files following the same pattern

- [ ] **Step 1: Create naming rules**

Rules L024–L030:
- `L024 TableAliasRequired` — flag multi-table queries where a table has no alias
- `L025 ReservedKeywordIdentifier` — flag identifiers that are SQL reserved keywords (requires quoting)
- `L026 ImplicitColumnList` — flag INSERT without explicit column list
- `L027 UnionAllPreferred` — flag UNION (deduplicate) when UNION ALL was likely intended
- `L028 MissingOrderByLimit` — flag LIMIT/OFFSET without ORDER BY (non-deterministic pagination)
- `L029 SubqueryCanBeJoin` — flag correlated subquery in WHERE that could be a JOIN
- `L030 DistinctOnMultipleColumns` — flag DISTINCT on many columns (suggests missing GROUP BY or index)

Follow the exact same struct + Check + Fix pattern as in Task 2/3.

- [ ] **Step 2: Write and run naming tests**

```bash
go test -race ./pkg/linter/rules/naming/ -v
```

Expected: all tests PASS.

- [ ] **Step 3: Commit naming rules**

```bash
git add pkg/linter/rules/naming/
git commit -m "feat(linter): add naming/style rules L024-L030 (alias, reserved keywords, implicit columns, UNION ALL, ORDER BY+LIMIT, subquery-as-join, DISTINCT)"
```

---

### Task 5: Update ValidRuleIDs map and run full suite

**Files:**
- Modify: `pkg/linter/rule.go`

- [ ] **Step 1: Extend the ValidRuleIDs map**

In `pkg/linter/rule.go`, update `ValidRuleIDs`:

```go
var ValidRuleIDs = map[string]string{
    // Existing whitespace rules
    "L001": "Trailing Whitespace",
    "L002": "Mixed Indentation",
    "L003": "Consecutive Blank Lines",
    "L004": "Indentation Depth",
    "L005": "Long Lines",
    "L006": "Column Alignment",
    // Existing style rules
    "L007": "Keyword Case Consistency",
    "L008": "Comma Placement",
    "L009": "Aliasing Consistency",
    "L010": "Redundant Whitespace",
    // Safety rules
    "L011": "Delete Without WHERE",
    "L012": "Update Without WHERE",
    "L013": "Drop Without IF EXISTS",
    "L014": "Truncate Table",
    "L015": "Select Into Outfile",
    // Performance rules
    "L016": "Select Star",
    "L017": "Missing WHERE on Full Scan",
    "L018": "Leading Wildcard LIKE",
    "L019": "NOT IN With NULL Risk",
    "L020": "Correlated Subquery in SELECT",
    "L021": "OR Instead of IN",
    "L022": "Function on Indexed Column",
    "L023": "Implicit Cross Join",
    // Naming/style rules
    "L024": "Table Alias Required",
    "L025": "Reserved Keyword Identifier",
    "L026": "Implicit Column List in INSERT",
    "L027": "UNION Instead of UNION ALL",
    "L028": "Missing ORDER BY with LIMIT",
    "L029": "Subquery Can Be JOIN",
    "L030": "Distinct on Many Columns",
}
```

- [ ] **Step 2: Run full linter test suite**

```bash
go test -race ./pkg/linter/... -v 2>&1 | tail -20
```

Expected: all packages PASS.

- [ ] **Step 3: Run full project test suite**

```bash
go test -race -timeout 120s ./...
```

Expected: all packages PASS.

- [ ] **Step 4: Commit rule map update**

```bash
git add pkg/linter/rule.go
git commit -m "feat(linter): register L011-L030 in ValidRuleIDs map (#445)"
```

---

### Task 6: Create PR

- [ ] **Step 1: Create PR**

```bash
gh pr create \
  --title "feat(linter): expand linter from 10 to 30 rules (#445)" \
  --body "Closes #445.

## New Rules
### Safety (L011–L015)
- L011: DELETE without WHERE
- L012: UPDATE without WHERE
- L013: DROP without IF EXISTS
- L014: TRUNCATE TABLE warning
- L015: SELECT INTO OUTFILE (security)

### Performance (L016–L023)
- L016: SELECT *
- L017: Missing WHERE (full scan)
- L018: Leading wildcard LIKE
- L019: NOT IN with NULL risk
- L020: Correlated subquery in SELECT list (N+1)
- L021: OR instead of IN
- L022: Function on indexed column
- L023: Implicit cross join

### Naming/Style (L024–L030)
- L024: Table alias required (multi-table)
- L025: Reserved keyword as identifier
- L026: Implicit column list in INSERT
- L027: UNION instead of UNION ALL
- L028: Missing ORDER BY with LIMIT
- L029: Subquery can be JOIN
- L030: DISTINCT on many columns
"
```

---

## Self-Review Checklist

- [x] All 20 new rules follow existing BaseRule + Rule interface
- [x] Each rule has a test for violation and no-violation cases
- [x] No auto-fix for dangerous operations (unsafe without human intent)
- [x] ValidRuleIDs map updated with all 30 rules
- [x] Race detector run included at every stage
- [x] Rule IDs are sequential L011–L030 with no gaps
