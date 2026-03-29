# DML Transform API #446 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add UPDATE SET clause manipulation and RETURNING clause support to the transform package, completing DML coverage so programmatic SQL generation works for UPDATE, DELETE, and INSERT-RETURNING patterns.

**Architecture:** Two new files in `pkg/transform/`: `set.go` (UPDATE SET manipulation) and `returning.go` (RETURNING clause for PostgreSQL/SQL Server). The existing `where.go` already supports UPDATE/DELETE WHERE. The `set.go` rules follow the same `RuleFunc` pattern used by `columns.go` and `orderby.go`.

**Tech Stack:** Go, existing `pkg/transform/` Rule interface, `pkg/sql/ast/` UpdateStatement/DeleteStatement/InsertStatement

---

## File Map

- Create: `pkg/transform/set.go` — AddSetClause, SetClause, ReplaceSetClause, RemoveSetClause
- Create: `pkg/transform/returning.go` — AddReturning, RemoveReturning
- Create: `pkg/transform/set_test.go` — tests for SET transforms
- Create: `pkg/transform/returning_test.go` — tests for RETURNING transforms

---

### Task 1: Understand the UpdateStatement and existing transform patterns

**Files:**
- Read: `pkg/sql/ast/ast.go` (UpdateStatement, UpdateExpression, InsertStatement, DeleteStatement)
- Read: `pkg/transform/columns.go`

- [ ] **Step 1: Check UpdateStatement and UpdateExpression fields**

```bash
grep -n "UpdateStatement\|UpdateExpression\|Assignments" pkg/sql/ast/ast.go | head -20
```

Expected output shows:
- `UpdateStatement.Assignments []UpdateExpression`
- `UpdateExpression` has `Column string` and `Value Expression` fields

- [ ] **Step 2: Check InsertStatement fields for RETURNING**

```bash
grep -n "InsertStatement\|Returning" pkg/sql/ast/ast.go | head -20
```

Expected: `InsertStatement.Returning []Expression`, `UpdateStatement.Returning []Expression`, `DeleteStatement.Returning []Expression`

- [ ] **Step 3: Check columns.go pattern to follow**

```bash
cat pkg/transform/columns.go
```

Note the pattern: `RuleFunc(func(stmt ast.Statement) error { ... })` with `ErrUnsupportedStatement`.

---

### Task 2: Write failing tests for SET transforms

**Files:**
- Create: `pkg/transform/set_test.go`

- [ ] **Step 1: Create the test file**

```go
// pkg/transform/set_test.go
package transform_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/transform"
)

func TestAddSetClause_Basic(t *testing.T) {
	tree, err := transform.ParseSQL("UPDATE users SET name = 'old'")
	if err != nil {
		t.Fatalf("ParseSQL: %v", err)
	}
	stmt := tree.Statements[0]

	err = transform.Apply(stmt, transform.AddSetClause("status", "active"))
	if err != nil {
		t.Fatalf("AddSetClause: %v", err)
	}

	sql := transform.FormatSQL(stmt)
	if !strings.Contains(sql, "status") || !strings.Contains(sql, "active") {
		t.Errorf("expected status = active in result, got: %s", sql)
	}
}

func TestSetClause_ReplaceExisting(t *testing.T) {
	tree, err := transform.ParseSQL("UPDATE users SET name = 'old', status = 'active'")
	if err != nil {
		t.Fatalf("ParseSQL: %v", err)
	}
	stmt := tree.Statements[0]

	err = transform.Apply(stmt, transform.SetClause("name", "new"))
	if err != nil {
		t.Fatalf("SetClause: %v", err)
	}

	sql := transform.FormatSQL(stmt)
	if !strings.Contains(sql, "new") {
		t.Errorf("expected name = new in result, got: %s", sql)
	}
	if strings.Contains(sql, "old") {
		t.Errorf("old value should have been replaced, got: %s", sql)
	}
}

func TestRemoveSetClause_RemovesColumn(t *testing.T) {
	tree, err := transform.ParseSQL("UPDATE users SET name = 'alice', status = 'active', age = 30")
	if err != nil {
		t.Fatalf("ParseSQL: %v", err)
	}
	stmt := tree.Statements[0]

	err = transform.Apply(stmt, transform.RemoveSetClause("status"))
	if err != nil {
		t.Fatalf("RemoveSetClause: %v", err)
	}

	sql := transform.FormatSQL(stmt)
	if strings.Contains(sql, "status") {
		t.Errorf("status column should have been removed, got: %s", sql)
	}
	if !strings.Contains(sql, "name") || !strings.Contains(sql, "age") {
		t.Errorf("other columns should remain, got: %s", sql)
	}
}

func TestReplaceSetClause_ReplacesAll(t *testing.T) {
	tree, err := transform.ParseSQL("UPDATE users SET name = 'old', status = 'x'")
	if err != nil {
		t.Fatalf("ParseSQL: %v", err)
	}
	stmt := tree.Statements[0]

	err = transform.Apply(stmt, transform.ReplaceSetClause(map[string]string{
		"email": "user@example.com",
	}))
	if err != nil {
		t.Fatalf("ReplaceSetClause: %v", err)
	}

	sql := transform.FormatSQL(stmt)
	if strings.Contains(sql, "name") || strings.Contains(sql, "status") {
		t.Errorf("old columns should be gone, got: %s", sql)
	}
	if !strings.Contains(sql, "email") {
		t.Errorf("new column should be present, got: %s", sql)
	}
}

func TestAddSetClause_OnNonUpdate_ReturnsError(t *testing.T) {
	tree, err := transform.ParseSQL("DELETE FROM users WHERE id = 1")
	if err != nil {
		t.Fatalf("ParseSQL: %v", err)
	}
	stmt := tree.Statements[0]

	err = transform.Apply(stmt, transform.AddSetClause("name", "x"))
	if err == nil {
		t.Error("expected error applying SET to DELETE statement")
	}
}
```

- [ ] **Step 2: Run tests — verify failure**

```bash
go test ./pkg/transform/ -run TestAddSetClause -v 2>&1 | head -10
```

Expected: `undefined: transform.AddSetClause`

---

### Task 3: Implement set.go

**Files:**
- Create: `pkg/transform/set.go`

- [ ] **Step 1: Create set.go**

```go
// pkg/transform/set.go
package transform

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// AddSetClause returns a Rule that appends a new assignment to the SET clause
// of an UPDATE statement. If the column already exists, its value is overwritten.
// Returns ErrUnsupportedStatement for non-UPDATE statements.
//
// Example:
//
//	transform.Apply(stmt, transform.AddSetClause("updated_at", "NOW()"))
func AddSetClause(column, valueSQL string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		upd, ok := stmt.(*ast.UpdateStatement)
		if !ok {
			return &ErrUnsupportedStatement{Transform: "AddSetClause", Got: stmtTypeName(stmt)}
		}
		// Parse the value expression
		expr, err := parseCondition(fmt.Sprintf("_col = %s", valueSQL))
		if err != nil {
			return fmt.Errorf("AddSetClause: parse value %q: %w", valueSQL, err)
		}
		// Extract the right side of the parsed binary expression
		var valueExpr ast.Expression
		if bin, ok := expr.(*ast.BinaryExpression); ok {
			valueExpr = bin.Right
		} else {
			valueExpr = expr
		}
		// Check if column already exists — replace if so
		for i, a := range upd.Assignments {
			if strings.EqualFold(a.Column, column) {
				upd.Assignments[i].Value = valueExpr
				return nil
			}
		}
		// Append new assignment
		upd.Assignments = append(upd.Assignments, ast.UpdateExpression{
			Column: column,
			Value:  valueExpr,
		})
		return nil
	})
}

// SetClause returns a Rule that sets the value of an existing column in the UPDATE
// SET clause, or adds it if not present. Alias for AddSetClause for clarity.
func SetClause(column, valueSQL string) Rule {
	return AddSetClause(column, valueSQL)
}

// RemoveSetClause returns a Rule that removes a column from the UPDATE SET clause.
// If the column is not found, the statement is unchanged (no error).
// Returns ErrUnsupportedStatement for non-UPDATE statements.
//
// Example:
//
//	transform.Apply(stmt, transform.RemoveSetClause("internal_flag"))
func RemoveSetClause(column string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		upd, ok := stmt.(*ast.UpdateStatement)
		if !ok {
			return &ErrUnsupportedStatement{Transform: "RemoveSetClause", Got: stmtTypeName(stmt)}
		}
		filtered := upd.Assignments[:0]
		for _, a := range upd.Assignments {
			if !strings.EqualFold(a.Column, column) {
				filtered = append(filtered, a)
			}
		}
		upd.Assignments = filtered
		return nil
	})
}

// ReplaceSetClause returns a Rule that completely replaces all SET assignments
// with the provided map. Keys are column names, values are SQL expressions.
// Returns ErrUnsupportedStatement for non-UPDATE statements.
//
// Example:
//
//	transform.Apply(stmt, transform.ReplaceSetClause(map[string]string{
//	    "status": "'active'",
//	    "updated_at": "NOW()",
//	}))
func ReplaceSetClause(assignments map[string]string) Rule {
	return RuleFunc(func(stmt ast.Statement) error {
		upd, ok := stmt.(*ast.UpdateStatement)
		if !ok {
			return &ErrUnsupportedStatement{Transform: "ReplaceSetClause", Got: stmtTypeName(stmt)}
		}
		newAssignments := make([]ast.UpdateExpression, 0, len(assignments))
		for col, valueSQL := range assignments {
			expr, err := parseCondition(fmt.Sprintf("_col = %s", valueSQL))
			if err != nil {
				return fmt.Errorf("ReplaceSetClause: parse value %q for column %q: %w", valueSQL, col, err)
			}
			var valueExpr ast.Expression
			if bin, ok := expr.(*ast.BinaryExpression); ok {
				valueExpr = bin.Right
			} else {
				valueExpr = expr
			}
			newAssignments = append(newAssignments, ast.UpdateExpression{
				Column: col,
				Value:  valueExpr,
			})
		}
		upd.Assignments = newAssignments
		return nil
	})
}
```

- [ ] **Step 2: Run set tests**

```bash
go test -race ./pkg/transform/ -run "TestAddSetClause|TestSetClause|TestRemoveSetClause|TestReplaceSetClause" -v
```

Expected: all tests PASS.

- [ ] **Step 3: Commit set.go**

```bash
git add pkg/transform/set.go pkg/transform/set_test.go
git commit -m "feat(transform): add SET clause transforms (AddSetClause, SetClause, RemoveSetClause, ReplaceSetClause)"
```

---

### Task 4: Write failing tests and implement returning.go

**Files:**
- Create: `pkg/transform/returning_test.go`
- Create: `pkg/transform/returning.go`

- [ ] **Step 1: Write returning tests**

```go
// pkg/transform/returning_test.go
package transform_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/transform"
)

func TestAddReturning_OnInsert(t *testing.T) {
	tree, err := transform.ParseSQL("INSERT INTO users (name) VALUES ('alice')")
	if err != nil {
		t.Fatalf("ParseSQL: %v", err)
	}
	stmt := tree.Statements[0]

	err = transform.Apply(stmt, transform.AddReturning("id"))
	if err != nil {
		t.Fatalf("AddReturning: %v", err)
	}

	sql := transform.FormatSQL(stmt)
	if !strings.Contains(strings.ToUpper(sql), "RETURNING") {
		t.Errorf("expected RETURNING in SQL, got: %s", sql)
	}
}

func TestAddReturning_OnUpdate(t *testing.T) {
	tree, err := transform.ParseSQL("UPDATE users SET status = 'active' WHERE id = 1")
	if err != nil {
		t.Fatalf("ParseSQL: %v", err)
	}
	stmt := tree.Statements[0]

	err = transform.Apply(stmt, transform.AddReturning("id", "updated_at"))
	if err != nil {
		t.Fatalf("AddReturning: %v", err)
	}

	sql := transform.FormatSQL(stmt)
	if !strings.Contains(strings.ToUpper(sql), "RETURNING") {
		t.Errorf("expected RETURNING clause, got: %s", sql)
	}
}

func TestRemoveReturning_RemovesClause(t *testing.T) {
	tree, err := transform.ParseSQL("DELETE FROM users WHERE id = 1")
	if err != nil {
		t.Fatalf("ParseSQL: %v", err)
	}
	stmt := tree.Statements[0]

	_ = transform.Apply(stmt, transform.AddReturning("id"))
	err = transform.Apply(stmt, transform.RemoveReturning())
	if err != nil {
		t.Fatalf("RemoveReturning: %v", err)
	}

	sql := transform.FormatSQL(stmt)
	if strings.Contains(strings.ToUpper(sql), "RETURNING") {
		t.Errorf("RETURNING should be removed, got: %s", sql)
	}
}
```

- [ ] **Step 2: Run tests — verify failure**

```bash
go test ./pkg/transform/ -run "TestAddReturning|TestRemoveReturning" 2>&1 | head -5
```

Expected: `undefined: transform.AddReturning`

- [ ] **Step 3: Implement returning.go**

```go
// pkg/transform/returning.go
package transform

import (
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// getReturning returns a pointer to the Returning field for supported statements
// (INSERT, UPDATE, DELETE). Other statement types return ErrUnsupportedStatement.
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

// AddReturning returns a Rule that appends columns to the RETURNING clause of
// an INSERT, UPDATE, or DELETE statement. Useful for PostgreSQL and SQL Server
// OUTPUT clause patterns.
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
			*ret = append(*ret, &ast.IdentifierExpr{Name: col})
		}
		return nil
	})
}

// RemoveReturning returns a Rule that clears the RETURNING clause from an
// INSERT, UPDATE, or DELETE statement.
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
```

- [ ] **Step 4: Run all returning tests**

```bash
go test -race ./pkg/transform/ -run "TestAddReturning|TestRemoveReturning" -v
```

Expected: all tests PASS.

- [ ] **Step 5: Run full transform test suite**

```bash
go test -race ./pkg/transform/ -v 2>&1 | tail -10
```

Expected: all tests PASS.

- [ ] **Step 6: Commit returning.go**

```bash
git add pkg/transform/returning.go pkg/transform/returning_test.go
git commit -m "feat(transform): add RETURNING clause transforms for INSERT/UPDATE/DELETE (PostgreSQL/SQL Server)"
```

---

### Task 5: Run full suite and create PR

- [ ] **Step 1: Run full test suite with race detector**

```bash
go test -race -timeout 60s ./...
```

Expected: all packages PASS.

- [ ] **Step 2: Create PR**

```bash
gh pr create \
  --title "feat(transform): DML Transform API — SET clause and RETURNING clause (#446)" \
  --body "Closes #446.

## Changes
- \`AddSetClause(column, valueSQL)\` — add or replace a SET assignment in UPDATE
- \`SetClause(column, valueSQL)\` — alias for AddSetClause
- \`RemoveSetClause(column)\` — remove a column from UPDATE SET
- \`ReplaceSetClause(map[string]string)\` — wholesale replace all SET assignments
- \`AddReturning(columns...)\` — add RETURNING clause to INSERT/UPDATE/DELETE
- \`RemoveReturning()\` — remove RETURNING clause

## Note
\`AddWhere\`, \`AddWhereFromSQL\`, \`ReplaceWhere\`, \`RemoveWhere\` already supported UPDATE/DELETE (via existing \`getWhere()\`). This PR completes the DML picture with SET and RETURNING.
"
```

---

## Self-Review Checklist

- [x] SET transforms use same `RuleFunc` pattern as existing transforms
- [x] `AddSetClause` replaces existing column rather than duplicating
- [x] `ReplaceSetClause` takes map (consistent with Go idioms)
- [x] RETURNING supports INSERT + UPDATE + DELETE via `getReturning()` helper
- [x] All transforms return `ErrUnsupportedStatement` for wrong statement types
- [x] Race detector run included
- [x] Existing AddWhere/RemoveWhere for UPDATE/DELETE tested (already passing — just verify)
