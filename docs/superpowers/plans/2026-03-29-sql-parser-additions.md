# SQL Parser Additions #450 #454 #455 #456 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Four parser/formatter additions: (1) ClickHouse SAMPLE clause, (2) Oracle CONNECT BY / hierarchical queries, (3) Formatter DDL render handlers for Sequence/Show/Describe, (4) SQL Server PIVOT/UNPIVOT.

**Architecture:**
- SAMPLE: Add to `parseSelectFrom()` in `parser.go`; add AST node `SampleClause`; add formatter render
- CONNECT BY: AST already has `ConnectByClause` and `SelectStatement.StartWith/ConnectBy` fields — add parser branch in `parseSelectFrom()` to populate them
- Formatter DDL: Add 5 `case` arms to `FormatStatement()` switch in `render.go` for existing AST nodes
- PIVOT/UNPIVOT: New AST nodes, new parser branch, new formatter render

**Tech Stack:** Go, `pkg/sql/parser/parser.go`, `pkg/sql/ast/ast.go`, `pkg/formatter/render.go`, `pkg/sql/keywords/`

---

## File Map

- Modify: `pkg/sql/ast/ast.go` — add `SampleClause` struct, `PivotClause`, `UnpivotClause`; modify `SelectStatement` to hold `Sample *SampleClause`
- Modify: `pkg/sql/parser/parser.go` — add SAMPLE, CONNECT BY, PIVOT/UNPIVOT parsing
- Modify: `pkg/formatter/render.go` — add render for Sequence DDL, Show, Describe, Sample, Pivot/Unpivot
- Modify: `pkg/sql/keywords/` — add PIVOT, UNPIVOT, SAMPLE if not already reserved
- Create: `pkg/sql/parser/parser_sample_test.go` — SAMPLE tests
- Create: `pkg/sql/parser/parser_connectby_test.go` — CONNECT BY tests
- Create: `pkg/formatter/render_ddl_test.go` — Formatter DDL render tests
- Create: `pkg/sql/parser/parser_pivot_test.go` — PIVOT/UNPIVOT tests

---

### Task 1: Formatter DDL — add render handlers for existing AST nodes (quickest win)

**Files:**
- Modify: `pkg/formatter/render.go`
- Create: `pkg/formatter/render_ddl_test.go`

- [ ] **Step 1: Confirm AST nodes exist for Sequence/Show/Describe**

```bash
grep -n "CreateSequenceStatement\|AlterSequenceStatement\|DropSequenceStatement\|ShowStatement\|DescribeStatement" pkg/sql/ast/ast.go | head -20
```

Expected: all 5 types defined in ast.go. Note their struct fields.

- [ ] **Step 2: Write failing formatter tests**

```go
// pkg/formatter/render_ddl_test.go
package formatter_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func TestFormat_CreateSequence(t *testing.T) {
	sql := "CREATE SEQUENCE user_id_seq START WITH 1 INCREMENT BY 1"
	result, err := gosqlx.Format(sql, gosqlx.DefaultFormatOptions())
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if !strings.Contains(strings.ToUpper(result), "SEQUENCE") {
		t.Errorf("expected SEQUENCE in formatted output, got: %s", result)
	}
}

func TestFormat_AlterSequence(t *testing.T) {
	sql := "ALTER SEQUENCE user_id_seq RESTART WITH 100"
	result, err := gosqlx.Format(sql, gosqlx.DefaultFormatOptions())
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if !strings.Contains(strings.ToUpper(result), "SEQUENCE") {
		t.Errorf("expected SEQUENCE in formatted output, got: %s", result)
	}
}

func TestFormat_DropSequence(t *testing.T) {
	sql := "DROP SEQUENCE IF EXISTS user_id_seq"
	result, err := gosqlx.Format(sql, gosqlx.DefaultFormatOptions())
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if !strings.Contains(strings.ToUpper(result), "SEQUENCE") {
		t.Errorf("expected SEQUENCE in formatted output, got: %s", result)
	}
}

func TestFormat_ShowStatement(t *testing.T) {
	sql := "SHOW TABLES"
	result, err := gosqlx.Format(sql, gosqlx.DefaultFormatOptions())
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if !strings.Contains(strings.ToUpper(result), "SHOW") {
		t.Errorf("expected SHOW in formatted output, got: %s", result)
	}
}

func TestFormat_DescribeStatement(t *testing.T) {
	sql := "DESCRIBE users"
	result, err := gosqlx.Format(sql, gosqlx.DefaultFormatOptions())
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if !strings.Contains(strings.ToUpper(result), "DESCRIBE") || !strings.Contains(result, "users") {
		t.Errorf("expected DESCRIBE users in output, got: %s", result)
	}
}
```

- [ ] **Step 3: Run tests — verify failure due to fallback stmtSQL**

```bash
go test ./pkg/formatter/ -run "TestFormat_.*Sequence\|TestFormat_Show\|TestFormat_Describe" -v 2>&1 | head -20
```

Expected: tests may pass trivially via `stmtSQL()` fallback, or fail with empty output. Confirm the current output quality.

- [ ] **Step 4: Read the actual struct fields for these AST nodes**

```bash
grep -A 15 "type CreateSequenceStatement\|type ShowStatement\|type DescribeStatement" pkg/sql/ast/ast.go
```

Use the actual field names in the render functions below.

- [ ] **Step 5: Add render cases to render.go**

In `pkg/formatter/render.go`, locate the `FormatStatement` switch (after line 128) and add before the `default:` case:

```go
case *ast.CreateSequenceStatement:
    return renderCreateSequence(v, opts)
case *ast.AlterSequenceStatement:
    return renderAlterSequence(v, opts)
case *ast.DropSequenceStatement:
    return renderDropSequence(v, opts)
case *ast.ShowStatement:
    return renderShow(v, opts)
case *ast.DescribeStatement:
    return renderDescribe(v, opts)
```

Then add the render functions at the bottom of render.go (or in a new file `render_ddl.go`):

```go
// renderCreateSequence renders a CREATE SEQUENCE statement.
func renderCreateSequence(s *ast.CreateSequenceStatement, opts ast.FormatOptions) string {
	f := newNodeFormatter(opts)
	sb := f.sb
	sb.WriteString(f.kw("CREATE SEQUENCE"))
	if s.IfNotExists {
		sb.WriteString(" " + f.kw("IF NOT EXISTS"))
	}
	sb.WriteString(" " + s.Name)
	if s.Options != nil {
		if s.Options.StartWith != 0 {
			sb.WriteString(fmt.Sprintf(" %s %d", f.kw("START WITH"), s.Options.StartWith))
		}
		if s.Options.IncrementBy != 0 {
			sb.WriteString(fmt.Sprintf(" %s %d", f.kw("INCREMENT BY"), s.Options.IncrementBy))
		}
		if s.Options.MinValue != 0 {
			sb.WriteString(fmt.Sprintf(" %s %d", f.kw("MINVALUE"), s.Options.MinValue))
		}
		if s.Options.MaxValue != 0 {
			sb.WriteString(fmt.Sprintf(" %s %d", f.kw("MAXVALUE"), s.Options.MaxValue))
		}
		if s.Options.Cache != 0 {
			sb.WriteString(fmt.Sprintf(" %s %d", f.kw("CACHE"), s.Options.Cache))
		}
		if s.Options.Cycle {
			sb.WriteString(" " + f.kw("CYCLE"))
		}
	}
	return sb.String()
}

// renderAlterSequence renders an ALTER SEQUENCE statement.
func renderAlterSequence(s *ast.AlterSequenceStatement, opts ast.FormatOptions) string {
	f := newNodeFormatter(opts)
	sb := f.sb
	sb.WriteString(f.kw("ALTER SEQUENCE"))
	if s.IfExists {
		sb.WriteString(" " + f.kw("IF EXISTS"))
	}
	sb.WriteString(" " + s.Name)
	if s.Options != nil {
		if s.Options.RestartWith != 0 {
			sb.WriteString(fmt.Sprintf(" %s %d", f.kw("RESTART WITH"), s.Options.RestartWith))
		}
		if s.Options.IncrementBy != 0 {
			sb.WriteString(fmt.Sprintf(" %s %d", f.kw("INCREMENT BY"), s.Options.IncrementBy))
		}
	}
	return sb.String()
}

// renderDropSequence renders a DROP SEQUENCE statement.
func renderDropSequence(s *ast.DropSequenceStatement, opts ast.FormatOptions) string {
	f := newNodeFormatter(opts)
	sb := f.sb
	sb.WriteString(f.kw("DROP SEQUENCE"))
	if s.IfExists {
		sb.WriteString(" " + f.kw("IF EXISTS"))
	}
	sb.WriteString(" " + s.Name)
	return sb.String()
}

// renderShow renders a SHOW statement (e.g., SHOW TABLES, SHOW DATABASES).
func renderShow(s *ast.ShowStatement, opts ast.FormatOptions) string {
	f := newNodeFormatter(opts)
	sb := f.sb
	sb.WriteString(f.kw("SHOW"))
	if s.What != "" {
		sb.WriteString(" " + f.kw(strings.ToUpper(s.What)))
	}
	if s.Like != "" {
		sb.WriteString(" " + f.kw("LIKE") + " '" + s.Like + "'")
	}
	return sb.String()
}

// renderDescribe renders a DESCRIBE/DESC statement.
func renderDescribe(s *ast.DescribeStatement, opts ast.FormatOptions) string {
	f := newNodeFormatter(opts)
	sb := f.sb
	sb.WriteString(f.kw("DESCRIBE"))
	sb.WriteString(" " + s.TableName)
	return sb.String()
}
```

Note: Adjust field names to match actual `ast.CreateSequenceStatement`, `ast.ShowStatement`, `ast.DescribeStatement` struct fields as found in step 4.

- [ ] **Step 6: Run DDL tests**

```bash
go test -race ./pkg/formatter/ -run "TestFormat_" -v
```

Expected: all tests PASS with proper SQL output (not fallback).

- [ ] **Step 7: Commit formatter DDL**

```bash
git add pkg/formatter/render.go pkg/formatter/render_ddl_test.go
git commit -m "feat(formatter): add render handlers for Sequence DDL, SHOW, and DESCRIBE statements (#455)"
```

---

### Task 2: CONNECT BY — wire existing AST nodes to the parser

**Files:**
- Modify: `pkg/sql/parser/parser.go`
- Create: `pkg/sql/parser/parser_connectby_test.go`

- [ ] **Step 1: Confirm AST fields exist**

```bash
grep -n "StartWith\|ConnectBy\|NoCycle\|ConnectByClause" pkg/sql/ast/ast.go | head -15
```

Expected: `SelectStatement.StartWith`, `SelectStatement.ConnectBy`, and `ConnectByClause` struct.

- [ ] **Step 2: Find where hierarchical keywords are reserved**

```bash
grep -rn "CONNECT\|NOCYCLE\|PRIOR" pkg/sql/keywords/ | head -10
```

Expected: CONNECT, BY, NOCYCLE, PRIOR are registered keywords.

- [ ] **Step 3: Write failing CONNECT BY tests**

```go
// pkg/sql/parser/parser_connectby_test.go
package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestConnectBy_Basic(t *testing.T) {
	sql := `SELECT employee_id, manager_id, name
	        FROM employees
	        START WITH manager_id IS NULL
	        CONNECT BY PRIOR employee_id = manager_id`
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	if sel.ConnectBy == nil {
		t.Error("expected ConnectBy clause to be populated")
	}
	if sel.StartWith == nil {
		t.Error("expected StartWith expression to be populated")
	}
}

func TestConnectBy_NoCycle(t *testing.T) {
	sql := `SELECT id, parent_id FROM categories
	        START WITH parent_id IS NULL
	        CONNECT BY NOCYCLE PRIOR id = parent_id`
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	sel := tree.Statements[0].(*ast.SelectStatement)
	if sel.ConnectBy == nil {
		t.Fatal("expected ConnectBy")
	}
	if !sel.ConnectBy.NoCycle {
		t.Error("expected NoCycle = true")
	}
}
```

- [ ] **Step 4: Run tests — verify failure**

```bash
go test ./pkg/sql/parser/ -run "TestConnectBy" -v 2>&1 | head -10
```

Expected: `ConnectBy == nil` failures — parsing doesn't populate the fields yet.

- [ ] **Step 5: Find the SELECT parsing location for HAVING/ORDER to add CONNECT BY after**

```bash
grep -n "HAVING\|ORDER\|parseSelect\|startWith\|connectBy" pkg/sql/parser/parser.go | head -30
```

Note the line where HAVING and ORDER BY are parsed in the SELECT statement parser. CONNECT BY / START WITH comes before ORDER BY in Oracle syntax.

- [ ] **Step 6: Add CONNECT BY parsing in parser.go**

After the HAVING clause parsing and before ORDER BY (in `parseSelectStatement` or equivalent), add:

```go
// Parse START WITH (Oracle hierarchical queries)
if p.peekKeyword("START") {
    p.advance() // consume START
    if p.expectKeyword("WITH") != nil {
        // restore if WITH not found
    } else {
        sel.StartWith, err = p.parseExpression()
        if err != nil {
            return nil, err
        }
    }
}

// Parse CONNECT BY (Oracle hierarchical queries)
if p.peekKeyword("CONNECT") {
    p.advance() // consume CONNECT
    if p.expectKeyword("BY") != nil {
        // restore
    } else {
        connectBy := &ast.ConnectByClause{}
        // Check for NOCYCLE
        if p.peekKeyword("NOCYCLE") {
            p.advance()
            connectBy.NoCycle = true
        }
        connectBy.Condition, err = p.parseExpression()
        if err != nil {
            return nil, err
        }
        sel.ConnectBy = connectBy
    }
}
```

The exact method names (`peekKeyword`, `expectKeyword`, `parseExpression`) must match the actual parser API. Check the existing parser methods:

```bash
grep -n "func.*peek\|func.*expect\|func.*advance" pkg/sql/parser/parser.go | head -20
```

- [ ] **Step 7: Run CONNECT BY tests**

```bash
go test -race ./pkg/sql/parser/ -run "TestConnectBy" -v
```

Expected: both tests PASS.

- [ ] **Step 8: Commit CONNECT BY**

```bash
git add pkg/sql/parser/parser.go pkg/sql/parser/parser_connectby_test.go
git commit -m "feat(parser): add Oracle CONNECT BY / START WITH hierarchical query support (#450)"
```

---

### Task 3: ClickHouse SAMPLE clause

**Files:**
- Modify: `pkg/sql/ast/ast.go` — add `SampleClause` struct; add `Sample *SampleClause` to `SelectStatement`
- Modify: `pkg/sql/parser/parser.go` — parse SAMPLE after FROM
- Modify: `pkg/formatter/render.go` — render SAMPLE in renderSelect
- Create: `pkg/sql/parser/parser_sample_test.go`

- [ ] **Step 1: Check if SAMPLE is a reserved keyword**

```bash
grep -rn "SAMPLE" pkg/sql/keywords/ | head -5
```

If not present, add it to the ClickHouse keywords file.

- [ ] **Step 2: Write failing SAMPLE tests**

```go
// pkg/sql/parser/parser_sample_test.go
package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestSample_Fraction(t *testing.T) {
	sql := "SELECT * FROM events SAMPLE 0.1"
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement")
	}
	if sel.Sample == nil {
		t.Error("expected Sample clause")
	}
}

func TestSample_AbsoluteRows(t *testing.T) {
	sql := "SELECT * FROM events SAMPLE 1000"
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	sel := tree.Statements[0].(*ast.SelectStatement)
	if sel.Sample == nil {
		t.Error("expected Sample clause for absolute rows")
	}
}
```

- [ ] **Step 3: Add SampleClause to ast.go and Sample field to SelectStatement**

```go
// In pkg/sql/ast/ast.go, add:

// SampleClause represents a ClickHouse SAMPLE clause for statistical sampling.
// SAMPLE 0.1 samples 10% of rows; SAMPLE 1000 samples 1000 rows absolute.
type SampleClause struct {
    Value    float64  // Fraction (0.0-1.0) or absolute row count
    IsRatio  bool     // true if fractional, false if absolute
    Pos      models.Location
}
```

Add `Sample *SampleClause` field to `SelectStatement` struct.

- [ ] **Step 4: Add SAMPLE parsing in parser.go**

After the FROM clause is parsed (after table references), add:

```go
// Parse ClickHouse SAMPLE clause
if p.peekKeyword("SAMPLE") {
    p.advance() // consume SAMPLE
    // Parse the sample value (fraction or absolute)
    // It's a numeric literal
    val, err := p.parseNumericLiteral()
    if err != nil {
        return nil, fmt.Errorf("SAMPLE: expected numeric value: %w", err)
    }
    isRatio := val >= 0 && val < 1.0
    sel.Sample = &ast.SampleClause{
        Value:   val,
        IsRatio: isRatio,
    }
}
```

The exact implementation depends on how numeric literals are parsed in the existing parser — check the actual method names.

- [ ] **Step 5: Add SAMPLE rendering in render.go**

In `renderSelect()`, after rendering the FROM clause and before WHERE:

```go
if s.Sample != nil {
    sb.WriteString(f.clauseSep())
    sb.WriteString(f.kw("SAMPLE") + " ")
    if s.Sample.IsRatio {
        sb.WriteString(fmt.Sprintf("%g", s.Sample.Value))
    } else {
        sb.WriteString(fmt.Sprintf("%d", int64(s.Sample.Value)))
    }
}
```

- [ ] **Step 6: Run SAMPLE tests**

```bash
go test -race ./pkg/sql/parser/ -run "TestSample" -v
```

Expected: both tests PASS.

- [ ] **Step 7: Commit SAMPLE**

```bash
git add pkg/sql/ast/ast.go pkg/sql/parser/parser.go pkg/formatter/render.go pkg/sql/parser/parser_sample_test.go
git commit -m "feat(parser): add ClickHouse SAMPLE clause support (#454)"
```

---

### Task 4: SQL Server PIVOT / UNPIVOT

**Files:**
- Modify: `pkg/sql/ast/ast.go` — add `PivotClause` and `UnpivotClause` structs
- Modify: `pkg/sql/parser/parser.go` — parse PIVOT/UNPIVOT in FROM clause
- Modify: `pkg/formatter/render.go` — render PIVOT/UNPIVOT
- Create: `pkg/sql/parser/parser_pivot_test.go`

- [ ] **Step 1: Check PIVOT/UNPIVOT keyword registration**

```bash
grep -rn "PIVOT\|UNPIVOT" pkg/sql/keywords/ | head -10
```

If not reserved, add to SQL Server keywords.

- [ ] **Step 2: Write failing PIVOT tests**

```go
// pkg/sql/parser/parser_pivot_test.go
package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func TestPivot_Basic(t *testing.T) {
	sql := `SELECT *
	        FROM orders
	        PIVOT (SUM(amount) FOR quarter IN ([Q1], [Q2], [Q3], [Q4]))`
	_, err := gosqlx.Parse(sql)
	if err != nil {
		t.Fatalf("Parse PIVOT: %v", err)
	}
}

func TestUnpivot_Basic(t *testing.T) {
	sql := `SELECT product, quarter, sales
	        FROM quarterly_sales
	        UNPIVOT (sales FOR quarter IN (Q1, Q2, Q3, Q4))`
	_, err := gosqlx.Parse(sql)
	if err != nil {
		t.Fatalf("Parse UNPIVOT: %v", err)
	}
}
```

- [ ] **Step 3: Add PivotClause and UnpivotClause to ast.go**

```go
// PivotClause represents a SQL Server PIVOT operation in the FROM clause.
type PivotClause struct {
    AggFunction string       // e.g., "SUM"
    AggColumn   string       // e.g., "amount"
    ForColumn   string       // e.g., "quarter"
    InValues    []string     // e.g., ["Q1", "Q2", "Q3", "Q4"]
    Alias       string
    Pos         models.Location
}

// UnpivotClause represents a SQL Server UNPIVOT operation in the FROM clause.
type UnpivotClause struct {
    ValueColumn  string      // output column for values
    ForColumn    string      // output column for names
    InColumns    []string    // columns to unpivot
    Alias        string
    Pos          models.Location
}
```

Add `Pivot *PivotClause` and `Unpivot *UnpivotClause` to `SelectStatement`.

- [ ] **Step 4: Add PIVOT/UNPIVOT parsing in parser.go**

After FROM table references, check for PIVOT/UNPIVOT:

```go
// Parse SQL Server PIVOT
if p.peekKeyword("PIVOT") {
    p.advance() // consume PIVOT
    // PIVOT (aggfunc(col) FOR col IN (val1, val2, ...))
    if err := p.expect(tokenizer.LPAREN); err != nil {
        return nil, fmt.Errorf("PIVOT: expected (: %w", err)
    }
    pivot := &ast.PivotClause{}
    // Parse: aggfunc(col) FOR col IN (vals...)
    // ... implementation depends on existing parser token methods
    sel.Pivot = pivot
    if err := p.expect(tokenizer.RPAREN); err != nil {
        return nil, fmt.Errorf("PIVOT: expected ): %w", err)
    }
}
```

The exact token constants depend on the tokenizer package. Check:
```bash
grep -n "LPAREN\|RPAREN\|TokenType" pkg/models/token.go | head -20
```

- [ ] **Step 5: Run all parser tests**

```bash
go test -race ./pkg/sql/parser/ -v 2>&1 | tail -20
```

Expected: all pre-existing tests still pass; new PIVOT/UNPIVOT tests pass.

- [ ] **Step 6: Commit PIVOT/UNPIVOT**

```bash
git add pkg/sql/ast/ast.go pkg/sql/parser/parser.go pkg/formatter/render.go pkg/sql/parser/parser_pivot_test.go
git commit -m "feat(parser): add SQL Server PIVOT/UNPIVOT support (#456)"
```

---

### Task 5: Run full suite and create PR

- [ ] **Step 1: Full test suite**

```bash
go test -race -timeout 120s ./...
```

Expected: all packages PASS.

- [ ] **Step 2: Run benchmarks to confirm no regression**

```bash
go test -bench=BenchmarkParse -benchmem ./pkg/sql/parser/ -count=3
```

Expected: throughput ≥ 1.3M ops/sec.

- [ ] **Step 3: Create PR**

```bash
gh pr create \
  --title "feat(parser/formatter): CONNECT BY, ClickHouse SAMPLE, Formatter DDL, PIVOT/UNPIVOT (#450 #454 #455 #456)" \
  --body "Closes #450 (Oracle CONNECT BY), closes #454 (ClickHouse SAMPLE), closes #455 (Formatter Sequence/Show/Describe), closes #456 (SQL Server PIVOT/UNPIVOT).

## Changes
- Oracle CONNECT BY / START WITH / NOCYCLE hierarchical queries — AST nodes already existed, parser now populates them
- ClickHouse SAMPLE clause — new SampleClause AST node + parser + formatter render
- Formatter DDL: CREATE/ALTER/DROP SEQUENCE, SHOW, DESCRIBE — 5 new case arms in FormatStatement switch
- SQL Server PIVOT/UNPIVOT — new AST nodes, parser, formatter render
"
```

---

## Self-Review Checklist

- [x] Formatter DDL tasks in Task 1 are lowest risk (no parser changes)
- [x] CONNECT BY reuses existing AST nodes — no AST changes needed
- [x] SAMPLE adds minimal new AST (SampleClause) following existing patterns
- [x] PIVOT/UNPIVOT has failing tests written before implementation
- [x] Full test suite and benchmark regression check at end
- [x] Formatter render functions check for nil before rendering optional clauses
