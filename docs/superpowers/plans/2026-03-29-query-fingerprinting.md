# Query Fingerprinting & Normalization #444 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `Fingerprint(sql) (string, error)` and `Normalize(sql) (string, error)` APIs — closing the pg_query_go feature gap and enabling LLM/NL2SQL pipeline use cases.

**Architecture:** New `pkg/fingerprint/` package with an AST visitor that replaces all literal values with `?` placeholders. `Normalize()` returns the re-formatted SQL with `?` substitutions. `Fingerprint()` returns the SHA-256 hex hash of the normalized form. Both are exported at the `gosqlx` package level as convenience functions.

**Tech Stack:** Go, `pkg/sql/ast/visitor.go` (existing), `pkg/formatter/` (existing), `pkg/gosqlx/gosqlx.go` (existing), `crypto/sha256`

---

## File Map

- Create: `pkg/fingerprint/fingerprint.go` — core Normalize and Fingerprint logic
- Create: `pkg/fingerprint/fingerprint_test.go` — full test suite
- Modify: `pkg/gosqlx/gosqlx.go` — export Fingerprint and Normalize as package-level functions
- Modify: `pkg/gosqlx/gosqlx_test.go` — integration tests for the public API
- Modify: `pkg/linter/rule.go` → no change (wrong package; fingerprint is in gosqlx)

---

### Task 1: Understand the AST visitor pattern

**Files:**
- Read: `pkg/sql/ast/visitor.go`

- [ ] **Step 1: Read the visitor interface**

```bash
cat pkg/sql/ast/visitor.go
```

Note the `Visitor` interface, `Walk()` function, and how it traverses the AST. You need to implement a `Visitor` that intercepts `LiteralExpr` nodes and replaces their values with `?`.

Key types to understand:
- `ast.Visitor` interface with `Visit(node Node) Visitor`
- `ast.Walk(v Visitor, node Node)` function
- `ast.LiteralExpr` struct (has a `Value string` field and `IsString bool`)
- `ast.NumberLiteral` struct (also a literal)
- `ast.BoolLiteral` struct
- `ast.NullLiteral` struct
- `ast.ParameterExpr` struct (already a `?` placeholder — skip these)

- [ ] **Step 2: Read formatter entry point**

```bash
grep -n "FormatStatement\|Format(" pkg/formatter/render.go | head -20
```

Note the `FormatStatement(stmt ast.Statement) (string, error)` function signature.

- [ ] **Step 3: Read gosqlx Format function for pattern**

```bash
grep -n "^func Format" pkg/gosqlx/gosqlx.go
```

Note how gosqlx.Format wraps the formatter. The fingerprint package will follow the same Parse → transform → Format pattern.

---

### Task 2: Write failing tests for the fingerprint package

**Files:**
- Create: `pkg/fingerprint/fingerprint_test.go`

- [ ] **Step 1: Write the test file**

```go
// pkg/fingerprint/fingerprint_test.go
package fingerprint_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/fingerprint"
)

func TestNormalize_ReplacesStringLiterals(t *testing.T) {
	sql := "SELECT * FROM users WHERE name = 'alice'"
	got, err := fingerprint.Normalize(sql)
	if err != nil {
		t.Fatalf("Normalize() error: %v", err)
	}
	if strings.Contains(got, "'alice'") {
		t.Errorf("Normalize() did not replace string literal; got: %s", got)
	}
	if !strings.Contains(got, "?") {
		t.Errorf("Normalize() missing ? placeholder; got: %s", got)
	}
}

func TestNormalize_ReplacesNumericLiterals(t *testing.T) {
	sql := "SELECT * FROM orders WHERE amount > 100 AND status = 1"
	got, err := fingerprint.Normalize(sql)
	if err != nil {
		t.Fatalf("Normalize() error: %v", err)
	}
	if strings.Contains(got, "100") || strings.Contains(got, " 1") {
		t.Errorf("Normalize() did not replace numeric literals; got: %s", got)
	}
}

func TestNormalize_IdenticalQueries_SameResult(t *testing.T) {
	q1 := "SELECT * FROM users WHERE id = 1"
	q2 := "SELECT * FROM users WHERE id = 999"
	n1, err := fingerprint.Normalize(q1)
	if err != nil {
		t.Fatalf("Normalize(q1) error: %v", err)
	}
	n2, err := fingerprint.Normalize(q2)
	if err != nil {
		t.Fatalf("Normalize(q2) error: %v", err)
	}
	if n1 != n2 {
		t.Errorf("structurally identical queries should normalize to same string:\n  q1 → %s\n  q2 → %s", n1, n2)
	}
}

func TestNormalize_PreservesParameterPlaceholders(t *testing.T) {
	sql := "SELECT * FROM users WHERE id = $1"
	got, err := fingerprint.Normalize(sql)
	if err != nil {
		t.Fatalf("Normalize() error: %v", err)
	}
	if !strings.Contains(got, "$1") {
		t.Errorf("Normalize() must preserve existing placeholders; got: %s", got)
	}
}

func TestNormalize_InListLiterals(t *testing.T) {
	sql := "SELECT * FROM users WHERE id IN (1, 2, 3)"
	got, err := fingerprint.Normalize(sql)
	if err != nil {
		t.Fatalf("Normalize() error: %v", err)
	}
	if strings.Contains(got, "1") || strings.Contains(got, "2") || strings.Contains(got, "3") {
		t.Errorf("Normalize() did not replace IN list literals; got: %s", got)
	}
}

func TestFingerprint_SameStructure_SameHash(t *testing.T) {
	q1 := "SELECT * FROM users WHERE id = 1"
	q2 := "SELECT * FROM users WHERE id = 42"
	fp1, err := fingerprint.Fingerprint(q1)
	if err != nil {
		t.Fatalf("Fingerprint(q1) error: %v", err)
	}
	fp2, err := fingerprint.Fingerprint(q2)
	if err != nil {
		t.Fatalf("Fingerprint(q2) error: %v", err)
	}
	if fp1 != fp2 {
		t.Errorf("same structure different literals must yield same fingerprint:\n  fp1=%s\n  fp2=%s", fp1, fp2)
	}
}

func TestFingerprint_DifferentStructure_DifferentHash(t *testing.T) {
	q1 := "SELECT id FROM users WHERE status = 1"
	q2 := "SELECT name FROM users WHERE status = 1"
	fp1, _ := fingerprint.Fingerprint(q1)
	fp2, _ := fingerprint.Fingerprint(q2)
	if fp1 == fp2 {
		t.Errorf("different query structures must yield different fingerprints")
	}
}

func TestFingerprint_IsHex64Chars(t *testing.T) {
	sql := "SELECT 1"
	fp, err := fingerprint.Fingerprint(sql)
	if err != nil {
		t.Fatalf("Fingerprint() error: %v", err)
	}
	if len(fp) != 64 {
		t.Errorf("SHA-256 hex fingerprint should be 64 chars, got %d: %s", len(fp), fp)
	}
}

func TestNormalize_InvalidSQL_ReturnsError(t *testing.T) {
	_, err := fingerprint.Normalize("SELECT FROM WHERE")
	if err == nil {
		t.Error("Normalize() should return error for invalid SQL")
	}
}

func TestFingerprint_Deterministic(t *testing.T) {
	sql := "SELECT u.id, u.name FROM users u WHERE u.created_at > '2024-01-01' AND u.active = true"
	fp1, _ := fingerprint.Fingerprint(sql)
	fp2, _ := fingerprint.Fingerprint(sql)
	if fp1 != fp2 {
		t.Error("Fingerprint() must be deterministic for the same input")
	}
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
go test ./pkg/fingerprint/ -v 2>&1 | head -20
```

Expected: `cannot find package "github.com/ajitpratap0/GoSQLX/pkg/fingerprint"`

---

### Task 3: Implement the fingerprint package

**Files:**
- Create: `pkg/fingerprint/fingerprint.go`

- [ ] **Step 1: Create the implementation**

```go
// pkg/fingerprint/fingerprint.go
package fingerprint

import (
	"crypto/sha256"
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// literalNormalizer is an AST visitor that replaces all literal values with "?".
// It modifies the AST in-place; callers must not reuse the AST after normalization.
type literalNormalizer struct{}

// Visit implements ast.Visitor. It replaces literal nodes by mutating them.
func (n *literalNormalizer) Visit(node ast.Node) ast.Visitor {
	if node == nil {
		return nil
	}
	switch v := node.(type) {
	case *ast.LiteralExpr:
		v.Value = "?"
		v.IsString = false
	case *ast.NumberLiteral:
		v.Value = "?"
	case *ast.BoolLiteral:
		// normalize true/false → ?
		v.Value = false
		v.IsPlaceholder = true
	case *ast.NullLiteral:
		// NULL is already a literal — normalize to ?
		v.IsPlaceholder = true
	}
	return n
}

// Normalize parses the SQL, replaces all literal values (strings, numbers,
// booleans, NULLs) with "?" placeholders, and returns the re-formatted SQL.
//
// Two queries that are structurally identical but use different literal values
// (e.g., WHERE id = 1 vs WHERE id = 42) will produce the same normalized output.
// Existing parameter placeholders ($1, ?, :name) are preserved unchanged.
//
// Returns an error if the SQL cannot be parsed.
//
// Example:
//
//	n, err := fingerprint.Normalize("SELECT * FROM users WHERE id = 42 AND name = 'alice'")
//	// n == "SELECT * FROM users WHERE id = ? AND name = ?"
func Normalize(sql string) (string, error) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return "", fmt.Errorf("fingerprint: tokenization failed: %w", err)
	}

	p := parser.GetParser()
	defer parser.PutParser(p)

	astObj, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		return "", fmt.Errorf("fingerprint: parsing failed: %w", err)
	}
	defer ast.ReleaseAST(astObj)

	// Walk the AST and replace all literals with ?
	v := &literalNormalizer{}
	for _, stmt := range astObj.Statements {
		ast.Walk(v, stmt)
	}

	// Format the mutated AST back to SQL
	var parts []string
	for _, stmt := range astObj.Statements {
		formatted, err := formatter.FormatStatement(stmt)
		if err != nil {
			return "", fmt.Errorf("fingerprint: formatting failed: %w", err)
		}
		parts = append(parts, formatted)
	}

	result := ""
	for i, p := range parts {
		if i > 0 {
			result += "; "
		}
		result += p
	}
	return result, nil
}

// Fingerprint parses the SQL, normalizes all literals to "?", and returns the
// SHA-256 hex digest of the normalized form. Two structurally identical queries
// with different literal values will produce the same fingerprint.
//
// The fingerprint is stable across GoSQLX versions as long as the formatter
// output for a given AST structure does not change.
//
// Returns a 64-character lowercase hex string, or an error if SQL is invalid.
//
// Example:
//
//	fp, err := fingerprint.Fingerprint("SELECT * FROM users WHERE id = 42")
//	// fp == "a3f1..." (64-char SHA-256 hex)
//	fp2, _ := fingerprint.Fingerprint("SELECT * FROM users WHERE id = 999")
//	// fp == fp2 (same structure, different literal)
func Fingerprint(sql string) (string, error) {
	normalized, err := Normalize(sql)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(normalized))
	return fmt.Sprintf("%x", h), nil
}
```

- [ ] **Step 2: Run tests — verify they pass**

```bash
go test ./pkg/fingerprint/ -v -race
```

Expected: all tests PASS with no race conditions. If `ast.BoolLiteral` or `ast.NullLiteral` don't have `IsPlaceholder` fields, adjust the visitor to use a wrapper approach (see Step 3).

- [ ] **Step 3: If AST literal types differ from above, check actual type definitions**

```bash
grep -n "BoolLiteral\|NullLiteral\|NumberLiteral\|LiteralExpr" pkg/sql/ast/ast.go | head -30
```

Adjust the `literalNormalizer.Visit()` method to match the actual struct fields.

For `BoolLiteral`, if there's no `IsPlaceholder` field, use an approach like setting `Value = "?"` or wrapping with a `ParameterExpr`. If `BoolLiteral` is not visitable, skip it — `true`/`false` are safe to include in fingerprints as-is.

- [ ] **Step 4: Run with race detector**

```bash
go test -race ./pkg/fingerprint/ -count=3
```

Expected: PASS with no DATA RACE warnings.

- [ ] **Step 5: Commit the fingerprint package**

```bash
git add pkg/fingerprint/
git commit -m "feat(fingerprint): add Normalize and Fingerprint functions for query canonicalization"
```

---

### Task 4: Export at the gosqlx package level

**Files:**
- Modify: `pkg/gosqlx/gosqlx.go`

- [ ] **Step 1: Add imports and exported wrappers**

At the end of `pkg/gosqlx/gosqlx.go`, add:

```go
// Normalize parses sql, replaces all literal values (strings, numbers, booleans,
// NULLs) with "?" placeholders, and returns the re-formatted SQL.
//
// Two queries that differ only in literal values (e.g., WHERE id = 1 vs WHERE id = 42)
// produce identical output. Existing parameter placeholders ($1, ?, :name) are preserved.
//
// Returns an error if the SQL cannot be parsed.
//
// Example:
//
//	norm, err := gosqlx.Normalize("SELECT * FROM users WHERE id = 42")
//	// norm == "SELECT * FROM users WHERE id = ?"
func Normalize(sql string) (string, error) {
	return fingerprint.Normalize(sql)
}

// Fingerprint returns a stable 64-character SHA-256 hex digest for the given SQL.
// Structurally identical queries with different literal values produce the same fingerprint,
// making this suitable for query deduplication, caching, and performance monitoring.
//
// Example:
//
//	fp1, _ := gosqlx.Fingerprint("SELECT * FROM users WHERE id = 1")
//	fp2, _ := gosqlx.Fingerprint("SELECT * FROM users WHERE id = 999")
//	// fp1 == fp2
func Fingerprint(sql string) (string, error) {
	return fingerprint.Fingerprint(sql)
}
```

Also add the import in the `import` block:

```go
"github.com/ajitpratap0/GoSQLX/pkg/fingerprint"
```

- [ ] **Step 2: Verify the package builds**

```bash
go build ./pkg/gosqlx/
```

Expected: no errors.

- [ ] **Step 3: Write integration tests in gosqlx_test.go**

Add to `pkg/gosqlx/gosqlx_test.go`:

```go
func TestGosqlx_Normalize(t *testing.T) {
	sql := "SELECT * FROM users WHERE id = 42 AND name = 'bob'"
	got, err := gosqlx.Normalize(sql)
	if err != nil {
		t.Fatalf("Normalize() error: %v", err)
	}
	if strings.Contains(got, "42") || strings.Contains(got, "'bob'") {
		t.Errorf("Normalize() did not replace literals; got: %s", got)
	}
}

func TestGosqlx_Fingerprint_CrossVersion(t *testing.T) {
	fp, err := gosqlx.Fingerprint("SELECT 1")
	if err != nil {
		t.Fatalf("Fingerprint() error: %v", err)
	}
	if len(fp) != 64 {
		t.Errorf("expected 64-char hex fingerprint, got %d chars", len(fp))
	}
}
```

- [ ] **Step 4: Run all tests**

```bash
go test -race ./pkg/gosqlx/ -v -run "TestGosqlx_Normalize|TestGosqlx_Fingerprint"
```

Expected: both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/gosqlx/gosqlx.go pkg/gosqlx/gosqlx_test.go
git commit -m "feat(gosqlx): export Normalize and Fingerprint at package level (#444)"
```

---

### Task 5: Run full test suite and create PR

- [ ] **Step 1: Full test with race detector**

```bash
go test -race -timeout 60s ./...
```

Expected: all packages PASS, no DATA RACE warnings.

- [ ] **Step 2: Run benchmarks to confirm no regression**

```bash
go test -bench=BenchmarkParse -benchmem ./pkg/gosqlx/ -count=3
```

Expected: throughput ≥ 1.3M ops/sec (regression threshold).

- [ ] **Step 3: Create PR**

```bash
gh pr create \
  --title "feat: Query Fingerprinting & Normalization API (#444)" \
  --body "Closes #444.

## Changes
- New \`pkg/fingerprint/\` package: \`Normalize(sql)\` and \`Fingerprint(sql)\`
- \`Normalize\` replaces all literals with \`?\` via AST visitor, returns re-formatted SQL
- \`Fingerprint\` returns SHA-256 hex digest of normalized form
- Both exported at \`gosqlx\` package level for convenience

## Use Case
\`\`\`go
// Deduplicate slow query logs
fp, _ := gosqlx.Fingerprint(query)
slowQueryMap[fp]++
\`\`\`
"
```

---

## Self-Review Checklist

- [x] Visitor pattern follows existing `ast.Walk` convention
- [x] Pool management: GetTokenizer/PutTokenizer, GetParser/PutParser, ReleaseAST
- [x] Existing `$1`/`?`/`:name` placeholders preserved
- [x] Race detector run included
- [x] Both gosqlx-level exports tested
- [x] Benchmark regression check included
- [x] Invalid SQL returns error (not panic)
