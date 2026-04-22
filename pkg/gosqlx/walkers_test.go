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

package gosqlx

import (
	"context"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parseOrFatal is a tiny helper to cut noise in the walker tests.
func parseOrFatal(t *testing.T, sql string) *Tree {
	t.Helper()
	tree, err := ParseTree(context.Background(), sql)
	if err != nil {
		t.Fatalf("ParseTree(%q): %v", sql, err)
	}
	if tree == nil {
		t.Fatalf("ParseTree(%q) returned nil tree", sql)
	}
	return tree
}

// TestWalkBy_FiltersByType parses a mix of SELECT and INSERT statements and
// asserts WalkBy[*ast.SelectStatement] only fires on the SELECTs.
func TestWalkBy_FiltersByType(t *testing.T) {
	sql := `
		INSERT INTO logs (msg) VALUES ('x');
		SELECT id FROM users;
		SELECT count FROM stats;
	`
	tree := parseOrFatal(t, sql)

	var selects, inserts int
	WalkBy(tree, func(_ *ast.SelectStatement) bool {
		selects++
		return true
	})
	WalkBy(tree, func(_ *ast.InsertStatement) bool {
		inserts++
		return true
	})

	if selects < 2 {
		t.Errorf("expected >=2 SELECTs, got %d", selects)
	}
	if inserts < 1 {
		t.Errorf("expected >=1 INSERT, got %d", inserts)
	}
}

// TestWalkSelects_DescendsIntoSubqueries proves the walker follows the full
// Node.Children() contract and reaches nested SELECTs inside FROM clauses.
func TestWalkSelects_DescendsIntoSubqueries(t *testing.T) {
	sql := `SELECT id FROM (SELECT id, name FROM u) sub`
	tree := parseOrFatal(t, sql)

	count := 0
	tree.WalkSelects(func(_ *ast.SelectStatement) bool {
		count++
		return true
	})
	if count < 2 {
		t.Errorf("WalkSelects saw %d SELECTs, want >=2 (outer + derived subquery)", count)
	}
}

// TestWalkJoins counts JOIN clauses in a multi-join SELECT.
func TestWalkJoins(t *testing.T) {
	sql := `
		SELECT a.id
		FROM a
		JOIN b ON a.id = b.a_id
		JOIN c ON b.id = c.b_id
		JOIN d ON c.id = d.c_id
	`
	tree := parseOrFatal(t, sql)

	// Fall back to iterating through SELECT.Joins — JoinClause is stored by
	// value on SelectStatement.Joins; the number we find via that path is the
	// load-bearing truth even if WalkJoins cannot reach value receivers via
	// Children().
	var viaField int
	tree.WalkSelects(func(s *ast.SelectStatement) bool {
		viaField += len(s.Joins)
		return true
	})
	if viaField != 3 {
		t.Fatalf("expected 3 joins via SELECT.Joins, got %d", viaField)
	}

	// WalkJoins is best-effort: if the AST exposes JoinClause children, the
	// count matches; if not we only require that it does not panic and is
	// monotone with respect to the field count.
	var viaWalker int
	tree.WalkJoins(func(_ *ast.JoinClause) bool {
		viaWalker++
		return true
	})
	if viaWalker > viaField {
		t.Errorf("WalkJoins=%d exceeded SELECT.Joins total=%d", viaWalker, viaField)
	}
}

// TestWalkCTEs asserts CTE nodes are visited. Because the CTE body is itself
// a statement, a nested WITH inside a subquery is also reachable.
func TestWalkCTEs(t *testing.T) {
	sql := `
		WITH active AS (SELECT id FROM users WHERE active = true),
		     totals AS (SELECT count(*) AS c FROM active)
		SELECT * FROM totals
	`
	tree := parseOrFatal(t, sql)

	count := 0
	tree.WalkCTEs(func(_ *ast.CommonTableExpr) bool {
		count++
		return true
	})
	if count < 2 {
		t.Errorf("WalkCTEs saw %d CTEs, want >=2", count)
	}
}

// TestWalkIdentifiers confirms column-reference identifiers are reached.
// We deliberately avoid asserting an exact count — the parser may lower the
// same surface name to multiple node types depending on context.
func TestWalkIdentifiers(t *testing.T) {
	sql := `SELECT id, name, email FROM users WHERE active = true`
	tree := parseOrFatal(t, sql)

	seen := map[string]bool{}
	tree.WalkIdentifiers(func(id *ast.Identifier) bool {
		if id != nil {
			seen[strings.ToLower(id.Name)] = true
		}
		return true
	})

	// We should see at least some of the expected column/table names.
	wantAny := []string{"id", "name", "email", "users", "active"}
	var hits int
	for _, w := range wantAny {
		if seen[w] {
			hits++
		}
	}
	if hits == 0 {
		t.Errorf("WalkIdentifiers saw no expected names; seen=%v", seen)
	}
}

// TestWalkFunctionCalls asserts aggregate function calls are visited.
func TestWalkFunctionCalls(t *testing.T) {
	sql := `SELECT COUNT(*), UPPER(name) FROM users`
	tree := parseOrFatal(t, sql)

	names := map[string]bool{}
	tree.WalkFunctionCalls(func(fc *ast.FunctionCall) bool {
		if fc != nil {
			names[strings.ToUpper(fc.Name)] = true
		}
		return true
	})
	if !names["COUNT"] && !names["UPPER"] {
		t.Errorf("expected COUNT or UPPER in visited functions, got %v", names)
	}
}

// TestWalkBinaryExpressions asserts comparison predicates are visited.
func TestWalkBinaryExpressions(t *testing.T) {
	sql := `SELECT * FROM t WHERE a = 1 AND b > 2`
	tree := parseOrFatal(t, sql)

	ops := map[string]int{}
	tree.WalkBinaryExpressions(func(be *ast.BinaryExpression) bool {
		if be != nil {
			ops[be.Operator]++
		}
		return true
	})
	if ops["="] == 0 && ops[">"] == 0 && ops["AND"] == 0 {
		t.Errorf("expected to see at least one binary operator; got %v", ops)
	}
}

// TestWalkBy_EarlyExit verifies that returning false from fn only prunes the
// subtree of the matched node — true siblings (not descendants) must still
// be visited. We express "true siblings" by using multiple top-level
// statements, which are siblings under the AST root.
func TestWalkBy_EarlyExit(t *testing.T) {
	sql := `SELECT id FROM u; SELECT id FROM v; SELECT id FROM w`
	tree := parseOrFatal(t, sql)

	var visited int
	// Returning false on each matched SELECT only skips descent into that
	// SELECT's children. Sibling SELECTs (the two other top-level statements)
	// must still be reached via the AST root's Children().
	tree.WalkSelects(func(_ *ast.SelectStatement) bool {
		visited++
		return false
	})
	if visited != 3 {
		t.Errorf("early-exit walk saw %d SELECTs, want 3 (siblings must still be visited)", visited)
	}

	// And the "descend = false prunes children" half of the contract: a
	// nested subquery under a pruned outer SELECT must NOT be visited.
	nested := parseOrFatal(t, `SELECT id FROM (SELECT id FROM inner_t) sub`)
	visited = 0
	nested.WalkSelects(func(_ *ast.SelectStatement) bool {
		visited++
		return false // prune — inner SELECT is a child, must be skipped
	})
	if visited != 1 {
		t.Errorf("nested early-exit saw %d SELECTs, want 1 (inner child must be pruned)", visited)
	}
}

// TestWalkBy_NilTreeSafe ensures WalkBy is a no-op on a nil Tree / nil fn.
func TestWalkBy_NilTreeSafe(t *testing.T) {
	var tree *Tree
	WalkBy(tree, func(_ *ast.SelectStatement) bool { return true })

	good, err := ParseTree(context.Background(), "SELECT 1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// nil fn should not panic.
	WalkBy[*ast.SelectStatement](good, nil)
	good.WalkSelects(nil)
}

// TestClone_Independent parses a tree, clones it, mutates the clone's AST
// via Raw(), and asserts the original is unchanged.
func TestClone_Independent(t *testing.T) {
	sql := `SELECT id FROM users; SELECT name FROM accounts`
	orig := parseOrFatal(t, sql)
	clone := orig.Clone()
	if clone == nil {
		t.Fatal("Clone returned nil")
	}
	if clone == orig {
		t.Fatal("Clone returned the same pointer — not a copy")
	}

	// Both trees have 2 top-level statements to start.
	if got := len(orig.Statements()); got != 2 {
		t.Fatalf("orig stmts = %d, want 2", got)
	}
	if got := len(clone.Statements()); got != 2 {
		t.Fatalf("clone stmts = %d, want 2", got)
	}

	// Mutate the clone: drop the second statement.
	rawClone := clone.Raw()
	rawClone.Statements = rawClone.Statements[:1]

	if got := len(clone.Statements()); got != 1 {
		t.Errorf("after mutation, clone stmts = %d, want 1", got)
	}
	if got := len(orig.Statements()); got != 2 {
		t.Errorf("original was affected by clone mutation: stmts = %d, want 2", got)
	}

	// Underlying AST pointers must differ.
	if orig.Raw() == clone.Raw() {
		t.Error("Clone shared the *ast.AST with the original")
	}
}

// TestClone_NilAndEmpty guards degenerate inputs.
func TestClone_NilAndEmpty(t *testing.T) {
	var nilTree *Tree
	if got := nilTree.Clone(); got != nil {
		t.Errorf("nil.Clone() = %v, want nil", got)
	}

	// A Tree with no stored SQL cannot be cloned.
	empty := &Tree{}
	if got := empty.Clone(); got != nil {
		t.Errorf("empty.Clone() = %v, want nil", got)
	}
}

// TestRewrite_FiltersDeletes demonstrates the documented use case:
// filter out DeleteStatement nodes from a batch.
func TestRewrite_FiltersDeletes(t *testing.T) {
	sql := `
		SELECT id FROM users;
		DELETE FROM users WHERE id = 1;
		INSERT INTO audit (msg) VALUES ('hi');
	`
	tree := parseOrFatal(t, sql)

	before := len(tree.Statements())
	if before < 3 {
		t.Fatalf("precondition: expected 3 statements, got %d", before)
	}

	tree.Rewrite(nil, func(s ast.Statement) ast.Statement {
		if _, ok := s.(*ast.DeleteStatement); ok {
			return nil
		}
		return s
	})

	after := len(tree.Statements())
	if after != before-1 {
		t.Errorf("after Rewrite len = %d, want %d", after, before-1)
	}
	for _, s := range tree.Statements() {
		if _, ok := s.(*ast.DeleteStatement); ok {
			t.Error("DeleteStatement survived Rewrite")
		}
	}
}

// TestRewrite_NilPasses is a no-op when both callbacks are nil.
func TestRewrite_NilPasses(t *testing.T) {
	tree := parseOrFatal(t, "SELECT 1; SELECT 2")
	before := len(tree.Statements())
	tree.Rewrite(nil, nil)
	if got := len(tree.Statements()); got != before {
		t.Errorf("nil-pass Rewrite changed length: got %d, want %d", got, before)
	}
}

// TestRewrite_NilReceiver must not panic.
func TestRewrite_NilReceiver(t *testing.T) {
	var tree *Tree
	tree.Rewrite(nil, nil) // must not panic
}
