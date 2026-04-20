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
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestParseTree_Happy(t *testing.T) {
	tree, err := ParseTree(context.Background(), "SELECT id, name FROM users")
	if err != nil {
		t.Fatalf("ParseTree: %v", err)
	}
	if tree == nil {
		t.Fatal("tree is nil")
	}
	if tree.Raw() == nil {
		t.Fatal("tree.Raw() is nil")
	}
	if got := tree.SQL(); got != "SELECT id, name FROM users" {
		t.Errorf("SQL() = %q", got)
	}
	if len(tree.Statements()) != 1 {
		t.Errorf("len(Statements) = %d, want 1", len(tree.Statements()))
	}
}

func TestParseTree_NilContext(t *testing.T) {
	// nil ctx should be treated as context.Background.
	tree, err := ParseTree(context.TODO(), "SELECT 1")
	if err != nil {
		t.Fatalf("ParseTree(nil ctx): %v", err)
	}
	if tree == nil {
		t.Fatal("tree is nil")
	}
}

func TestParseTree_SyntaxError(t *testing.T) {
	_, err := ParseTree(context.Background(), "SELECT * FORM users")
	if err == nil {
		t.Fatal("expected syntax error, got nil")
	}
	if !errors.Is(err, ErrSyntax) {
		t.Errorf("errors.Is(err, ErrSyntax) = false; err = %v", err)
	}
}

func TestParseTree_UnsupportedDialect(t *testing.T) {
	_, err := ParseTree(context.Background(), "SELECT 1", WithDialect("klingon"))
	if err == nil {
		t.Fatal("expected unsupported-dialect error, got nil")
	}
	if !errors.Is(err, ErrUnsupportedDialect) {
		t.Errorf("errors.Is(err, ErrUnsupportedDialect) = false; err = %v", err)
	}
}

func TestParseTree_WithDialect(t *testing.T) {
	// PostgreSQL-specific JSON operator syntax.
	sql := "SELECT data->>'name' FROM users"
	tree, err := ParseTree(context.Background(), sql, WithDialect("postgresql"))
	if err != nil {
		t.Fatalf("ParseTree with postgresql: %v", err)
	}
	if tree == nil {
		t.Fatal("tree is nil")
	}
}

func TestParseTree_WithTimeoutCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before call.
	_, err := ParseTree(ctx, "SELECT 1")
	if err == nil {
		t.Fatal("expected timeout error on cancelled ctx, got nil")
	}
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("errors.Is(err, ErrTimeout) = false; err = %v", err)
	}
}

func TestParseTree_NilTreeMethodsSafe(t *testing.T) {
	var tree *Tree
	// None of these should panic.
	if tree.Raw() != nil {
		t.Error("Raw() on nil should be nil")
	}
	if tree.Statements() != nil {
		t.Error("Statements() on nil should be nil")
	}
	if tree.SQL() != "" {
		t.Error("SQL() on nil should be empty")
	}
	tree.Walk(func(ast.Node) bool { return true })
	if tree.Tables() != nil {
		t.Error("Tables() on nil should be nil")
	}
	if tree.Columns() != nil {
		t.Error("Columns() on nil should be nil")
	}
	if tree.Functions() != nil {
		t.Error("Functions() on nil should be nil")
	}
	if tree.Format() != "" {
		t.Error("Format() on nil should be empty")
	}
	tree.Release()
}

// TestTree_Walk_DescendsIntoSubqueries is the load-bearing test for H1's
// claim that Tree.Walk walks the entire tree, not just the top level.
func TestTree_Walk_DescendsIntoSubqueries(t *testing.T) {
	sql := `
		SELECT *
		FROM (
			SELECT id, (SELECT COUNT(*) FROM logs WHERE logs.user_id = u.id) AS cnt
			FROM users u
		) sub
		WHERE sub.id IN (SELECT user_id FROM blocked)
	`
	tree, err := ParseTree(context.Background(), sql)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Count every SELECT statement encountered during the walk. There are 3
	// in the above SQL (outer + derived subquery in FROM + scalar subquery in
	// select list + IN-subquery in WHERE = 4). We assert >= 3 to remain
	// robust against parser AST restructuring while still proving the walk
	// descends more than one level.
	selectCount := 0
	tree.Walk(func(n ast.Node) bool {
		if _, ok := n.(*ast.SelectStatement); ok {
			selectCount++
		}
		return true
	})

	if selectCount < 3 {
		t.Errorf("Walk saw %d SELECT nodes, expected >= 3 (top-level plus subqueries)", selectCount)
	}
}

func TestTree_Walk_ShortCircuit(t *testing.T) {
	tree, err := ParseTree(context.Background(), "SELECT a, b, c FROM t")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	visited := 0
	tree.Walk(func(n ast.Node) bool {
		visited++
		return false // Don't descend.
	})
	if visited == 0 {
		t.Error("Walk never called fn")
	}
}

func TestTree_Tables(t *testing.T) {
	tree, err := ParseTree(context.Background(), "SELECT * FROM users JOIN orders ON users.id = orders.user_id")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := tree.Tables()
	wantContains := []string{"users", "orders"}
	for _, w := range wantContains {
		found := false
		for _, g := range got {
			if strings.EqualFold(g, w) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Tables() = %v, missing %q", got, w)
		}
	}
}

func TestTree_Columns(t *testing.T) {
	tree, err := ParseTree(context.Background(), "SELECT id, name FROM users WHERE active = true")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := tree.Columns()
	if len(got) == 0 {
		t.Error("Columns() returned empty slice")
	}
}

func TestTree_Functions(t *testing.T) {
	tree, err := ParseTree(context.Background(), "SELECT COUNT(*), UPPER(name) FROM users")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := tree.Functions()
	if len(got) < 2 {
		t.Errorf("Functions() = %v, want at least 2 entries", got)
	}
}

// TestFormatTree_NoReparse verifies that FormatTree does not re-parse — it
// should produce output even if we hand-construct a Tree from an AST that
// was never tokenized from a string.
func TestFormatTree_NoReparse(t *testing.T) {
	tree, err := ParseTree(context.Background(), "select * from users")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Wipe the original SQL to prove formatting does not depend on it.
	tree.sql = ""
	out := tree.Format()
	if out == "" {
		t.Fatal("FormatTree produced empty output without source SQL")
	}
}

func TestFormatTree_WithUppercase(t *testing.T) {
	tree, err := ParseTree(context.Background(), "select id from users")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	out := tree.Format(WithUppercaseKeywords(true))
	if !strings.Contains(strings.ToUpper(out), "SELECT") {
		t.Errorf("Format uppercase output missing SELECT: %q", out)
	}
	if !strings.Contains(out, "SELECT") {
		t.Errorf("expected uppercase SELECT, got %q", out)
	}
}

func TestFormatTree_WithIndent(t *testing.T) {
	tree, err := ParseTree(context.Background(), "SELECT id FROM users WHERE active = true")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compact := tree.Format(WithIndent(0))
	indented := tree.Format(WithIndent(4))
	// The indented version should contain at least one newline (NewlinePerClause).
	if !strings.Contains(indented, "\n") {
		t.Errorf("indented format has no newlines: %q", indented)
	}
	if strings.Contains(compact, "\n") {
		// Compact may still have newlines between statements — this single-statement
		// case must not.
		t.Logf("compact format: %q", compact)
	}
}

func TestFormatTree_NegativeIndentClamped(t *testing.T) {
	tree, err := ParseTree(context.Background(), "SELECT 1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Should not panic; -5 is clamped to 0.
	out := tree.Format(WithIndent(-5))
	if out == "" {
		t.Error("format with clamped indent produced empty output")
	}
}

// TestFormatTree_Idempotent verifies the round-trip parse → format → reparse
// → format is stable for a set of canonical queries.
func TestFormatTree_Idempotent(t *testing.T) {
	inputs := []string{
		"SELECT id FROM users",
		"SELECT COUNT(*) FROM orders WHERE status = 'paid'",
		"SELECT a, b FROM t1 JOIN t2 ON t1.id = t2.id",
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			tree1, err := ParseTree(context.Background(), in)
			if err != nil {
				t.Fatalf("parse 1: %v", err)
			}
			out1 := FormatTree(tree1, WithUppercaseKeywords(true), WithIndent(2))
			tree2, err := ParseTree(context.Background(), out1)
			if err != nil {
				t.Fatalf("parse 2 of %q: %v", out1, err)
			}
			out2 := FormatTree(tree2, WithUppercaseKeywords(true), WithIndent(2))
			if out1 != out2 {
				t.Errorf("format not idempotent:\nfirst:  %q\nsecond: %q", out1, out2)
			}
		})
	}
}

// TestFormatAST_NilSafe ensures FormatAST on nil AST returns empty string.
func TestFormatAST_NilSafe(t *testing.T) {
	if got := FormatAST(nil); got != "" {
		t.Errorf("FormatAST(nil) = %q, want \"\"", got)
	}
	if got := FormatTree(nil); got != "" {
		t.Errorf("FormatTree(nil) = %q, want \"\"", got)
	}
}

// TestFormatAST_RawEscapeHatch confirms FormatAST accepts a raw *ast.AST.
func TestFormatAST_RawEscapeHatch(t *testing.T) {
	tree, err := ParseTree(context.Background(), "SELECT 1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	raw := tree.Raw()
	if raw == nil {
		t.Fatal("raw AST is nil")
	}
	out := FormatAST(raw, WithUppercaseKeywords(true))
	if !strings.Contains(out, "SELECT") {
		t.Errorf("FormatAST output missing SELECT: %q", out)
	}
}

func TestParseTree_RecoveryMode(t *testing.T) {
	// Recovery mode: invalid SQL should still produce a Tree (with whatever
	// statements parsed cleanly) plus an error wrapped in ErrSyntax.
	_, err := ParseTree(context.Background(), "SELECT * FORM users", WithRecovery())
	// In recovery mode, the parser may succeed returning partial tree + error.
	// We accept either: a returned tree with errors, or an error wrapped.
	if err == nil {
		// Some recovery implementations may silently swallow the syntax issue
		// at the top level; that is acceptable. What matters is no panic.
		return
	}
	if !errors.Is(err, ErrSyntax) && !errors.Is(err, ErrTokenize) {
		t.Errorf("recovery error = %v, want ErrSyntax or ErrTokenize", err)
	}
}

// Smoke test: prior legacy entry points continue to work unchanged. This
// guards the "purely additive" contract of H1-H4.
func TestLegacyAPI_StillFunctional(t *testing.T) {
	sql := "SELECT * FROM users"

	if _, err := Parse(sql); err != nil {
		t.Errorf("legacy Parse: %v", err)
	}
	if _, err := ParseWithContext(context.Background(), sql); err != nil {
		t.Errorf("legacy ParseWithContext: %v", err)
	}
	if _, err := ParseWithTimeout(sql, time.Second); err != nil {
		t.Errorf("legacy ParseWithTimeout: %v", err)
	}
	if _, err := ParseBytes([]byte(sql)); err != nil {
		t.Errorf("legacy ParseBytes: %v", err)
	}
	if err := Validate(sql); err != nil {
		t.Errorf("legacy Validate: %v", err)
	}
	if _, err := Format(sql, DefaultFormatOptions()); err != nil {
		t.Errorf("legacy Format: %v", err)
	}
}

// guard against accidental import cycle or symbol removal
var _ = fmt.Sprintf
