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
	astObj, parseErr := p.ParseFromModelTokens(tokens)
	ctx.WithAST(astObj, parseErr)
	return ctx
}

// L016: SelectStar

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
	if v[0].Rule != "L016" {
		t.Errorf("expected rule L016, got %s", v[0].Rule)
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

func TestSelectStar_NilAST(t *testing.T) {
	rule := performance.NewSelectStarRule()
	ctx := linter.NewContext("", "<test>")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected no violations for nil AST, got %d", len(v))
	}
}

// L017: MissingWhere

func TestMissingWhere_Violation(t *testing.T) {
	rule := performance.NewMissingWhereRule()
	ctx := makeCtx(t, "SELECT id, name FROM users")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) == 0 {
		t.Error("expected violation for SELECT without WHERE or LIMIT")
	}
	if v[0].Rule != "L017" {
		t.Errorf("expected rule L017, got %s", v[0].Rule)
	}
}

func TestMissingWhere_NoViolation_WithWhere(t *testing.T) {
	rule := performance.NewMissingWhereRule()
	ctx := makeCtx(t, "SELECT id, name FROM users WHERE active = 1")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected no violations when WHERE is present, got %d", len(v))
	}
}

func TestMissingWhere_NoViolation_WithLimit(t *testing.T) {
	rule := performance.NewMissingWhereRule()
	ctx := makeCtx(t, "SELECT id, name FROM users LIMIT 10")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected no violations when LIMIT is present, got %d", len(v))
	}
}

func TestMissingWhere_NoViolation_NoTable(t *testing.T) {
	rule := performance.NewMissingWhereRule()
	ctx := makeCtx(t, "SELECT 1 + 1")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected no violations for SELECT without table, got %d", len(v))
	}
}

// L018: LeadingWildcard

func TestLeadingWildcard_Violation(t *testing.T) {
	rule := performance.NewLeadingWildcardRule()
	ctx := makeCtx(t, "SELECT id FROM users WHERE name LIKE '%alice'")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) == 0 {
		t.Error("expected violation for leading wildcard LIKE")
	}
	if v[0].Rule != "L018" {
		t.Errorf("expected rule L018, got %s", v[0].Rule)
	}
}

func TestLeadingWildcard_NoViolation(t *testing.T) {
	rule := performance.NewLeadingWildcardRule()
	ctx := makeCtx(t, "SELECT id FROM users WHERE name LIKE 'alice%'")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected no violations for trailing wildcard, got %d", len(v))
	}
}

func TestLeadingWildcard_NoWildcard_NoViolation(t *testing.T) {
	rule := performance.NewLeadingWildcardRule()
	ctx := makeCtx(t, "SELECT id FROM users WHERE name LIKE 'alice'")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected no violations for exact LIKE match, got %d", len(v))
	}
}

func TestLeadingWildcard_NilAST(t *testing.T) {
	rule := performance.NewLeadingWildcardRule()
	ctx := linter.NewContext("", "<test>")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected no violations for nil AST, got %d", len(v))
	}
}

// L019: NotInWithNull

func TestNotInWithNull_Violation(t *testing.T) {
	rule := performance.NewNotInWithNullRule()
	ctx := makeCtx(t, "SELECT id FROM orders WHERE user_id NOT IN (SELECT id FROM users WHERE deleted = 1)")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) == 0 {
		t.Error("expected violation for NOT IN (subquery)")
	}
	if v[0].Rule != "L019" {
		t.Errorf("expected rule L019, got %s", v[0].Rule)
	}
}

func TestNotInWithNull_NoViolation_InList(t *testing.T) {
	rule := performance.NewNotInWithNullRule()
	ctx := makeCtx(t, "SELECT id FROM users WHERE status NOT IN (1, 2, 3)")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected no violations for NOT IN with literal list, got %d", len(v))
	}
}

func TestNotInWithNull_NoViolation_In(t *testing.T) {
	rule := performance.NewNotInWithNullRule()
	ctx := makeCtx(t, "SELECT id FROM orders WHERE user_id IN (SELECT id FROM users)")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected no violations for IN (not NOT IN), got %d", len(v))
	}
}

// L020: SubqueryInSelect

func TestSubqueryInSelect_Violation(t *testing.T) {
	rule := performance.NewSubqueryInSelectRule()
	ctx := makeCtx(t, "SELECT id, (SELECT name FROM departments WHERE id = users.dept_id) AS dept_name FROM users")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) == 0 {
		t.Error("expected violation for subquery in SELECT list")
	}
	if v[0].Rule != "L020" {
		t.Errorf("expected rule L020, got %s", v[0].Rule)
	}
}

func TestSubqueryInSelect_NoViolation(t *testing.T) {
	rule := performance.NewSubqueryInSelectRule()
	ctx := makeCtx(t, "SELECT id, name FROM users")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected no violations for simple SELECT, got %d", len(v))
	}
}

// L021: OrInsteadOfIn

func TestOrInsteadOfIn_Violation(t *testing.T) {
	rule := performance.NewOrInsteadOfInRule()
	ctx := makeCtx(t, "SELECT id FROM users WHERE status = 1 OR status = 2 OR status = 3")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) == 0 {
		t.Error("expected violation for multiple OR conditions on same column")
	}
	if v[0].Rule != "L021" {
		t.Errorf("expected rule L021, got %s", v[0].Rule)
	}
}

func TestOrInsteadOfIn_NoViolation_TwoOr(t *testing.T) {
	rule := performance.NewOrInsteadOfInRule()
	ctx := makeCtx(t, "SELECT id FROM users WHERE status = 1 OR status = 2")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected no violations for only two OR conditions, got %d", len(v))
	}
}

func TestOrInsteadOfIn_NoViolation_DifferentColumns(t *testing.T) {
	rule := performance.NewOrInsteadOfInRule()
	ctx := makeCtx(t, "SELECT id FROM users WHERE status = 1 OR role = 2 OR active = 3")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected no violations for OR on different columns, got %d", len(v))
	}
}

// L022: FunctionOnColumn

func TestFunctionOnColumn_Violation(t *testing.T) {
	rule := performance.NewFunctionOnColumnRule()
	ctx := makeCtx(t, "SELECT id FROM orders WHERE YEAR(created_at) = 2024")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) == 0 {
		t.Error("expected violation for function on indexed column")
	}
	if v[0].Rule != "L022" {
		t.Errorf("expected rule L022, got %s", v[0].Rule)
	}
}

func TestFunctionOnColumn_NoViolation(t *testing.T) {
	rule := performance.NewFunctionOnColumnRule()
	ctx := makeCtx(t, "SELECT id FROM orders WHERE created_at >= '2024-01-01'")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected no violations for range condition, got %d", len(v))
	}
}

func TestFunctionOnColumn_NilAST(t *testing.T) {
	rule := performance.NewFunctionOnColumnRule()
	ctx := linter.NewContext("", "<test>")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected no violations for nil AST, got %d", len(v))
	}
}

// L023: ImplicitCrossJoin

func TestImplicitCrossJoin_Violation(t *testing.T) {
	rule := performance.NewImplicitCrossJoinRule()
	ctx := makeCtx(t, "SELECT u.id, o.id FROM users u, orders o")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) == 0 {
		t.Error("expected violation for implicit cross join")
	}
	if v[0].Rule != "L023" {
		t.Errorf("expected rule L023, got %s", v[0].Rule)
	}
}

func TestImplicitCrossJoin_NoViolation_ExplicitJoin(t *testing.T) {
	rule := performance.NewImplicitCrossJoinRule()
	ctx := makeCtx(t, "SELECT u.id, o.id FROM users u JOIN orders o ON u.id = o.user_id")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected no violations for explicit JOIN, got %d", len(v))
	}
}

func TestImplicitCrossJoin_NoViolation_SingleTable(t *testing.T) {
	rule := performance.NewImplicitCrossJoinRule()
	ctx := makeCtx(t, "SELECT id FROM users WHERE active = 1")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected no violations for single table query, got %d", len(v))
	}
}

func TestImplicitCrossJoin_NilAST(t *testing.T) {
	rule := performance.NewImplicitCrossJoinRule()
	ctx := linter.NewContext("", "<test>")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected no violations for nil AST, got %d", len(v))
	}
}

// Nested-traversal tests (C5: ast.Walk migration)
//
// These tests verify that rules fire on nested SELECT/subquery/CTE bodies,
// not just top-level statements. Top-level-only traversal would miss all
// of these cases.

// L016: SELECT * in a subquery (derived table) must be flagged.
func TestSelectStar_Nested_DerivedTable(t *testing.T) {
	rule := performance.NewSelectStarRule()
	ctx := makeCtx(t, "SELECT id FROM (SELECT * FROM users) t")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) == 0 {
		t.Error("expected violation for SELECT * inside a derived table subquery")
	}
}

// L016: SELECT * inside a CTE body must be flagged.
func TestSelectStar_Nested_CTE(t *testing.T) {
	rule := performance.NewSelectStarRule()
	ctx := makeCtx(t, "WITH c AS (SELECT * FROM big_table) SELECT id FROM c")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) == 0 {
		t.Error("expected violation for SELECT * inside a CTE body")
	}
}

// L017: Missing WHERE inside a derived table must be flagged.
func TestMissingWhere_Nested_DerivedTable(t *testing.T) {
	rule := performance.NewMissingWhereRule()
	ctx := makeCtx(t, "SELECT id FROM (SELECT id, name FROM users) t WHERE id = 1")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	// The outer SELECT has a WHERE; the inner one doesn't — migration exposes this.
	if len(v) == 0 {
		t.Error("expected violation for nested SELECT without WHERE/LIMIT")
	}
}

// L018: Leading wildcard LIKE inside a CTE body must be flagged.
func TestLeadingWildcard_Nested_CTE(t *testing.T) {
	rule := performance.NewLeadingWildcardRule()
	ctx := makeCtx(t, "WITH c AS (SELECT id FROM users WHERE name LIKE '%alice') SELECT * FROM c")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) == 0 {
		t.Error("expected violation for leading wildcard LIKE inside a CTE body")
	}
}

// L019: NOT IN (subquery) inside a nested SELECT must be flagged.
func TestNotInWithNull_Nested(t *testing.T) {
	rule := performance.NewNotInWithNullRule()
	ctx := makeCtx(t, "SELECT id FROM (SELECT id FROM orders WHERE user_id NOT IN (SELECT id FROM users)) t")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) == 0 {
		t.Error("expected violation for NOT IN (subquery) inside a derived table")
	}
}

// L020: Subquery in SELECT list inside a derived table must be flagged.
func TestSubqueryInSelect_Nested_DerivedTable(t *testing.T) {
	rule := performance.NewSubqueryInSelectRule()
	ctx := makeCtx(t, "SELECT x FROM (SELECT id, (SELECT name FROM departments WHERE id = u.dept_id) AS dn FROM users u) x")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) == 0 {
		t.Error("expected violation for scalar subquery in inner SELECT column list")
	}
}

// L021: OR-chain on same column inside a CTE body must be flagged.
func TestOrInsteadOfIn_Nested_CTE(t *testing.T) {
	rule := performance.NewOrInsteadOfInRule()
	ctx := makeCtx(t, "WITH c AS (SELECT id FROM users WHERE status = 1 OR status = 2 OR status = 3) SELECT * FROM c")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) == 0 {
		t.Error("expected violation for OR-chain inside a CTE body")
	}
}

// L022: Function-on-column inside a nested SELECT must be flagged. The existing
// FunctionOnColumnRule already walks CTEs explicitly; this test locks that in.
func TestFunctionOnColumn_Nested_CTE(t *testing.T) {
	rule := performance.NewFunctionOnColumnRule()
	ctx := makeCtx(t, "WITH c AS (SELECT id FROM orders WHERE YEAR(created_at) = 2024) SELECT * FROM c")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) == 0 {
		t.Error("expected violation for function on indexed column inside a CTE body")
	}
}

// L023: Implicit cross join inside a subquery must be flagged.
func TestImplicitCrossJoin_Nested_Subquery(t *testing.T) {
	rule := performance.NewImplicitCrossJoinRule()
	ctx := makeCtx(t, "SELECT id FROM (SELECT u.id FROM users u, orders o) t")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) == 0 {
		t.Error("expected violation for implicit cross join inside a derived table")
	}
}

// Fix methods

func TestSelectStar_Fix(t *testing.T) {
	rule := performance.NewSelectStarRule()
	content := "SELECT * FROM users"
	result, err := rule.Fix(content, nil)
	if err != nil {
		t.Fatalf("Fix() error: %v", err)
	}
	if result != content {
		t.Errorf("Fix() should return content unchanged, got %q", result)
	}
}
