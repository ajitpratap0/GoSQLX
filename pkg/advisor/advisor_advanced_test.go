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

package advisor

import (
	"fmt"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// analyzeWithRule parses sql and runs a single Rule against the first statement.
func analyzeWithRule(t *testing.T, sql string, rule Rule) []Suggestion {
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

// ---------------------------------------------------------------------------
// OPT-009: Correlated Subquery in SELECT List
// ---------------------------------------------------------------------------

func TestOPT009_CorrelatedSubqueryInSelect_Violation(t *testing.T) {
	rule := &CorrelatedSubqueryInSelectRule{}
	sug := analyzeWithRule(t,
		`SELECT id, (SELECT name FROM departments WHERE id = e.dept_id) AS dept_name FROM employees e`,
		rule)
	if len(sug) == 0 {
		t.Error("expected N+1 warning for correlated subquery in SELECT list")
	}
	if sug[0].RuleID != "OPT-009" {
		t.Errorf("expected RuleID OPT-009, got %q", sug[0].RuleID)
	}
}

func TestOPT009_CorrelatedSubqueryInSelect_NoViolation(t *testing.T) {
	rule := &CorrelatedSubqueryInSelectRule{}
	sug := analyzeWithRule(t,
		`SELECT e.id, d.name FROM employees e JOIN departments d ON e.dept_id = d.id`,
		rule)
	if len(sug) != 0 {
		t.Errorf("expected no violation for JOIN query, got %d suggestion(s)", len(sug))
	}
}

func TestOPT009_ColumnsOnly_NoViolation(t *testing.T) {
	rule := &CorrelatedSubqueryInSelectRule{}
	sug := analyzeWithRule(t, `SELECT id, name, status FROM users WHERE active = true`, rule)
	if len(sug) != 0 {
		t.Errorf("expected no violation for plain column list, got %d", len(sug))
	}
}

func TestOPT009_RuleMetadata(t *testing.T) {
	rule := &CorrelatedSubqueryInSelectRule{}
	if rule.ID() != "OPT-009" {
		t.Errorf("ID() = %q, want OPT-009", rule.ID())
	}
	if rule.Name() == "" {
		t.Error("Name() must not be empty")
	}
	if rule.Description() == "" {
		t.Error("Description() must not be empty")
	}
}

func TestOPT009_NonSelect_NoViolation(t *testing.T) {
	rule := &CorrelatedSubqueryInSelectRule{}
	tree, err := gosqlx.Parse("UPDATE users SET name = 'test' WHERE id = 1")
	if err != nil {
		t.Fatal(err)
	}
	sug := rule.Analyze(tree.Statements[0])
	if len(sug) != 0 {
		t.Errorf("expected no violation for UPDATE, got %d", len(sug))
	}
}

// ---------------------------------------------------------------------------
// OPT-010: HAVING Without GROUP BY
// ---------------------------------------------------------------------------

func TestOPT010_HavingWithoutGroupBy_Violation(t *testing.T) {
	rule := &HavingWithoutGroupByRule{}
	sug := analyzeWithRule(t, "SELECT COUNT(*) FROM users HAVING COUNT(*) > 0", rule)
	if len(sug) == 0 {
		t.Error("expected violation for HAVING without GROUP BY")
	}
	if sug[0].RuleID != "OPT-010" {
		t.Errorf("expected RuleID OPT-010, got %q", sug[0].RuleID)
	}
}

func TestOPT010_HavingWithGroupBy_NoViolation(t *testing.T) {
	rule := &HavingWithoutGroupByRule{}
	sug := analyzeWithRule(t, "SELECT dept, COUNT(*) FROM users GROUP BY dept HAVING COUNT(*) > 5", rule)
	if len(sug) != 0 {
		t.Errorf("expected no violation for HAVING with GROUP BY, got %d", len(sug))
	}
}

func TestOPT010_NoHaving_NoViolation(t *testing.T) {
	rule := &HavingWithoutGroupByRule{}
	sug := analyzeWithRule(t, "SELECT id, name FROM users WHERE active = true", rule)
	if len(sug) != 0 {
		t.Errorf("expected no violation for query without HAVING, got %d", len(sug))
	}
}

func TestOPT010_RuleMetadata(t *testing.T) {
	rule := &HavingWithoutGroupByRule{}
	if rule.ID() != "OPT-010" {
		t.Errorf("ID() = %q, want OPT-010", rule.ID())
	}
	if rule.Name() == "" || rule.Description() == "" {
		t.Error("Name() and Description() must not be empty")
	}
}

// ---------------------------------------------------------------------------
// OPT-011: Redundant ORDER BY in CTE
// ---------------------------------------------------------------------------

func TestOPT011_OrderByInCTE_Violation(t *testing.T) {
	rule := &RedundantOrderByInCTERule{}
	sug := analyzeWithRule(t, `
		WITH ranked AS (
			SELECT id, name FROM users ORDER BY name
		)
		SELECT * FROM ranked`, rule)
	if len(sug) == 0 {
		t.Error("expected warning for ORDER BY inside CTE definition")
	}
	if sug[0].RuleID != "OPT-011" {
		t.Errorf("expected RuleID OPT-011, got %q", sug[0].RuleID)
	}
}

func TestOPT011_OrderByInCTE_WithLimit_NoViolation(t *testing.T) {
	rule := &RedundantOrderByInCTERule{}
	sug := analyzeWithRule(t, `
		WITH top5 AS (
			SELECT id, name FROM users ORDER BY name LIMIT 5
		)
		SELECT * FROM top5`, rule)
	if len(sug) != 0 {
		t.Errorf("expected no violation for ORDER BY + LIMIT in CTE, got %d", len(sug))
	}
}

func TestOPT011_NoCTE_NoViolation(t *testing.T) {
	rule := &RedundantOrderByInCTERule{}
	sug := analyzeWithRule(t, "SELECT id, name FROM users ORDER BY name", rule)
	if len(sug) != 0 {
		t.Errorf("expected no violation for outer ORDER BY (not in CTE), got %d", len(sug))
	}
}

func TestOPT011_RuleMetadata(t *testing.T) {
	rule := &RedundantOrderByInCTERule{}
	if rule.ID() != "OPT-011" {
		t.Errorf("ID() = %q, want OPT-011", rule.ID())
	}
	if rule.Name() == "" || rule.Description() == "" {
		t.Error("Name() and Description() must not be empty")
	}
}

// ---------------------------------------------------------------------------
// OPT-012: Implicit Type Conversion (CAST in WHERE)
// ---------------------------------------------------------------------------

func TestOPT012_CastInWhere_Violation(t *testing.T) {
	rule := &ImplicitTypeConversionRule{}
	sug := analyzeWithRule(t, "SELECT * FROM orders WHERE CAST(user_id AS VARCHAR) = '123'", rule)
	if len(sug) == 0 {
		t.Error("expected warning for CAST in WHERE condition")
	}
	if sug[0].RuleID != "OPT-012" {
		t.Errorf("expected RuleID OPT-012, got %q", sug[0].RuleID)
	}
}

func TestOPT012_NoCastInWhere_NoViolation(t *testing.T) {
	rule := &ImplicitTypeConversionRule{}
	sug := analyzeWithRule(t, "SELECT * FROM orders WHERE user_id = 123", rule)
	if len(sug) != 0 {
		t.Errorf("expected no violation for plain WHERE comparison, got %d", len(sug))
	}
}

func TestOPT012_NoWhere_NoViolation(t *testing.T) {
	rule := &ImplicitTypeConversionRule{}
	sug := analyzeWithRule(t, "SELECT * FROM orders", rule)
	if len(sug) != 0 {
		t.Errorf("expected no violation for query without WHERE, got %d", len(sug))
	}
}

func TestOPT012_RuleMetadata(t *testing.T) {
	rule := &ImplicitTypeConversionRule{}
	if rule.ID() != "OPT-012" {
		t.Errorf("ID() = %q, want OPT-012", rule.ID())
	}
	if rule.Name() == "" || rule.Description() == "" {
		t.Error("Name() and Description() must not be empty")
	}
}

// ---------------------------------------------------------------------------
// OPT-013: OR-to-IN Conversion
// ---------------------------------------------------------------------------

func TestOPT013_OrThreeSameColumn_Violation(t *testing.T) {
	rule := &OrToInConversionRule{}
	sug := analyzeWithRule(t, "SELECT * FROM users WHERE status = 1 OR status = 2 OR status = 3", rule)
	if len(sug) == 0 {
		t.Error("expected suggestion to replace 3x OR with IN")
	}
	if sug[0].RuleID != "OPT-013" {
		t.Errorf("expected RuleID OPT-013, got %q", sug[0].RuleID)
	}
}

func TestOPT013_OrDifferentColumns_NoViolation(t *testing.T) {
	rule := &OrToInConversionRule{}
	sug := analyzeWithRule(t, "SELECT * FROM users WHERE status = 1 OR active = true", rule)
	if len(sug) != 0 {
		t.Errorf("OR on different columns should not trigger IN suggestion, got %d", len(sug))
	}
}

func TestOPT013_OnlyTwoSameColumn_NoViolation(t *testing.T) {
	rule := &OrToInConversionRule{}
	sug := analyzeWithRule(t, "SELECT * FROM users WHERE status = 1 OR status = 2", rule)
	if len(sug) != 0 {
		t.Errorf("only 2 OR conditions should not trigger (threshold is 3), got %d", len(sug))
	}
}

func TestOPT013_NoWhere_NoViolation(t *testing.T) {
	rule := &OrToInConversionRule{}
	sug := analyzeWithRule(t, "SELECT * FROM users", rule)
	if len(sug) != 0 {
		t.Errorf("expected no violation for query without WHERE, got %d", len(sug))
	}
}

func TestOPT013_RuleMetadata(t *testing.T) {
	rule := &OrToInConversionRule{}
	if rule.ID() != "OPT-013" {
		t.Errorf("ID() = %q, want OPT-013", rule.ID())
	}
	if rule.Name() == "" || rule.Description() == "" {
		t.Error("Name() and Description() must not be empty")
	}
}

// ---------------------------------------------------------------------------
// OPT-014: NOT IN Subquery NULL Risk
// ---------------------------------------------------------------------------

func TestOPT014_NotInSubquery_Violation(t *testing.T) {
	rule := &NotInSubqueryNullRule{}
	sug := analyzeWithRule(t,
		`SELECT * FROM users WHERE id NOT IN (SELECT manager_id FROM employees)`,
		rule)
	if len(sug) == 0 {
		t.Error("expected warning for NOT IN with subquery (NULL risk)")
	}
	if sug[0].RuleID != "OPT-014" {
		t.Errorf("expected RuleID OPT-014, got %q", sug[0].RuleID)
	}
}

func TestOPT014_InSubquery_NoViolation(t *testing.T) {
	rule := &NotInSubqueryNullRule{}
	sug := analyzeWithRule(t,
		`SELECT * FROM users WHERE id IN (SELECT manager_id FROM employees)`,
		rule)
	if len(sug) != 0 {
		t.Errorf("IN (not NOT IN) should not trigger, got %d", len(sug))
	}
}

func TestOPT014_NotInValueList_NoViolation(t *testing.T) {
	rule := &NotInSubqueryNullRule{}
	sug := analyzeWithRule(t,
		`SELECT * FROM users WHERE status NOT IN (1, 2, 3)`,
		rule)
	if len(sug) != 0 {
		t.Errorf("NOT IN value list (no subquery) should not trigger, got %d", len(sug))
	}
}

func TestOPT014_RuleMetadata(t *testing.T) {
	rule := &NotInSubqueryNullRule{}
	if rule.ID() != "OPT-014" {
		t.Errorf("ID() = %q, want OPT-014", rule.ID())
	}
	if rule.Name() == "" || rule.Description() == "" {
		t.Error("Name() and Description() must not be empty")
	}
}

// ---------------------------------------------------------------------------
// OPT-015: Missing LIMIT
// ---------------------------------------------------------------------------

func TestOPT015_OrderByNoLimit_Violation(t *testing.T) {
	rule := &MissingLimitRule{}
	sug := analyzeWithRule(t, "SELECT * FROM audit_log ORDER BY created_at DESC", rule)
	if len(sug) == 0 {
		t.Error("expected suggestion to add LIMIT to ORDER BY query without LIMIT")
	}
	if sug[0].RuleID != "OPT-015" {
		t.Errorf("expected RuleID OPT-015, got %q", sug[0].RuleID)
	}
}

func TestOPT015_OrderByWithLimit_NoViolation(t *testing.T) {
	rule := &MissingLimitRule{}
	sug := analyzeWithRule(t, "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 100", rule)
	if len(sug) != 0 {
		t.Errorf("expected no violation with LIMIT, got %d", len(sug))
	}
}

func TestOPT015_NoOrderBy_NoViolation(t *testing.T) {
	rule := &MissingLimitRule{}
	sug := analyzeWithRule(t, "SELECT * FROM users WHERE active = true", rule)
	if len(sug) != 0 {
		t.Errorf("expected no violation for query without ORDER BY, got %d", len(sug))
	}
}

func TestOPT015_RuleMetadata(t *testing.T) {
	rule := &MissingLimitRule{}
	if rule.ID() != "OPT-015" {
		t.Errorf("ID() = %q, want OPT-015", rule.ID())
	}
	if rule.Name() == "" || rule.Description() == "" {
		t.Error("Name() and Description() must not be empty")
	}
}

// ---------------------------------------------------------------------------
// OPT-016: Unused Alias
// ---------------------------------------------------------------------------

func TestOPT016_UnusedAlias_Violation(t *testing.T) {
	rule := &UnusedAliasRule{}
	sug := analyzeWithRule(t,
		"SELECT id, name AS full_name FROM users ORDER BY name",
		rule)
	if len(sug) == 0 {
		t.Error("expected violation for alias 'full_name' not used in ORDER BY/HAVING")
	}
	if sug[0].RuleID != "OPT-016" {
		t.Errorf("expected RuleID OPT-016, got %q", sug[0].RuleID)
	}
}

func TestOPT016_AliasUsedInOrderBy_NoViolation(t *testing.T) {
	rule := &UnusedAliasRule{}
	sug := analyzeWithRule(t,
		"SELECT id, name AS full_name FROM users ORDER BY full_name",
		rule)
	if len(sug) != 0 {
		t.Errorf("expected no violation when alias used in ORDER BY, got %d", len(sug))
	}
}

func TestOPT016_NoAlias_NoViolation(t *testing.T) {
	rule := &UnusedAliasRule{}
	sug := analyzeWithRule(t, "SELECT id, name FROM users", rule)
	if len(sug) != 0 {
		t.Errorf("expected no violation for query without aliases, got %d", len(sug))
	}
}

func TestOPT016_RuleMetadata(t *testing.T) {
	rule := &UnusedAliasRule{}
	if rule.ID() != "OPT-016" {
		t.Errorf("ID() = %q, want OPT-016", rule.ID())
	}
	if rule.Name() == "" || rule.Description() == "" {
		t.Error("Name() and Description() must not be empty")
	}
}

// ---------------------------------------------------------------------------
// OPT-017: UNION Deduplication
// ---------------------------------------------------------------------------

func TestOPT017_Union_Violation(t *testing.T) {
	rule := &UnionDeduplicationRule{}
	tree, err := gosqlx.Parse("SELECT id FROM users UNION SELECT id FROM admins")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(tree.Statements) == 0 {
		t.Fatal("no statements parsed")
	}
	sug := rule.Analyze(tree.Statements[0])
	if len(sug) == 0 {
		t.Error("expected suggestion for UNION (non-ALL) on possibly large result sets")
	}
	if sug[0].RuleID != "OPT-017" {
		t.Errorf("expected RuleID OPT-017, got %q", sug[0].RuleID)
	}
}

func TestOPT017_UnionAll_NoViolation(t *testing.T) {
	rule := &UnionDeduplicationRule{}
	tree, err := gosqlx.Parse("SELECT id FROM users UNION ALL SELECT id FROM admins")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	sug := rule.Analyze(tree.Statements[0])
	if len(sug) != 0 {
		t.Errorf("UNION ALL should not trigger, got %d", len(sug))
	}
}

func TestOPT017_SelectOnly_NoViolation(t *testing.T) {
	rule := &UnionDeduplicationRule{}
	sug := analyzeWithRule(t, "SELECT id FROM users", rule)
	if len(sug) != 0 {
		t.Errorf("plain SELECT should not trigger OPT-017, got %d", len(sug))
	}
}

func TestOPT017_RuleMetadata(t *testing.T) {
	rule := &UnionDeduplicationRule{}
	if rule.ID() != "OPT-017" {
		t.Errorf("ID() = %q, want OPT-017", rule.ID())
	}
	if rule.Name() == "" || rule.Description() == "" {
		t.Error("Name() and Description() must not be empty")
	}
}

// ---------------------------------------------------------------------------
// OPT-018: COUNT(DISTINCT col) where COUNT(*) may suffice
// ---------------------------------------------------------------------------

func TestOPT018_CountDistinct_Violation(t *testing.T) {
	rule := &CountStarRule{}
	sug := analyzeWithRule(t, "SELECT COUNT(DISTINCT user_id) FROM orders", rule)
	if len(sug) == 0 {
		t.Error("expected info suggestion for COUNT(DISTINCT col)")
	}
	if sug[0].RuleID != "OPT-018" {
		t.Errorf("expected RuleID OPT-018, got %q", sug[0].RuleID)
	}
}

func TestOPT018_CountStar_NoViolation(t *testing.T) {
	rule := &CountStarRule{}
	sug := analyzeWithRule(t, "SELECT COUNT(*) FROM orders", rule)
	if len(sug) != 0 {
		t.Errorf("COUNT(*) should not trigger OPT-018, got %d", len(sug))
	}
}

func TestOPT018_CountColumn_NoViolation(t *testing.T) {
	rule := &CountStarRule{}
	sug := analyzeWithRule(t, "SELECT COUNT(id) FROM orders", rule)
	if len(sug) != 0 {
		t.Errorf("COUNT(col) without DISTINCT should not trigger OPT-018, got %d", len(sug))
	}
}

func TestOPT018_RuleMetadata(t *testing.T) {
	rule := &CountStarRule{}
	if rule.ID() != "OPT-018" {
		t.Errorf("ID() = %q, want OPT-018", rule.ID())
	}
	if rule.Name() == "" || rule.Description() == "" {
		t.Error("Name() and Description() must not be empty")
	}
}

// ---------------------------------------------------------------------------
// OPT-019: Deep Subquery Nesting
// ---------------------------------------------------------------------------

func TestOPT019_DeepNesting_Violation(t *testing.T) {
	rule := &DeepSubqueryNestingRule{}
	sug := analyzeWithRule(t,
		`SELECT * FROM a WHERE id IN (SELECT id FROM b WHERE id IN (SELECT id FROM c WHERE id IN (SELECT id FROM d WHERE id IN (SELECT id FROM e))))`,
		rule)
	if len(sug) == 0 {
		t.Error("expected warning for deeply nested subqueries (>3 levels)")
	}
	if sug[0].RuleID != "OPT-019" {
		t.Errorf("expected RuleID OPT-019, got %q", sug[0].RuleID)
	}
}

func TestOPT019_ShallowNesting_NoViolation(t *testing.T) {
	rule := &DeepSubqueryNestingRule{}
	sug := analyzeWithRule(t,
		`SELECT * FROM a WHERE id IN (SELECT id FROM b WHERE id IN (SELECT id FROM c))`,
		rule)
	if len(sug) != 0 {
		t.Errorf("2-level nesting should not trigger (threshold >3), got %d", len(sug))
	}
}

func TestOPT019_NoSubquery_NoViolation(t *testing.T) {
	rule := &DeepSubqueryNestingRule{}
	sug := analyzeWithRule(t, "SELECT * FROM users WHERE active = true", rule)
	if len(sug) != 0 {
		t.Errorf("no subquery should not trigger OPT-019, got %d", len(sug))
	}
}

func TestOPT019_RuleMetadata(t *testing.T) {
	rule := &DeepSubqueryNestingRule{}
	if rule.ID() != "OPT-019" {
		t.Errorf("ID() = %q, want OPT-019", rule.ID())
	}
	if rule.Name() == "" || rule.Description() == "" {
		t.Error("Name() and Description() must not be empty")
	}
}

// ---------------------------------------------------------------------------
// OPT-020: Explicit Cross Join / Cartesian Product
// ---------------------------------------------------------------------------

func TestOPT020_ExplicitCrossJoin_Violation(t *testing.T) {
	rule := &ExplicitCrossJoinRule{}
	sug := analyzeWithRule(t, "SELECT * FROM a CROSS JOIN b", rule)
	if len(sug) == 0 {
		t.Error("expected warning for explicit CROSS JOIN")
	}
	if sug[0].RuleID != "OPT-020" {
		t.Errorf("expected RuleID OPT-020, got %q", sug[0].RuleID)
	}
}

func TestOPT020_InnerJoin_NoViolation(t *testing.T) {
	rule := &ExplicitCrossJoinRule{}
	sug := analyzeWithRule(t, "SELECT * FROM a JOIN b ON a.id = b.a_id", rule)
	if len(sug) != 0 {
		t.Errorf("INNER JOIN with condition should not trigger OPT-020, got %d", len(sug))
	}
}

func TestOPT020_SingleTable_NoViolation(t *testing.T) {
	rule := &ExplicitCrossJoinRule{}
	sug := analyzeWithRule(t, "SELECT * FROM users", rule)
	if len(sug) != 0 {
		t.Errorf("single table should not trigger OPT-020, got %d", len(sug))
	}
}

func TestOPT020_RuleMetadata(t *testing.T) {
	rule := &ExplicitCrossJoinRule{}
	if rule.ID() != "OPT-020" {
		t.Errorf("ID() = %q, want OPT-020", rule.ID())
	}
	if rule.Name() == "" || rule.Description() == "" {
		t.Error("Name() and Description() must not be empty")
	}
}

// ---------------------------------------------------------------------------
// Integration: DefaultRules includes all 20 rules
// ---------------------------------------------------------------------------

func TestDefaultRules_Count(t *testing.T) {
	rules := DefaultRules()
	if len(rules) != 20 {
		t.Errorf("DefaultRules() returned %d rules, want 20", len(rules))
	}
}

func TestDefaultRules_UniqueIDs(t *testing.T) {
	rules := DefaultRules()
	seen := make(map[string]bool)
	for _, r := range rules {
		if seen[r.ID()] {
			t.Errorf("duplicate rule ID: %s", r.ID())
		}
		seen[r.ID()] = true
	}
}

func TestDefaultRules_AllNewRulesPresent(t *testing.T) {
	rules := DefaultRules()
	ids := make(map[string]bool)
	for _, r := range rules {
		ids[r.ID()] = true
	}
	for i := 9; i <= 20; i++ {
		id := fmt.Sprintf("OPT-%03d", i)
		if !ids[id] {
			t.Errorf("DefaultRules() missing %s", id)
		}
	}
}

// ---------------------------------------------------------------------------
// Integration: Optimizer with advanced rules
// ---------------------------------------------------------------------------

func TestOptimizer_AdvancedRules_Score(t *testing.T) {
	opt := New()

	// A correlated subquery + ORDER BY without LIMIT should deduct points
	result, err := opt.AnalyzeSQL(
		`SELECT id, (SELECT name FROM depts WHERE id = e.dept_id) FROM employees ORDER BY id`)
	if err != nil {
		t.Fatalf("AnalyzeSQL: %v", err)
	}
	if result.Score >= 100 {
		t.Errorf("expected score < 100 for query with multiple issues, got %d", result.Score)
	}
}

func TestOptimizer_NotInSubquery_Score(t *testing.T) {
	opt := New()
	result, err := opt.AnalyzeSQL(
		`SELECT * FROM users WHERE id NOT IN (SELECT manager_id FROM employees)`)
	if err != nil {
		t.Fatalf("AnalyzeSQL: %v", err)
	}
	found := false
	for _, s := range result.Suggestions {
		if s.RuleID == "OPT-014" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected OPT-014 suggestion from full optimizer on NOT IN subquery")
	}
}

// Ensure the ast package import is used (for type assertions in future tests).
var _ ast.Statement
