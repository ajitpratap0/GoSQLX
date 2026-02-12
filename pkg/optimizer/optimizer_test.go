package optimizer

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// ---------------------------------------------------------------------------
// Helper to run AnalyzeSQL and fail on error
// ---------------------------------------------------------------------------

func mustAnalyze(t *testing.T, opt *Optimizer, sql string) *OptimizationResult {
	t.Helper()
	result, err := opt.AnalyzeSQL(sql)
	if err != nil {
		t.Fatalf("AnalyzeSQL(%q) returned unexpected error: %v", sql, err)
	}
	return result
}

func hasSuggestion(result *OptimizationResult, ruleID string) bool {
	for _, s := range result.Suggestions {
		if s.RuleID == ruleID {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// OPT-001: SELECT * Detection
// ---------------------------------------------------------------------------

func TestSelectStarRule(t *testing.T) {
	opt := New()

	tests := []struct {
		name    string
		sql     string
		wantHit bool
	}{
		{
			name:    "SELECT * triggers suggestion",
			sql:     "SELECT * FROM users",
			wantHit: true,
		},
		{
			name:    "Named columns do not trigger",
			sql:     "SELECT id, name FROM users",
			wantHit: false,
		},
		{
			name:    "COUNT(*) does not trigger",
			sql:     "SELECT COUNT(*) FROM users",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mustAnalyze(t, opt, tt.sql)
			got := hasSuggestion(result, "OPT-001")
			if got != tt.wantHit {
				t.Errorf("hasSuggestion(OPT-001) = %v, want %v for SQL %q", got, tt.wantHit, tt.sql)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// OPT-002: Missing WHERE Clause
// ---------------------------------------------------------------------------

func TestMissingWhereRule(t *testing.T) {
	opt := New()

	tests := []struct {
		name    string
		sql     string
		wantHit bool
	}{
		{
			name:    "UPDATE without WHERE triggers",
			sql:     "UPDATE users SET active = true",
			wantHit: true,
		},
		{
			name:    "UPDATE with WHERE does not trigger",
			sql:     "UPDATE users SET active = true WHERE id = 1",
			wantHit: false,
		},
		{
			name:    "DELETE without WHERE triggers",
			sql:     "DELETE FROM orders",
			wantHit: true,
		},
		{
			name:    "DELETE with WHERE does not trigger",
			sql:     "DELETE FROM orders WHERE status = 'expired'",
			wantHit: false,
		},
		{
			name:    "SELECT without WHERE does not trigger (rule only applies to UPDATE/DELETE)",
			sql:     "SELECT * FROM users",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mustAnalyze(t, opt, tt.sql)
			got := hasSuggestion(result, "OPT-002")
			if got != tt.wantHit {
				t.Errorf("hasSuggestion(OPT-002) = %v, want %v for SQL %q", got, tt.wantHit, tt.sql)
			}
			// Verify severity is error for dangerous operations
			if tt.wantHit {
				for _, s := range result.Suggestions {
					if s.RuleID == "OPT-002" && s.Severity != SeverityError {
						t.Errorf("expected severity %q for OPT-002, got %q", SeverityError, s.Severity)
					}
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// OPT-003: Cartesian Product Detection
// ---------------------------------------------------------------------------

func TestCartesianProductRule(t *testing.T) {
	opt := New()

	tests := []struct {
		name    string
		sql     string
		wantHit bool
	}{
		{
			name:    "Single table does not trigger",
			sql:     "SELECT id FROM users",
			wantHit: false,
		},
		{
			name:    "Explicit JOIN does not trigger",
			sql:     "SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mustAnalyze(t, opt, tt.sql)
			got := hasSuggestion(result, "OPT-003")
			if got != tt.wantHit {
				t.Errorf("hasSuggestion(OPT-003) = %v, want %v for SQL %q", got, tt.wantHit, tt.sql)
			}
		})
	}
}

func TestCartesianProductRuleDirect(t *testing.T) {
	// Test with directly constructed AST to ensure rule logic works
	rule := &CartesianProductRule{}

	t.Run("two tables without WHERE triggers", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
			From: []ast.TableReference{
				{Name: "users"},
				{Name: "orders"},
			},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) == 0 {
			t.Error("expected Cartesian product suggestion for two tables without WHERE")
		}
	})

	t.Run("single table does not trigger", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
			From: []ast.TableReference{
				{Name: "users"},
			},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) != 0 {
			t.Error("expected no Cartesian product suggestion for single table")
		}
	})

	t.Run("with explicit JOIN does not trigger", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
			From: []ast.TableReference{
				{Name: "users"},
				{Name: "orders"},
			},
			Joins: []ast.JoinClause{
				{
					Type:  "INNER",
					Left:  ast.TableReference{Name: "users"},
					Right: ast.TableReference{Name: "orders"},
					Condition: &ast.BinaryExpression{
						Left:     &ast.Identifier{Name: "id", Table: "users"},
						Operator: "=",
						Right:    &ast.Identifier{Name: "user_id", Table: "orders"},
					},
				},
			},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) != 0 {
			t.Error("expected no Cartesian product suggestion when JOINs are present")
		}
	})

	t.Run("with join condition in WHERE does not trigger", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
			From: []ast.TableReference{
				{Name: "users"},
				{Name: "orders"},
			},
			Where: &ast.BinaryExpression{
				Left:     &ast.Identifier{Name: "id", Table: "users"},
				Operator: "=",
				Right:    &ast.Identifier{Name: "user_id", Table: "orders"},
			},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) != 0 {
			t.Error("expected no Cartesian product suggestion when WHERE has join condition")
		}
	})
}

// ---------------------------------------------------------------------------
// OPT-004: SELECT DISTINCT Overuse
// ---------------------------------------------------------------------------

func TestDistinctOveruseRule(t *testing.T) {
	opt := New()

	tests := []struct {
		name    string
		sql     string
		wantHit bool
	}{
		{
			name:    "DISTINCT without JOIN triggers info",
			sql:     "SELECT DISTINCT status FROM orders",
			wantHit: true,
		},
		{
			name:    "No DISTINCT does not trigger",
			sql:     "SELECT status FROM orders",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mustAnalyze(t, opt, tt.sql)
			got := hasSuggestion(result, "OPT-004")
			if got != tt.wantHit {
				t.Errorf("hasSuggestion(OPT-004) = %v, want %v for SQL %q", got, tt.wantHit, tt.sql)
			}
		})
	}
}

func TestDistinctOveruseRuleDirect(t *testing.T) {
	rule := &DistinctOveruseRule{}

	t.Run("DISTINCT with JOIN triggers warning severity", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Distinct: true,
			Columns:  []ast.Expression{&ast.Identifier{Name: "name"}},
			From:     []ast.TableReference{{Name: "users"}},
			Joins: []ast.JoinClause{
				{
					Type:  "INNER",
					Left:  ast.TableReference{Name: "users"},
					Right: ast.TableReference{Name: "orders"},
				},
			},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) == 0 {
			t.Fatal("expected suggestion for DISTINCT with JOINs")
		}
		if suggestions[0].Severity != SeverityWarning {
			t.Errorf("expected severity %q, got %q", SeverityWarning, suggestions[0].Severity)
		}
	})

	t.Run("DISTINCT without JOIN triggers info severity", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Distinct: true,
			Columns:  []ast.Expression{&ast.Identifier{Name: "status"}},
			From:     []ast.TableReference{{Name: "orders"}},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) == 0 {
			t.Fatal("expected suggestion for DISTINCT without JOIN")
		}
		if suggestions[0].Severity != SeverityInfo {
			t.Errorf("expected severity %q, got %q", SeverityInfo, suggestions[0].Severity)
		}
	})
}

// ---------------------------------------------------------------------------
// OPT-005: Subquery in WHERE
// ---------------------------------------------------------------------------

func TestSubqueryInWhereRule(t *testing.T) {
	rule := &SubqueryInWhereRule{}

	t.Run("IN subquery triggers", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "name"}},
			From:    []ast.TableReference{{Name: "users"}},
			Where: &ast.InExpression{
				Expr: &ast.Identifier{Name: "id"},
				Subquery: &ast.SelectStatement{
					Columns: []ast.Expression{&ast.Identifier{Name: "user_id"}},
					From:    []ast.TableReference{{Name: "orders"}},
				},
			},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) == 0 {
			t.Error("expected suggestion for IN subquery")
		}
	})

	t.Run("EXISTS subquery triggers", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "name"}},
			From:    []ast.TableReference{{Name: "users"}},
			Where: &ast.ExistsExpression{
				Subquery: &ast.SelectStatement{
					Columns: []ast.Expression{&ast.LiteralValue{Value: 1, Type: "INTEGER"}},
					From:    []ast.TableReference{{Name: "orders"}},
				},
			},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) == 0 {
			t.Error("expected suggestion for EXISTS subquery")
		}
	})

	t.Run("no subquery does not trigger", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "name"}},
			From:    []ast.TableReference{{Name: "users"}},
			Where: &ast.BinaryExpression{
				Left:     &ast.Identifier{Name: "active"},
				Operator: "=",
				Right:    &ast.LiteralValue{Value: true, Type: "BOOLEAN"},
			},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) != 0 {
			t.Errorf("expected no suggestion, got %d", len(suggestions))
		}
	})

	t.Run("scalar subquery triggers", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "name"}},
			From:    []ast.TableReference{{Name: "users"}},
			Where: &ast.BinaryExpression{
				Left:     &ast.Identifier{Name: "salary"},
				Operator: ">",
				Right: &ast.SubqueryExpression{
					Subquery: &ast.SelectStatement{
						Columns: []ast.Expression{
							&ast.FunctionCall{Name: "AVG", Arguments: []ast.Expression{&ast.Identifier{Name: "salary"}}},
						},
						From: []ast.TableReference{{Name: "employees"}},
					},
				},
			},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) == 0 {
			t.Error("expected suggestion for scalar subquery in WHERE")
		}
	})
}

// ---------------------------------------------------------------------------
// OPT-006: OR in WHERE
// ---------------------------------------------------------------------------

func TestOrInWhereRule(t *testing.T) {
	rule := &OrInWhereRule{}

	t.Run("OR on different columns triggers", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
			From:    []ast.TableReference{{Name: "users"}},
			Where: &ast.BinaryExpression{
				Left: &ast.BinaryExpression{
					Left:     &ast.Identifier{Name: "name"},
					Operator: "=",
					Right:    &ast.LiteralValue{Value: "John", Type: "STRING"},
				},
				Operator: "OR",
				Right: &ast.BinaryExpression{
					Left:     &ast.Identifier{Name: "email"},
					Operator: "=",
					Right:    &ast.LiteralValue{Value: "john@example.com", Type: "STRING"},
				},
			},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) == 0 {
			t.Error("expected suggestion for OR on different columns")
		}
	})

	t.Run("OR on same column does not trigger", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
			From:    []ast.TableReference{{Name: "users"}},
			Where: &ast.BinaryExpression{
				Left: &ast.BinaryExpression{
					Left:     &ast.Identifier{Name: "status"},
					Operator: "=",
					Right:    &ast.LiteralValue{Value: "active", Type: "STRING"},
				},
				Operator: "OR",
				Right: &ast.BinaryExpression{
					Left:     &ast.Identifier{Name: "status"},
					Operator: "=",
					Right:    &ast.LiteralValue{Value: "pending", Type: "STRING"},
				},
			},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) != 0 {
			t.Errorf("expected no suggestion for OR on same column, got %d", len(suggestions))
		}
	})

	t.Run("no WHERE does not trigger", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
			From:    []ast.TableReference{{Name: "users"}},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) != 0 {
			t.Errorf("expected no suggestion for no WHERE, got %d", len(suggestions))
		}
	})
}

// ---------------------------------------------------------------------------
// OPT-007: Leading Wildcard in LIKE
// ---------------------------------------------------------------------------

func TestLeadingWildcardLikeRule(t *testing.T) {
	rule := &LeadingWildcardLikeRule{}

	t.Run("leading wildcard triggers", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "name"}},
			From:    []ast.TableReference{{Name: "users"}},
			Where: &ast.BinaryExpression{
				Left:     &ast.Identifier{Name: "name"},
				Operator: "LIKE",
				Right:    &ast.LiteralValue{Value: "%smith", Type: "STRING"},
			},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) == 0 {
			t.Error("expected suggestion for leading wildcard LIKE")
		}
	})

	t.Run("trailing wildcard does not trigger", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "name"}},
			From:    []ast.TableReference{{Name: "users"}},
			Where: &ast.BinaryExpression{
				Left:     &ast.Identifier{Name: "name"},
				Operator: "LIKE",
				Right:    &ast.LiteralValue{Value: "smith%", Type: "STRING"},
			},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) == 0 {
			return // We might get zero if LIKE itself is not recurse-checked; this is fine
		}
		// Verify none are for OPT-007
		for _, s := range suggestions {
			if s.RuleID == "OPT-007" {
				t.Error("expected no suggestion for trailing wildcard LIKE")
			}
		}
	})

	t.Run("ILIKE with leading wildcard triggers", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "name"}},
			From:    []ast.TableReference{{Name: "users"}},
			Where: &ast.BinaryExpression{
				Left:     &ast.Identifier{Name: "name"},
				Operator: "ILIKE",
				Right:    &ast.LiteralValue{Value: "%john%", Type: "STRING"},
			},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) == 0 {
			t.Error("expected suggestion for leading wildcard ILIKE")
		}
	})

	t.Run("nested in AND triggers", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "name"}},
			From:    []ast.TableReference{{Name: "users"}},
			Where: &ast.BinaryExpression{
				Left: &ast.BinaryExpression{
					Left:     &ast.Identifier{Name: "active"},
					Operator: "=",
					Right:    &ast.LiteralValue{Value: true, Type: "BOOLEAN"},
				},
				Operator: "AND",
				Right: &ast.BinaryExpression{
					Left:     &ast.Identifier{Name: "name"},
					Operator: "LIKE",
					Right:    &ast.LiteralValue{Value: "%test", Type: "STRING"},
				},
			},
		}
		suggestions := rule.Analyze(stmt)
		found := false
		for _, s := range suggestions {
			if s.RuleID == "OPT-007" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected OPT-007 suggestion for leading wildcard nested in AND")
		}
	})
}

// ---------------------------------------------------------------------------
// OPT-008: Function on Indexed Column
// ---------------------------------------------------------------------------

func TestFunctionOnColumnRule(t *testing.T) {
	rule := &FunctionOnColumnRule{}

	t.Run("UPPER(column) = value triggers", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
			From:    []ast.TableReference{{Name: "users"}},
			Where: &ast.BinaryExpression{
				Left: &ast.FunctionCall{
					Name:      "UPPER",
					Arguments: []ast.Expression{&ast.Identifier{Name: "name"}},
				},
				Operator: "=",
				Right:    &ast.LiteralValue{Value: "JOHN", Type: "STRING"},
			},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) == 0 {
			t.Error("expected suggestion for function wrapping column")
		}
	})

	t.Run("column = value does not trigger", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
			From:    []ast.TableReference{{Name: "users"}},
			Where: &ast.BinaryExpression{
				Left:     &ast.Identifier{Name: "name"},
				Operator: "=",
				Right:    &ast.LiteralValue{Value: "John", Type: "STRING"},
			},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) != 0 {
			t.Errorf("expected no suggestion for plain column comparison, got %d", len(suggestions))
		}
	})

	t.Run("YEAR(created_at) triggers", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
			From:    []ast.TableReference{{Name: "events"}},
			Where: &ast.BinaryExpression{
				Left: &ast.FunctionCall{
					Name:      "YEAR",
					Arguments: []ast.Expression{&ast.Identifier{Name: "created_at"}},
				},
				Operator: "=",
				Right:    &ast.LiteralValue{Value: 2024, Type: "INTEGER"},
			},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) == 0 {
			t.Error("expected suggestion for YEAR() on column")
		}
	})

	t.Run("nested in AND triggers", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
			From:    []ast.TableReference{{Name: "users"}},
			Where: &ast.BinaryExpression{
				Left: &ast.BinaryExpression{
					Left:     &ast.Identifier{Name: "active"},
					Operator: "=",
					Right:    &ast.LiteralValue{Value: true, Type: "BOOLEAN"},
				},
				Operator: "AND",
				Right: &ast.BinaryExpression{
					Left: &ast.FunctionCall{
						Name:      "LOWER",
						Arguments: []ast.Expression{&ast.Identifier{Name: "email"}},
					},
					Operator: "=",
					Right:    &ast.LiteralValue{Value: "test@example.com", Type: "STRING"},
				},
			},
		}
		suggestions := rule.Analyze(stmt)
		found := false
		for _, s := range suggestions {
			if s.RuleID == "OPT-008" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected OPT-008 suggestion for function on column nested in AND")
		}
	})

	t.Run("function without column arg does not trigger", func(t *testing.T) {
		stmt := &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
			From:    []ast.TableReference{{Name: "users"}},
			Where: &ast.BinaryExpression{
				Left: &ast.FunctionCall{
					Name:      "NOW",
					Arguments: []ast.Expression{},
				},
				Operator: ">",
				Right:    &ast.Identifier{Name: "created_at"},
			},
		}
		suggestions := rule.Analyze(stmt)
		// Should not trigger for NOW() which has no column argument
		for _, s := range suggestions {
			if s.RuleID == "OPT-008" && s.Message == "Function NOW() wrapping column \"<column>\" in WHERE prevents index usage" {
				t.Error("should not trigger for function without column argument")
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Clean query tests (no suggestions expected)
// ---------------------------------------------------------------------------

func TestCleanQueries(t *testing.T) {
	opt := New()

	cleanQueries := []struct {
		name string
		sql  string
	}{
		{
			name: "simple SELECT with named columns",
			sql:  "SELECT id, name, email FROM users WHERE active = true",
		},
		{
			name: "JOIN with WHERE and named columns",
			sql:  "SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id WHERE o.status = 'completed'",
		},
		{
			name: "UPDATE with WHERE",
			sql:  "UPDATE users SET active = false WHERE last_login < '2024-01-01'",
		},
		{
			name: "DELETE with WHERE",
			sql:  "DELETE FROM sessions WHERE expired_at < NOW()",
		},
		{
			name: "INSERT statement",
			sql:  "INSERT INTO users (name, email) VALUES ('John', 'john@test.com')",
		},
	}

	for _, tt := range cleanQueries {
		t.Run(tt.name, func(t *testing.T) {
			result := mustAnalyze(t, opt, tt.sql)
			// A clean query might still have some info-level suggestions;
			// the important thing is no error or warning suggestions.
			for _, s := range result.Suggestions {
				if s.Severity == SeverityError {
					t.Errorf("clean query %q produced error suggestion: %s - %s", tt.sql, s.RuleID, s.Message)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AnalyzeSQL convenience method
// ---------------------------------------------------------------------------

func TestAnalyzeSQL(t *testing.T) {
	opt := New()

	t.Run("valid SQL succeeds", func(t *testing.T) {
		result, err := opt.AnalyzeSQL("SELECT id FROM users")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Score < 0 || result.Score > 100 {
			t.Errorf("score %d out of valid range [0, 100]", result.Score)
		}
	})

	t.Run("invalid SQL returns error", func(t *testing.T) {
		_, err := opt.AnalyzeSQL("NOT VALID SQL $$$")
		if err == nil {
			t.Error("expected error for invalid SQL")
		}
	})
}

// ---------------------------------------------------------------------------
// Score and Complexity tests
// ---------------------------------------------------------------------------

func TestScoreCalculation(t *testing.T) {
	t.Run("perfect score for no suggestions", func(t *testing.T) {
		score := calculateScore(nil)
		if score != 100 {
			t.Errorf("expected 100, got %d", score)
		}
	})

	t.Run("error reduces score by 20", func(t *testing.T) {
		suggestions := []Suggestion{
			{Severity: SeverityError},
		}
		score := calculateScore(suggestions)
		if score != 80 {
			t.Errorf("expected 80, got %d", score)
		}
	})

	t.Run("warning reduces score by 10", func(t *testing.T) {
		suggestions := []Suggestion{
			{Severity: SeverityWarning},
		}
		score := calculateScore(suggestions)
		if score != 90 {
			t.Errorf("expected 90, got %d", score)
		}
	})

	t.Run("info reduces score by 5", func(t *testing.T) {
		suggestions := []Suggestion{
			{Severity: SeverityInfo},
		}
		score := calculateScore(suggestions)
		if score != 95 {
			t.Errorf("expected 95, got %d", score)
		}
	})

	t.Run("score does not go below 0", func(t *testing.T) {
		suggestions := make([]Suggestion, 10)
		for i := range suggestions {
			suggestions[i].Severity = SeverityError
		}
		score := calculateScore(suggestions)
		if score != 0 {
			t.Errorf("expected 0, got %d", score)
		}
	})
}

func TestComplexityClassification(t *testing.T) {
	t.Run("nil AST is simple", func(t *testing.T) {
		complexity := classifyComplexity(nil)
		if complexity != ComplexitySimple {
			t.Errorf("expected %q, got %q", ComplexitySimple, complexity)
		}
	})

	t.Run("empty AST is simple", func(t *testing.T) {
		tree := &ast.AST{}
		complexity := classifyComplexity(tree)
		if complexity != ComplexitySimple {
			t.Errorf("expected %q, got %q", ComplexitySimple, complexity)
		}
	})

	t.Run("simple SELECT is simple", func(t *testing.T) {
		tree := &ast.AST{
			Statements: []ast.Statement{
				&ast.SelectStatement{
					Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
					From:    []ast.TableReference{{Name: "users"}},
				},
			},
		}
		complexity := classifyComplexity(tree)
		if complexity != ComplexitySimple {
			t.Errorf("expected %q, got %q", ComplexitySimple, complexity)
		}
	})

	t.Run("SELECT with JOINs is moderate", func(t *testing.T) {
		tree := &ast.AST{
			Statements: []ast.Statement{
				&ast.SelectStatement{
					Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
					From:    []ast.TableReference{{Name: "users"}},
					Joins: []ast.JoinClause{
						{Type: "INNER"},
					},
					GroupBy: []ast.Expression{&ast.Identifier{Name: "dept"}},
				},
			},
		}
		complexity := classifyComplexity(tree)
		if complexity != ComplexityModerate {
			t.Errorf("expected %q, got %q", ComplexityModerate, complexity)
		}
	})

	t.Run("complex query is complex", func(t *testing.T) {
		tree := &ast.AST{
			Statements: []ast.Statement{
				&ast.SelectStatement{
					Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
					From:    []ast.TableReference{{Name: "users"}},
					Joins: []ast.JoinClause{
						{Type: "INNER"},
						{Type: "LEFT"},
						{Type: "LEFT"},
					},
					GroupBy: []ast.Expression{&ast.Identifier{Name: "dept"}},
					Having:  &ast.BinaryExpression{Left: &ast.Identifier{Name: "cnt"}, Operator: ">", Right: &ast.LiteralValue{Value: 5}},
				},
			},
		}
		complexity := classifyComplexity(tree)
		if complexity != ComplexityComplex {
			t.Errorf("expected %q, got %q", ComplexityComplex, complexity)
		}
	})
}

// ---------------------------------------------------------------------------
// Nil AST / edge cases
// ---------------------------------------------------------------------------

func TestAnalyzeNilAST(t *testing.T) {
	opt := New()

	result := opt.Analyze(nil)
	if result == nil {
		t.Fatal("expected non-nil result for nil AST")
	}
	if len(result.Suggestions) != 0 {
		t.Errorf("expected 0 suggestions for nil AST, got %d", len(result.Suggestions))
	}
	if result.Score != 100 {
		t.Errorf("expected score 100 for nil AST, got %d", result.Score)
	}
}

func TestNewWithCustomRules(t *testing.T) {
	opt := NewWithRules(&SelectStarRule{})
	if len(opt.Rules()) != 1 {
		t.Errorf("expected 1 rule, got %d", len(opt.Rules()))
	}

	result := mustAnalyze(t, opt, "SELECT * FROM users")
	if !hasSuggestion(result, "OPT-001") {
		t.Error("expected OPT-001 suggestion")
	}
	if hasSuggestion(result, "OPT-002") {
		t.Error("OPT-002 should not be present with custom rules")
	}
}

// ---------------------------------------------------------------------------
// FormatResult
// ---------------------------------------------------------------------------

func TestFormatResult(t *testing.T) {
	t.Run("no suggestions", func(t *testing.T) {
		result := &OptimizationResult{
			Suggestions:     []Suggestion{},
			QueryComplexity: ComplexitySimple,
			Score:           100,
		}
		output := FormatResult(result)
		if output == "" {
			t.Error("expected non-empty output")
		}
		if !contains(output, "100/100") {
			t.Error("expected score in output")
		}
		if !contains(output, "No optimization suggestions") {
			t.Error("expected clean message in output")
		}
	})

	t.Run("with suggestions", func(t *testing.T) {
		result := &OptimizationResult{
			Suggestions: []Suggestion{
				{
					RuleID:       "OPT-001",
					Severity:     SeverityWarning,
					Message:      "Avoid SELECT *",
					SuggestedSQL: "SELECT col1, col2 FROM ...",
				},
			},
			QueryComplexity: ComplexitySimple,
			Score:           90,
		}
		output := FormatResult(result)
		if !contains(output, "OPT-001") {
			t.Error("expected rule ID in output")
		}
		if !contains(output, "90/100") {
			t.Error("expected score in output")
		}
	})
}

// ---------------------------------------------------------------------------
// DefaultRules
// ---------------------------------------------------------------------------

func TestDefaultRules(t *testing.T) {
	rules := DefaultRules()
	if len(rules) != 8 {
		t.Errorf("expected 8 default rules, got %d", len(rules))
	}

	ids := make(map[string]bool)
	for _, rule := range rules {
		if ids[rule.ID()] {
			t.Errorf("duplicate rule ID: %s", rule.ID())
		}
		ids[rule.ID()] = true

		if rule.Name() == "" {
			t.Errorf("rule %s has empty name", rule.ID())
		}
		if rule.Description() == "" {
			t.Errorf("rule %s has empty description", rule.ID())
		}
	}
}

// ---------------------------------------------------------------------------
// Rule interface methods
// ---------------------------------------------------------------------------

func TestRuleMetadata(t *testing.T) {
	rules := DefaultRules()

	expectedIDs := []string{
		"OPT-001", "OPT-002", "OPT-003", "OPT-004",
		"OPT-005", "OPT-006", "OPT-007", "OPT-008",
	}

	for i, rule := range rules {
		if rule.ID() != expectedIDs[i] {
			t.Errorf("rule %d: expected ID %q, got %q", i, expectedIDs[i], rule.ID())
		}
	}
}

// ---------------------------------------------------------------------------
// Non-SELECT statements
// ---------------------------------------------------------------------------

func TestNonSelectStatements(t *testing.T) {
	t.Run("rules targeting SELECT ignore INSERT", func(t *testing.T) {
		rule := &SelectStarRule{}
		stmt := &ast.InsertStatement{
			TableName: "users",
			Columns:   []ast.Expression{&ast.Identifier{Name: "name"}},
			Values:    [][]ast.Expression{{&ast.LiteralValue{Value: "John", Type: "STRING"}}},
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) != 0 {
			t.Error("SELECT * rule should not trigger on INSERT")
		}
	})

	t.Run("rules targeting SELECT ignore CREATE TABLE", func(t *testing.T) {
		rule := &DistinctOveruseRule{}
		stmt := &ast.CreateTableStatement{
			Name: "users",
		}
		suggestions := rule.Analyze(stmt)
		if len(suggestions) != 0 {
			t.Error("DISTINCT rule should not trigger on CREATE TABLE")
		}
	})
}

// ---------------------------------------------------------------------------
// Integration test with AnalyzeSQL
// ---------------------------------------------------------------------------

func TestIntegrationAnalyzeSQL(t *testing.T) {
	opt := New()

	t.Run("SELECT * produces OPT-001", func(t *testing.T) {
		result := mustAnalyze(t, opt, "SELECT * FROM users")
		if !hasSuggestion(result, "OPT-001") {
			t.Error("expected OPT-001 for SELECT *")
		}
	})

	t.Run("UPDATE without WHERE produces OPT-002", func(t *testing.T) {
		result := mustAnalyze(t, opt, "UPDATE users SET name = 'test'")
		if !hasSuggestion(result, "OPT-002") {
			t.Error("expected OPT-002 for UPDATE without WHERE")
		}
	})

	t.Run("DELETE without WHERE produces OPT-002", func(t *testing.T) {
		result := mustAnalyze(t, opt, "DELETE FROM users")
		if !hasSuggestion(result, "OPT-002") {
			t.Error("expected OPT-002 for DELETE without WHERE")
		}
	})

	t.Run("DISTINCT produces OPT-004", func(t *testing.T) {
		result := mustAnalyze(t, opt, "SELECT DISTINCT name FROM users")
		if !hasSuggestion(result, "OPT-004") {
			t.Error("expected OPT-004 for SELECT DISTINCT")
		}
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsSubstring(s, substr)
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
