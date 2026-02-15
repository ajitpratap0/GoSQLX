package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestParser_NullsFirstLast_SelectStatement tests NULLS FIRST/LAST in SELECT ORDER BY
func TestParser_NullsFirstLast_SelectStatement(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		validateAST func(*testing.T, *ast.AST)
	}{
		{
			name: "ORDER BY with NULLS FIRST",
			sql:  "SELECT name FROM users ORDER BY salary NULLS FIRST",
			validateAST: func(t *testing.T, astObj *ast.AST) {
				if len(astObj.Statements) != 1 {
					t.Fatalf("expected 1 statement, got %d", len(astObj.Statements))
				}
				sel, ok := astObj.Statements[0].(*ast.SelectStatement)
				if !ok {
					t.Fatalf("expected *ast.SelectStatement, got %T", astObj.Statements[0])
				}
				if len(sel.OrderBy) != 1 {
					t.Fatalf("expected 1 ORDER BY expression, got %d", len(sel.OrderBy))
				}
				orderBy := sel.OrderBy[0]
				if orderBy.NullsFirst == nil {
					t.Fatal("expected NullsFirst to be non-nil")
				}
				if !*orderBy.NullsFirst {
					t.Error("expected NullsFirst to be true")
				}
				if !orderBy.Ascending {
					t.Error("expected Ascending to be true (default)")
				}
			},
		},
		{
			name: "ORDER BY with NULLS LAST",
			sql:  "SELECT name FROM users ORDER BY salary NULLS LAST",
			validateAST: func(t *testing.T, astObj *ast.AST) {
				sel := astObj.Statements[0].(*ast.SelectStatement)
				orderBy := sel.OrderBy[0]
				if orderBy.NullsFirst == nil {
					t.Fatal("expected NullsFirst to be non-nil")
				}
				if *orderBy.NullsFirst {
					t.Error("expected NullsFirst to be false")
				}
			},
		},
		{
			name: "ORDER BY DESC with NULLS FIRST",
			sql:  "SELECT name FROM users ORDER BY salary DESC NULLS FIRST",
			validateAST: func(t *testing.T, astObj *ast.AST) {
				sel := astObj.Statements[0].(*ast.SelectStatement)
				orderBy := sel.OrderBy[0]
				if orderBy.Ascending {
					t.Error("expected Ascending to be false")
				}
				if orderBy.NullsFirst == nil {
					t.Fatal("expected NullsFirst to be non-nil")
				}
				if !*orderBy.NullsFirst {
					t.Error("expected NullsFirst to be true")
				}
			},
		},
		{
			name: "ORDER BY ASC with NULLS LAST",
			sql:  "SELECT name FROM users ORDER BY salary ASC NULLS LAST",
			validateAST: func(t *testing.T, astObj *ast.AST) {
				sel := astObj.Statements[0].(*ast.SelectStatement)
				orderBy := sel.OrderBy[0]
				if !orderBy.Ascending {
					t.Error("expected Ascending to be true")
				}
				if orderBy.NullsFirst == nil {
					t.Fatal("expected NullsFirst to be non-nil")
				}
				if *orderBy.NullsFirst {
					t.Error("expected NullsFirst to be false")
				}
			},
		},
		{
			name: "Multiple ORDER BY columns with mixed NULLS clauses",
			sql:  "SELECT name FROM users ORDER BY dept NULLS FIRST, salary DESC NULLS LAST",
			validateAST: func(t *testing.T, astObj *ast.AST) {
				sel := astObj.Statements[0].(*ast.SelectStatement)
				if len(sel.OrderBy) != 2 {
					t.Fatalf("expected 2 ORDER BY expressions, got %d", len(sel.OrderBy))
				}

				// First column: dept NULLS FIRST
				first := sel.OrderBy[0]
				if !first.Ascending {
					t.Error("expected first column Ascending to be true (default)")
				}
				if first.NullsFirst == nil {
					t.Fatal("expected first column NullsFirst to be non-nil")
				}
				if !*first.NullsFirst {
					t.Error("expected first column NullsFirst to be true")
				}

				// Second column: salary DESC NULLS LAST
				second := sel.OrderBy[1]
				if second.Ascending {
					t.Error("expected second column Ascending to be false")
				}
				if second.NullsFirst == nil {
					t.Fatal("expected second column NullsFirst to be non-nil")
				}
				if *second.NullsFirst {
					t.Error("expected second column NullsFirst to be false")
				}
			},
		},
		{
			name: "ORDER BY without NULLS clause (default behavior)",
			sql:  "SELECT name FROM users ORDER BY salary DESC",
			validateAST: func(t *testing.T, astObj *ast.AST) {
				sel := astObj.Statements[0].(*ast.SelectStatement)
				orderBy := sel.OrderBy[0]
				if orderBy.NullsFirst != nil {
					t.Errorf("expected NullsFirst to be nil (database default), got %v", *orderBy.NullsFirst)
				}
			},
		},
		// Note: Complex expressions like "salary * 1.1" in ORDER BY are not yet supported by the parser
		// This is a parser limitation, not related to NULLS FIRST/LAST functionality
		{
			name: "Function call in ORDER BY with NULLS LAST",
			sql:  "SELECT name FROM users ORDER BY UPPER(name) NULLS LAST",
			validateAST: func(t *testing.T, astObj *ast.AST) {
				sel := astObj.Statements[0].(*ast.SelectStatement)
				orderBy := sel.OrderBy[0]
				if orderBy.NullsFirst == nil {
					t.Fatal("expected NullsFirst to be non-nil")
				}
				if *orderBy.NullsFirst {
					t.Error("expected NullsFirst to be false")
				}
				// Verify expression is a function call
				if _, ok := orderBy.Expression.(*ast.FunctionCall); !ok {
					t.Errorf("expected FunctionCall, got %T", orderBy.Expression)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			astObj := parseSQL(t, tt.sql)
			if tt.validateAST != nil {
				tt.validateAST(t, astObj)
			}
		})
	}
}

// TestParser_NullsFirstLast_WindowFunctions tests NULLS FIRST/LAST in window function ORDER BY
func TestParser_NullsFirstLast_WindowFunctions(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		validateAST func(*testing.T, *ast.AST)
	}{
		{
			name: "Window function with NULLS FIRST",
			sql:  "SELECT ROW_NUMBER() OVER (ORDER BY salary NULLS FIRST) FROM users",
			validateAST: func(t *testing.T, astObj *ast.AST) {
				sel := astObj.Statements[0].(*ast.SelectStatement)
				if len(sel.Columns) != 1 {
					t.Fatalf("expected 1 column, got %d", len(sel.Columns))
				}
				funcCall, ok := sel.Columns[0].(*ast.FunctionCall)
				if !ok {
					t.Fatalf("expected FunctionCall, got %T", sel.Columns[0])
				}
				if funcCall.Over == nil {
					t.Fatal("expected Over clause to be non-nil")
				}
				if len(funcCall.Over.OrderBy) != 1 {
					t.Fatalf("expected 1 ORDER BY in window spec, got %d", len(funcCall.Over.OrderBy))
				}
				orderBy := funcCall.Over.OrderBy[0]
				if orderBy.NullsFirst == nil {
					t.Fatal("expected NullsFirst to be non-nil")
				}
				if !*orderBy.NullsFirst {
					t.Error("expected NullsFirst to be true")
				}
			},
		},
		{
			name: "Window function with DESC NULLS LAST",
			sql:  "SELECT RANK() OVER (ORDER BY salary DESC NULLS LAST) FROM users",
			validateAST: func(t *testing.T, astObj *ast.AST) {
				sel := astObj.Statements[0].(*ast.SelectStatement)
				funcCall := sel.Columns[0].(*ast.FunctionCall)
				orderBy := funcCall.Over.OrderBy[0]
				if orderBy.Ascending {
					t.Error("expected Ascending to be false")
				}
				if orderBy.NullsFirst == nil {
					t.Fatal("expected NullsFirst to be non-nil")
				}
				if *orderBy.NullsFirst {
					t.Error("expected NullsFirst to be false")
				}
			},
		},
		{
			name: "Window function with PARTITION BY and NULLS FIRST",
			sql:  "SELECT RANK() OVER (PARTITION BY dept ORDER BY salary DESC NULLS FIRST) FROM employees",
			validateAST: func(t *testing.T, astObj *ast.AST) {
				sel := astObj.Statements[0].(*ast.SelectStatement)
				funcCall := sel.Columns[0].(*ast.FunctionCall)
				if funcCall.Over == nil {
					t.Fatal("expected Over clause to be non-nil")
				}
				if len(funcCall.Over.PartitionBy) != 1 {
					t.Errorf("expected 1 PARTITION BY expression, got %d", len(funcCall.Over.PartitionBy))
				}
				if len(funcCall.Over.OrderBy) != 1 {
					t.Fatalf("expected 1 ORDER BY expression, got %d", len(funcCall.Over.OrderBy))
				}
				orderBy := funcCall.Over.OrderBy[0]
				if orderBy.NullsFirst == nil {
					t.Fatal("expected NullsFirst to be non-nil")
				}
				if !*orderBy.NullsFirst {
					t.Error("expected NullsFirst to be true")
				}
			},
		},
		{
			name: "Window function with multiple ORDER BY and mixed NULLS clauses",
			sql:  "SELECT DENSE_RANK() OVER (ORDER BY dept NULLS FIRST, salary DESC NULLS LAST) FROM employees",
			validateAST: func(t *testing.T, astObj *ast.AST) {
				sel := astObj.Statements[0].(*ast.SelectStatement)
				funcCall := sel.Columns[0].(*ast.FunctionCall)
				if len(funcCall.Over.OrderBy) != 2 {
					t.Fatalf("expected 2 ORDER BY expressions, got %d", len(funcCall.Over.OrderBy))
				}

				// First: dept NULLS FIRST
				first := funcCall.Over.OrderBy[0]
				if first.NullsFirst == nil || !*first.NullsFirst {
					t.Error("expected first column NullsFirst to be true")
				}

				// Second: salary DESC NULLS LAST
				second := funcCall.Over.OrderBy[1]
				if second.NullsFirst == nil || *second.NullsFirst {
					t.Error("expected second column NullsFirst to be false")
				}
			},
		},
		{
			name: "Window function without NULLS clause",
			sql:  "SELECT ROW_NUMBER() OVER (ORDER BY salary DESC) FROM users",
			validateAST: func(t *testing.T, astObj *ast.AST) {
				sel := astObj.Statements[0].(*ast.SelectStatement)
				funcCall := sel.Columns[0].(*ast.FunctionCall)
				orderBy := funcCall.Over.OrderBy[0]
				if orderBy.NullsFirst != nil {
					t.Errorf("expected NullsFirst to be nil (database default), got %v", *orderBy.NullsFirst)
				}
			},
		},
		{
			name: "LAG with NULLS LAST in window ORDER BY",
			sql:  "SELECT LAG(salary, 1) OVER (ORDER BY hire_date NULLS LAST) FROM employees",
			validateAST: func(t *testing.T, astObj *ast.AST) {
				sel := astObj.Statements[0].(*ast.SelectStatement)
				funcCall := sel.Columns[0].(*ast.FunctionCall)
				if funcCall.Name != "LAG" {
					t.Errorf("expected function name LAG, got %s", funcCall.Name)
				}
				orderBy := funcCall.Over.OrderBy[0]
				if orderBy.NullsFirst == nil {
					t.Fatal("expected NullsFirst to be non-nil")
				}
				if *orderBy.NullsFirst {
					t.Error("expected NullsFirst to be false")
				}
			},
		},
		{
			name: "FIRST_VALUE with complex window spec and NULLS FIRST",
			sql:  "SELECT FIRST_VALUE(salary) OVER (PARTITION BY dept ORDER BY salary DESC NULLS FIRST ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) FROM employees",
			validateAST: func(t *testing.T, astObj *ast.AST) {
				sel := astObj.Statements[0].(*ast.SelectStatement)
				funcCall := sel.Columns[0].(*ast.FunctionCall)
				if funcCall.Name != "FIRST_VALUE" {
					t.Errorf("expected function name FIRST_VALUE, got %s", funcCall.Name)
				}
				orderBy := funcCall.Over.OrderBy[0]
				if orderBy.NullsFirst == nil {
					t.Fatal("expected NullsFirst to be non-nil")
				}
				if !*orderBy.NullsFirst {
					t.Error("expected NullsFirst to be true")
				}
				// Verify frame clause exists
				if funcCall.Over.FrameClause == nil {
					t.Error("expected FrameClause to be non-nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			astObj := parseSQL(t, tt.sql)
			if tt.validateAST != nil {
				tt.validateAST(t, astObj)
			}
		})
	}
}

// TestParser_NullsFirstLast_RealWorldQueries tests NULLS FIRST/LAST with realistic queries
// Note: Some advanced SQL features like column aliases (AS keyword) are not yet supported by the parser
func TestParser_NullsFirstLast_RealWorldQueries(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		description string
	}{
		{
			name: "Multi-level sorting with mixed NULLS",
			sql: `SELECT *
			FROM orders
			ORDER BY
				priority NULLS FIRST,
				order_date DESC NULLS LAST,
				customer_id NULLS FIRST`,
			description: "Complex sorting with different NULL behaviors per column",
		},
		// Note: Tests with column aliases (AS keyword) are disabled because the parser doesn't support AS yet
		// These would be valuable tests to add once AS keyword support is implemented:
		// - E-commerce product ranking with window functions
		// - Employee salary analysis with LAG function
		// - Sales leaderboard with ROW_NUMBER
		// - Window frames with SUM and NULLS ordering
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			astObj := parseSQL(t, tt.sql)

			if astObj == nil {
				t.Fatalf("expected non-nil AST for: %s", tt.description)
			}

			if len(astObj.Statements) == 0 {
				t.Fatalf("expected statements for: %s", tt.description)
			}
		})
	}
}
