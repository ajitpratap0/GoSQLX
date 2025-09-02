package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestParser_CTE(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		wantErr bool
		check   func(*testing.T, *ast.AST)
	}{
		{
			name: "Simple CTE",
			sql:  "WITH sales AS (SELECT * FROM orders) SELECT * FROM sales",
			check: func(t *testing.T, astObj *ast.AST) {
				if len(astObj.Statements) != 1 {
					t.Fatal("Expected 1 statement")
				}
				selectStmt, ok := astObj.Statements[0].(*ast.SelectStatement)
				if !ok {
					t.Fatal("Expected SELECT statement")
				}
				if selectStmt.With == nil {
					t.Fatal("Expected WITH clause")
				}
				if len(selectStmt.With.CTEs) != 1 {
					t.Errorf("Expected 1 CTE, got %d", len(selectStmt.With.CTEs))
				}
				if selectStmt.With.CTEs[0].Name != "sales" {
					t.Errorf("Expected CTE name 'sales', got %s", selectStmt.With.CTEs[0].Name)
				}
			},
		},
		{
			name: "CTE with column list",
			sql:  "WITH sales (id, amount) AS (SELECT order_id, total FROM orders) SELECT * FROM sales",
			check: func(t *testing.T, astObj *ast.AST) {
				selectStmt := astObj.Statements[0].(*ast.SelectStatement)
				if selectStmt.With == nil {
					t.Fatal("Expected WITH clause")
				}
				cte := selectStmt.With.CTEs[0]
				if len(cte.Columns) != 2 {
					t.Errorf("Expected 2 columns, got %d", len(cte.Columns))
				}
				if cte.Columns[0] != "id" || cte.Columns[1] != "amount" {
					t.Errorf("Expected columns [id, amount], got %v", cte.Columns)
				}
			},
		},
		{
			name: "Multiple CTEs",
			sql:  "WITH sales AS (SELECT * FROM orders), customers AS (SELECT * FROM users) SELECT * FROM sales JOIN customers ON sales.user_id = customers.id",
			check: func(t *testing.T, astObj *ast.AST) {
				selectStmt := astObj.Statements[0].(*ast.SelectStatement)
				if selectStmt.With == nil {
					t.Fatal("Expected WITH clause")
				}
				if len(selectStmt.With.CTEs) != 2 {
					t.Errorf("Expected 2 CTEs, got %d", len(selectStmt.With.CTEs))
				}
				if selectStmt.With.CTEs[0].Name != "sales" {
					t.Errorf("Expected first CTE name 'sales', got %s", selectStmt.With.CTEs[0].Name)
				}
				if selectStmt.With.CTEs[1].Name != "customers" {
					t.Errorf("Expected second CTE name 'customers', got %s", selectStmt.With.CTEs[1].Name)
				}
			},
		},
		{
			name: "RECURSIVE CTE",
			sql: `WITH RECURSIVE counter AS (
				SELECT 1 AS n
				UNION ALL
				SELECT n + 1 FROM counter WHERE n < 10
			) SELECT * FROM counter`,
			check: func(t *testing.T, astObj *ast.AST) {
				selectStmt := astObj.Statements[0].(*ast.SelectStatement)
				if selectStmt.With == nil {
					t.Fatal("Expected WITH clause")
				}
				if !selectStmt.With.Recursive {
					t.Error("Expected RECURSIVE flag to be true")
				}
				if selectStmt.With.CTEs[0].Name != "counter" {
					t.Errorf("Expected CTE name 'counter', got %s", selectStmt.With.CTEs[0].Name)
				}
			},
		},
		{
			name: "CTE in subquery",
			sql:  "WITH dept_avg AS (SELECT dept_id, AVG(salary) AS avg_sal FROM employees GROUP BY dept_id) SELECT * FROM employees e JOIN dept_avg d ON e.dept_id = d.dept_id WHERE e.salary > d.avg_sal",
			check: func(t *testing.T, astObj *ast.AST) {
				selectStmt := astObj.Statements[0].(*ast.SelectStatement)
				if selectStmt.With == nil {
					t.Fatal("Expected WITH clause")
				}
				if selectStmt.With.CTEs[0].Name != "dept_avg" {
					t.Errorf("Expected CTE name 'dept_avg', got %s", selectStmt.With.CTEs[0].Name)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get tokenizer from pool
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			// Tokenize SQL
			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("Failed to tokenize: %v", err)
			}

			// Convert tokens for parser
			convertedTokens := convertTokens(tokens)

			// Parse tokens
			parser := &Parser{}
			astObj, err := parser.Parse(convertedTokens)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && astObj != nil && tt.check != nil {
				defer ast.ReleaseAST(astObj)
				tt.check(t, astObj)
			}
		})
	}
}

func TestParser_RecursiveCTE(t *testing.T) {
	sql := `
		WITH RECURSIVE fibonacci (n, fib_n, next_fib_n) AS (
			SELECT 1, 0, 1
			UNION ALL
			SELECT n + 1, next_fib_n, fib_n + next_fib_n
			FROM fibonacci
			WHERE n < 10
		)
		SELECT * FROM fibonacci
	`

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	// Convert tokens for parser
	convertedTokens := convertTokens(tokens)

	// Parse tokens
	parser := &Parser{}
	astObj, err := parser.Parse(convertedTokens)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	// Verify the structure
	if len(astObj.Statements) != 1 {
		t.Fatal("Expected 1 statement")
	}

	selectStmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatal("Expected SELECT statement")
	}

	if selectStmt.With == nil {
		t.Fatal("Expected WITH clause")
	}

	if !selectStmt.With.Recursive {
		t.Error("Expected RECURSIVE flag to be true")
	}

	if len(selectStmt.With.CTEs) != 1 {
		t.Errorf("Expected 1 CTE, got %d", len(selectStmt.With.CTEs))
	}

	cte := selectStmt.With.CTEs[0]
	if cte.Name != "fibonacci" {
		t.Errorf("Expected CTE name 'fibonacci', got %s", cte.Name)
	}

	if len(cte.Columns) != 3 {
		t.Errorf("Expected 3 columns, got %d", len(cte.Columns))
	}

	expectedColumns := []string{"n", "fib_n", "next_fib_n"}
	for i, col := range cte.Columns {
		if col != expectedColumns[i] {
			t.Errorf("Column %d: expected %s, got %s", i, expectedColumns[i], col)
		}
	}
}
