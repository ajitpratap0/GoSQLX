// Package parser - fetch_test.go
// Tests for SQL-99 FETCH FIRST/NEXT clause parsing (F861, F862)

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// Note: Uses parseSQL helper from nulls_first_last_test.go

func TestParser_FetchClause(t *testing.T) {
	tests := []struct {
		name          string
		sql           string
		wantFetchType string
		wantFetchVal  int64
		wantWithTies  bool
		wantIsPercent bool
		wantOffset    *int
	}{
		{
			name:          "FETCH FIRST 5 ROWS ONLY",
			sql:           "SELECT * FROM users ORDER BY created_at FETCH FIRST 5 ROWS ONLY",
			wantFetchType: "FIRST",
			wantFetchVal:  5,
			wantWithTies:  false,
			wantIsPercent: false,
			wantOffset:    nil,
		},
		{
			name:          "FETCH NEXT 10 ROWS ONLY",
			sql:           "SELECT * FROM users ORDER BY id FETCH NEXT 10 ROWS ONLY",
			wantFetchType: "NEXT",
			wantFetchVal:  10,
			wantWithTies:  false,
			wantIsPercent: false,
			wantOffset:    nil,
		},
		{
			name:          "FETCH FIRST with ROW (singular)",
			sql:           "SELECT * FROM users FETCH FIRST 1 ROW ONLY",
			wantFetchType: "FIRST",
			wantFetchVal:  1,
			wantWithTies:  false,
			wantIsPercent: false,
			wantOffset:    nil,
		},
		{
			name:          "FETCH with WITH TIES",
			sql:           "SELECT * FROM products ORDER BY price FETCH FIRST 10 ROWS WITH TIES",
			wantFetchType: "FIRST",
			wantFetchVal:  10,
			wantWithTies:  true,
			wantIsPercent: false,
			wantOffset:    nil,
		},
		{
			name:          "FETCH with PERCENT",
			sql:           "SELECT * FROM orders ORDER BY total FETCH FIRST 10 PERCENT ROWS ONLY",
			wantFetchType: "FIRST",
			wantFetchVal:  10,
			wantWithTies:  false,
			wantIsPercent: true,
			wantOffset:    nil,
		},
		{
			name:          "FETCH PERCENT WITH TIES",
			sql:           "SELECT * FROM orders ORDER BY total FETCH FIRST 25 PERCENT ROWS WITH TIES",
			wantFetchType: "FIRST",
			wantFetchVal:  25,
			wantWithTies:  true,
			wantIsPercent: true,
			wantOffset:    nil,
		},
		{
			name:          "OFFSET with FETCH",
			sql:           "SELECT * FROM users ORDER BY id OFFSET 20 FETCH NEXT 10 ROWS ONLY",
			wantFetchType: "NEXT",
			wantFetchVal:  10,
			wantWithTies:  false,
			wantIsPercent: false,
			wantOffset:    intPtrFetch(20),
		},
		{
			name:          "OFFSET ROWS with FETCH",
			sql:           "SELECT * FROM users ORDER BY id OFFSET 20 ROWS FETCH NEXT 10 ROWS ONLY",
			wantFetchType: "NEXT",
			wantFetchVal:  10,
			wantWithTies:  false,
			wantIsPercent: false,
			wantOffset:    intPtrFetch(20),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmt := parseSQL(t, tt.sql)

			if stmt == nil {
				t.Fatal("expected statement, got nil")
			}

			if len(stmt.Statements) == 0 {
				t.Fatal("expected at least one statement")
			}

			selectStmt, ok := stmt.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected SelectStatement, got %T", stmt.Statements[0])
			}

			// Check FETCH clause
			if selectStmt.Fetch == nil {
				t.Fatal("expected Fetch clause, got nil")
			}

			fetch := selectStmt.Fetch

			if fetch.FetchType != tt.wantFetchType {
				t.Errorf("FetchType = %q, want %q", fetch.FetchType, tt.wantFetchType)
			}

			if fetch.FetchValue == nil {
				t.Fatal("expected FetchValue, got nil")
			}

			if *fetch.FetchValue != tt.wantFetchVal {
				t.Errorf("FetchValue = %d, want %d", *fetch.FetchValue, tt.wantFetchVal)
			}

			if fetch.WithTies != tt.wantWithTies {
				t.Errorf("WithTies = %v, want %v", fetch.WithTies, tt.wantWithTies)
			}

			if fetch.IsPercent != tt.wantIsPercent {
				t.Errorf("IsPercent = %v, want %v", fetch.IsPercent, tt.wantIsPercent)
			}

			// Check OFFSET if expected
			if tt.wantOffset != nil {
				if selectStmt.Offset == nil {
					t.Errorf("expected Offset = %d, got nil", *tt.wantOffset)
				} else if *selectStmt.Offset != *tt.wantOffset {
					t.Errorf("Offset = %d, want %d", *selectStmt.Offset, *tt.wantOffset)
				}
			}
		})
	}
}

func TestParser_FetchClauseWithComplexQueries(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "FETCH with WHERE and JOIN",
			sql: `SELECT u.name, o.total
				  FROM users u
				  JOIN orders o ON u.id = o.user_id
				  WHERE o.status_id = 1
				  ORDER BY o.total DESC
				  FETCH FIRST 10 ROWS ONLY`,
		},
		{
			name: "FETCH with GROUP BY and HAVING",
			sql: `SELECT department, AVG(salary)
				  FROM employees
				  GROUP BY department
				  HAVING COUNT(*) > 5
				  ORDER BY department DESC
				  FETCH FIRST 3 ROWS WITH TIES`,
		},
		{
			name: "FETCH with subquery",
			sql: `SELECT name, salary
				  FROM employees
				  WHERE salary > (SELECT AVG(salary) FROM employees)
				  ORDER BY salary DESC
				  OFFSET 5 ROWS
				  FETCH NEXT 10 ROWS ONLY`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmt := parseSQL(t, tt.sql)

			if stmt == nil || len(stmt.Statements) == 0 {
				t.Fatal("expected statement")
			}

			selectStmt, ok := stmt.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected SelectStatement, got %T", stmt.Statements[0])
			}

			if selectStmt.Fetch == nil {
				t.Error("expected Fetch clause")
			}
		})
	}
}

func TestParser_LimitVsFetch(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		wantLimit *int
		wantFetch bool
	}{
		{
			name:      "MySQL-style LIMIT only",
			sql:       "SELECT * FROM users LIMIT 10",
			wantLimit: intPtrFetch(10),
			wantFetch: false,
		},
		{
			name:      "MySQL-style LIMIT with OFFSET",
			sql:       "SELECT * FROM users LIMIT 10 OFFSET 5",
			wantLimit: intPtrFetch(10),
			wantFetch: false,
		},
		{
			name:      "SQL-99 FETCH only",
			sql:       "SELECT * FROM users FETCH FIRST 10 ROWS ONLY",
			wantLimit: nil,
			wantFetch: true,
		},
		{
			name:      "SQL-99 OFFSET with FETCH",
			sql:       "SELECT * FROM users OFFSET 5 FETCH NEXT 10 ROWS ONLY",
			wantLimit: nil,
			wantFetch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmt := parseSQL(t, tt.sql)

			selectStmt, ok := stmt.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected SelectStatement, got %T", stmt.Statements[0])
			}

			// Check LIMIT
			if tt.wantLimit != nil {
				if selectStmt.Limit == nil {
					t.Errorf("expected Limit = %d, got nil", *tt.wantLimit)
				} else if *selectStmt.Limit != *tt.wantLimit {
					t.Errorf("Limit = %d, want %d", *selectStmt.Limit, *tt.wantLimit)
				}
			} else if selectStmt.Limit != nil {
				t.Errorf("expected Limit = nil, got %d", *selectStmt.Limit)
			}

			// Check FETCH
			if tt.wantFetch && selectStmt.Fetch == nil {
				t.Error("expected Fetch clause, got nil")
			} else if !tt.wantFetch && selectStmt.Fetch != nil {
				t.Error("expected no Fetch clause")
			}
		})
	}
}

// intPtrFetch returns a pointer to an int (named differently to avoid conflict)
func intPtrFetch(i int) *int {
	return &i
}
