// Package parser - aggregate_orderby_test.go
// Tests for ORDER BY inside aggregate functions (STRING_AGG, ARRAY_AGG, etc.)
// GitHub Issue #174

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// convertTokensForAggregateTests converts TokenWithSpan to Token for parser
func convertTokensForAggregateTests(tokens []models.TokenWithSpan) []token.Token {
	result := make([]token.Token, 0, len(tokens))
	for _, t := range tokens {
		// Handle compound keywords by splitting them
		if t.Token.Value == "ORDER BY" || t.Token.Type == models.TokenTypeOrderBy {
			result = append(result, token.Token{Type: "ORDER", Literal: "ORDER"})
			result = append(result, token.Token{Type: "BY", Literal: "BY"})
			continue
		}

		// Determine token type
		//lint:ignore SA1019 intentional use during #215 migration
		var tokenType token.Type

		switch t.Token.Type {
		case models.TokenTypeIdentifier:
			tokenType = "IDENT"
		case models.TokenTypeKeyword:
			//lint:ignore SA1019 intentional use during #215 migration
			tokenType = token.Type(t.Token.Value)
		case models.TokenTypeFrom:
			tokenType = "FROM"
		case models.TokenTypeSelect:
			tokenType = "SELECT"
		case models.TokenTypeOrder:
			tokenType = "ORDER"
		case models.TokenTypeBy:
			tokenType = "BY"
		case models.TokenTypeDesc:
			tokenType = "DESC"
		case models.TokenTypeAsc:
			tokenType = "ASC"
		case models.TokenTypeWhere:
			tokenType = "WHERE"
		case models.TokenTypeNulls:
			tokenType = "NULLS"
		case models.TokenTypeFirst:
			tokenType = "FIRST"
		case models.TokenTypeLast:
			tokenType = "LAST"
		case models.TokenTypeDistinct:
			tokenType = "DISTINCT"
		case models.TokenTypeOver:
			tokenType = "OVER"
		case models.TokenTypePartition:
			tokenType = "PARTITION"
		case models.TokenTypeString:
			tokenType = "STRING"
		case models.TokenTypeSingleQuotedString:
			tokenType = "STRING"
		case models.TokenTypeDoubleQuotedString:
			tokenType = "IDENT" // Double-quoted strings are identifiers in SQL
		case models.TokenTypeNumber:
			tokenType = "INT"
		case models.TokenTypeOperator:
			//lint:ignore SA1019 intentional use during #215 migration
			tokenType = token.Type(t.Token.Value)
		case models.TokenTypeLParen:
			tokenType = "("
		case models.TokenTypeRParen:
			tokenType = ")"
		case models.TokenTypeComma:
			tokenType = ","
		case models.TokenTypePeriod:
			tokenType = "."
		case models.TokenTypeEq:
			tokenType = "="
		case models.TokenTypeAsterisk:
			tokenType = "*"
		case models.TokenTypeCase:
			tokenType = "CASE"
		case models.TokenTypeWhen:
			tokenType = "WHEN"
		case models.TokenTypeThen:
			tokenType = "THEN"
		case models.TokenTypeElse:
			tokenType = "ELSE"
		case models.TokenTypeEnd:
			tokenType = "END"
		case models.TokenTypeAs:
			tokenType = "AS"
		default:
			// For any other type, use the value as the type if it looks like a keyword
			if t.Token.Value != "" {
				//lint:ignore SA1019 intentional use during #215 migration
				tokenType = token.Type(t.Token.Value)
			}
		}

		// Only add tokens with valid types and values
		if tokenType != "" && t.Token.Value != "" {
			result = append(result, token.Token{
				Type:    tokenType,
				Literal: t.Token.Value,
			})
		}
	}
	return result
}

func TestParser_AggregateOrderBy_StringAgg(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		wantErr bool
	}{
		{
			name:    "STRING_AGG with ORDER BY",
			sql:     "SELECT STRING_AGG(name, ', ' ORDER BY name) FROM users",
			wantErr: false,
		},
		{
			name:    "STRING_AGG with ORDER BY ASC",
			sql:     "SELECT STRING_AGG(name, ', ' ORDER BY name ASC) FROM users",
			wantErr: false,
		},
		{
			name:    "STRING_AGG with ORDER BY DESC",
			sql:     "SELECT STRING_AGG(name, ', ' ORDER BY name DESC) FROM users",
			wantErr: false,
		},
		{
			name:    "STRING_AGG with ORDER BY NULLS FIRST",
			sql:     "SELECT STRING_AGG(name, ', ' ORDER BY name NULLS FIRST) FROM users",
			wantErr: false,
		},
		{
			name:    "STRING_AGG with ORDER BY NULLS LAST",
			sql:     "SELECT STRING_AGG(name, ', ' ORDER BY name NULLS LAST) FROM users",
			wantErr: false,
		},
		{
			name:    "STRING_AGG with ORDER BY DESC NULLS LAST",
			sql:     "SELECT STRING_AGG(name, ', ' ORDER BY name DESC NULLS LAST) FROM users",
			wantErr: false,
		},
		{
			name:    "STRING_AGG with ORDER BY multiple columns",
			sql:     "SELECT STRING_AGG(name, ', ' ORDER BY last_name, first_name) FROM users",
			wantErr: false,
		},
		{
			name:    "STRING_AGG with ORDER BY multiple columns with directions",
			sql:     "SELECT STRING_AGG(name, ', ' ORDER BY last_name DESC, first_name ASC) FROM users",
			wantErr: false,
		},
		{
			name:    "STRING_AGG without ORDER BY (backward compatibility)",
			sql:     "SELECT STRING_AGG(name, ', ') FROM users",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("tokenization failed: %v", err)
			}

			convertedTokens := convertTokensForAggregateTests(tokens)
			parser := &Parser{}
			result, err := parser.Parse(convertedTokens)

			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				if len(result.Statements) == 0 {
					t.Error("expected statements, got none")
					return
				}

				selectStmt, ok := result.Statements[0].(*ast.SelectStatement)
				if !ok {
					t.Errorf("expected SelectStatement, got %T", result.Statements[0])
					return
				}

				if len(selectStmt.Columns) == 0 {
					t.Error("expected columns, got none")
					return
				}

				funcCall, ok := selectStmt.Columns[0].(*ast.FunctionCall)
				if !ok {
					t.Errorf("expected FunctionCall, got %T", selectStmt.Columns[0])
					return
				}

				// Verify function name
				if funcCall.Name != "STRING_AGG" {
					t.Errorf("expected function name STRING_AGG, got %s", funcCall.Name)
				}

				// Verify arguments (STRING_AGG should have 2 arguments: expression and separator)
				if len(funcCall.Arguments) != 2 {
					t.Errorf("expected 2 arguments, got %d", len(funcCall.Arguments))
				}

				// Verify ORDER BY clause if present in SQL
				if contains(tt.sql, "ORDER BY") {
					if len(funcCall.OrderBy) == 0 {
						t.Error("expected ORDER BY clause in function call, got none")
					}

					// Verify first order by expression
					orderBy := funcCall.OrderBy[0]
					if orderBy.Expression == nil {
						t.Error("expected order by expression, got nil")
					}

					// Verify ASC/DESC
					if contains(tt.sql, "DESC") && orderBy.Ascending {
						t.Error("expected DESC (Ascending=false), got ASC (Ascending=true)")
					}
					if !contains(tt.sql, "DESC") && contains(tt.sql, "ASC") && !orderBy.Ascending {
						t.Error("expected ASC (Ascending=true), got DESC (Ascending=false)")
					}

					// Verify NULLS FIRST/LAST
					if contains(tt.sql, "NULLS FIRST") {
						if orderBy.NullsFirst == nil || !*orderBy.NullsFirst {
							t.Error("expected NULLS FIRST")
						}
					}
					if contains(tt.sql, "NULLS LAST") {
						if orderBy.NullsFirst == nil || *orderBy.NullsFirst {
							t.Error("expected NULLS LAST")
						}
					}

					// Verify multiple order by columns
					if contains(tt.sql, "last_name") && contains(tt.sql, "first_name") {
						if len(funcCall.OrderBy) != 2 {
							t.Errorf("expected 2 ORDER BY expressions, got %d", len(funcCall.OrderBy))
						}
					}
				} else {
					// Verify no ORDER BY clause when not in SQL
					if len(funcCall.OrderBy) != 0 {
						t.Errorf("expected no ORDER BY clause, got %d expressions", len(funcCall.OrderBy))
					}
				}
			}
		})
	}
}

func TestParser_AggregateOrderBy_ArrayAgg(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		wantErr bool
	}{
		{
			name:    "ARRAY_AGG with ORDER BY",
			sql:     "SELECT ARRAY_AGG(value ORDER BY created_at) FROM items",
			wantErr: false,
		},
		{
			name:    "ARRAY_AGG with ORDER BY DESC",
			sql:     "SELECT ARRAY_AGG(value ORDER BY created_at DESC) FROM items",
			wantErr: false,
		},
		{
			name:    "ARRAY_AGG with ORDER BY and NULLS FIRST",
			sql:     "SELECT ARRAY_AGG(value ORDER BY priority DESC NULLS FIRST) FROM tasks",
			wantErr: false,
		},
		{
			name:    "ARRAY_AGG without ORDER BY",
			sql:     "SELECT ARRAY_AGG(value) FROM items",
			wantErr: false,
		},
		{
			name:    "ARRAY_AGG with DISTINCT and ORDER BY",
			sql:     "SELECT ARRAY_AGG(DISTINCT tag ORDER BY tag) FROM posts",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("tokenization failed: %v", err)
			}

			convertedTokens := convertTokensForAggregateTests(tokens)
			parser := &Parser{}
			result, err := parser.Parse(convertedTokens)

			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				if len(result.Statements) == 0 {
					t.Error("expected statements, got none")
					return
				}

				selectStmt, ok := result.Statements[0].(*ast.SelectStatement)
				if !ok {
					t.Errorf("expected SelectStatement, got %T", result.Statements[0])
					return
				}

				if len(selectStmt.Columns) == 0 {
					t.Error("expected columns, got none")
					return
				}

				funcCall, ok := selectStmt.Columns[0].(*ast.FunctionCall)
				if !ok {
					t.Errorf("expected FunctionCall, got %T", selectStmt.Columns[0])
					return
				}

				if funcCall.Name != "ARRAY_AGG" {
					t.Errorf("expected function name ARRAY_AGG, got %s", funcCall.Name)
				}

				// Verify DISTINCT
				if contains(tt.sql, "DISTINCT") && !funcCall.Distinct {
					t.Error("expected DISTINCT flag to be true")
				}

				// Verify ORDER BY
				if contains(tt.sql, "ORDER BY") {
					if len(funcCall.OrderBy) == 0 {
						t.Error("expected ORDER BY clause in function call, got none")
					}
				} else {
					if len(funcCall.OrderBy) != 0 {
						t.Errorf("expected no ORDER BY clause, got %d expressions", len(funcCall.OrderBy))
					}
				}
			}
		})
	}
}

func TestParser_AggregateOrderBy_OtherAggregates(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		funcName string
		wantErr  bool
	}{
		{
			name:     "JSON_AGG with ORDER BY",
			sql:      "SELECT JSON_AGG(data ORDER BY id) FROM records",
			funcName: "JSON_AGG",
			wantErr:  false,
		},
		{
			name:     "JSONB_AGG with ORDER BY",
			sql:      "SELECT JSONB_AGG(data ORDER BY created_at DESC) FROM events",
			funcName: "JSONB_AGG",
			wantErr:  false,
		},
		{
			name:     "XMLAGG with ORDER BY",
			sql:      "SELECT XMLAGG(element ORDER BY position) FROM xml_data",
			funcName: "XMLAGG",
			wantErr:  false,
		},
		{
			name:     "GROUP_CONCAT with ORDER BY (MySQL style - simplified)",
			sql:      "SELECT GROUP_CONCAT(name ORDER BY name) FROM users",
			funcName: "GROUP_CONCAT",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("tokenization failed: %v", err)
			}

			convertedTokens := convertTokensForAggregateTests(tokens)
			parser := &Parser{}
			result, err := parser.Parse(convertedTokens)

			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				selectStmt := result.Statements[0].(*ast.SelectStatement)
				funcCall := selectStmt.Columns[0].(*ast.FunctionCall)

				if funcCall.Name != tt.funcName {
					t.Errorf("expected function name %s, got %s", tt.funcName, funcCall.Name)
				}

				if len(funcCall.OrderBy) == 0 {
					t.Error("expected ORDER BY clause in function call, got none")
				}
			}
		})
	}
}

func TestParser_AggregateOrderBy_ComplexExpressions(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		wantErr bool
	}{
		{
			name:    "ORDER BY with expression",
			sql:     "SELECT STRING_AGG(name, ', ' ORDER BY UPPER(name)) FROM users",
			wantErr: false,
		},
		{
			name:    "ORDER BY with CASE expression",
			sql:     "SELECT ARRAY_AGG(id ORDER BY CASE WHEN priority = 'HIGH' THEN 1 ELSE 2 END) FROM tasks",
			wantErr: false,
		},
		{
			name:    "ORDER BY with arithmetic expression",
			sql:     "SELECT STRING_AGG(name, ', ' ORDER BY score * 100) FROM results",
			wantErr: false,
		},
		{
			name:    "ORDER BY with qualified column",
			sql:     "SELECT STRING_AGG(u.name, ', ' ORDER BY u.created_at) FROM users u",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("tokenization failed: %v", err)
			}

			convertedTokens := convertTokensForAggregateTests(tokens)
			parser := &Parser{}
			result, err := parser.Parse(convertedTokens)

			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				selectStmt := result.Statements[0].(*ast.SelectStatement)
				funcCall := selectStmt.Columns[0].(*ast.FunctionCall)

				if len(funcCall.OrderBy) == 0 {
					t.Error("expected ORDER BY clause in function call, got none")
				}

				// Verify that the ORDER BY expression was parsed
				if funcCall.OrderBy[0].Expression == nil {
					t.Error("expected ORDER BY expression, got nil")
				}
			}
		})
	}
}

func TestParser_AggregateOrderBy_WithWindowFunctions(t *testing.T) {
	// Test that ORDER BY in aggregate doesn't interfere with OVER clause
	tests := []struct {
		name    string
		sql     string
		wantErr bool
	}{
		{
			name:    "STRING_AGG with ORDER BY and window function",
			sql:     "SELECT STRING_AGG(name, ', ' ORDER BY name) OVER (PARTITION BY dept) FROM users",
			wantErr: false,
		},
		{
			name:    "ARRAY_AGG with ORDER BY inside and ORDER BY in OVER",
			sql:     "SELECT ARRAY_AGG(value ORDER BY created_at) OVER (ORDER BY id) FROM items",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("tokenization failed: %v", err)
			}

			convertedTokens := convertTokensForAggregateTests(tokens)
			parser := &Parser{}
			result, err := parser.Parse(convertedTokens)

			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				selectStmt := result.Statements[0].(*ast.SelectStatement)
				funcCall := selectStmt.Columns[0].(*ast.FunctionCall)

				// Verify ORDER BY inside function
				if len(funcCall.OrderBy) == 0 {
					t.Error("expected ORDER BY clause inside function call, got none")
				}

				// Verify OVER clause
				if funcCall.Over == nil {
					t.Error("expected OVER clause, got nil")
				}
			}
		})
	}
}

func TestParser_AggregateOrderBy_ErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		wantErr bool
	}{
		{
			name:    "ORDER BY without BY keyword",
			sql:     "SELECT STRING_AGG(name, ', ' ORDER name) FROM users",
			wantErr: true,
		},
		{
			name:    "ORDER BY without expression",
			sql:     "SELECT STRING_AGG(name, ', ' ORDER BY) FROM users",
			wantErr: true,
		},
		{
			name:    "Invalid ORDER BY syntax",
			sql:     "SELECT STRING_AGG(name, ', ' ORDER BY name DESC ASC) FROM users",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("tokenization failed: %v", err)
			}

			convertedTokens := convertTokensForAggregateTests(tokens)
			parser := &Parser{}
			_, err = parser.Parse(convertedTokens)

			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParser_AggregateOrderBy_InSubquery(t *testing.T) {
	sql := `
		SELECT dept,
			   (SELECT STRING_AGG(name, ', ' ORDER BY name)
			    FROM employees e
			    WHERE e.dept_id = d.id) as employees
		FROM departments d
	`

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenization failed: %v", err)
	}

	convertedTokens := convertTokensForAggregateTests(tokens)
	parser := &Parser{}
	result, err := parser.Parse(convertedTokens)

	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}

	selectStmt := result.Statements[0].(*ast.SelectStatement)
	if len(selectStmt.Columns) < 2 {
		t.Fatalf("expected at least 2 columns, got %d", len(selectStmt.Columns))
	}

	// The second column should be a subquery with an aliased expression
	aliasedExpr, ok := selectStmt.Columns[1].(*ast.AliasedExpression)
	if !ok {
		t.Fatalf("expected AliasedExpression, got %T", selectStmt.Columns[1])
	}

	subqueryExpr, ok := aliasedExpr.Expr.(*ast.SubqueryExpression)
	if !ok {
		t.Fatalf("expected SubqueryExpression, got %T", aliasedExpr.Expr)
	}

	subquerySelect, ok := subqueryExpr.Subquery.(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement in subquery, got %T", subqueryExpr.Subquery)
	}

	funcCall, ok := subquerySelect.Columns[0].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected FunctionCall in subquery, got %T", subquerySelect.Columns[0])
	}

	if len(funcCall.OrderBy) == 0 {
		t.Error("expected ORDER BY clause in function call within subquery, got none")
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
