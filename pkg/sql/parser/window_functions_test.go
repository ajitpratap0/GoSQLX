package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// convertTokensForWindowFunctions converts TokenWithSpan to Token for parser
func convertTokensForWindowFunctions(tokens []models.TokenWithSpan) []token.Token {
	result := make([]token.Token, 0, len(tokens))
	for _, t := range tokens {
		// Handle compound keywords by splitting them
		if t.Token.Value == "ORDER BY" {
			result = append(result, token.Token{Type: "ORDER", Literal: "ORDER", ModelType: models.TokenTypeOrder})
			result = append(result, token.Token{Type: "BY", Literal: "BY", ModelType: models.TokenTypeBy})
			continue
		}
		if t.Token.Value == "GROUP BY" {
			result = append(result, token.Token{Type: "GROUP", Literal: "GROUP", ModelType: models.TokenTypeGroup})
			result = append(result, token.Token{Type: "BY", Literal: "BY", ModelType: models.TokenTypeBy})
			continue
		}

		// Determine token type
		//lint:ignore SA1019 intentional use during #215 migration
		var tokenType token.Type
		modelType := t.Token.Type // Use the tokenizer's type as the model type

		switch t.Token.Type {
		case models.TokenTypeIdentifier:
			// Handle window function keywords that might be tokenized as identifiers
			if t.Token.Value == "OVER" || t.Token.Value == "PARTITION" ||
				t.Token.Value == "ROWS" || t.Token.Value == "RANGE" ||
				t.Token.Value == "CURRENT" || t.Token.Value == "UNBOUNDED" ||
				t.Token.Value == "PRECEDING" || t.Token.Value == "FOLLOWING" ||
				t.Token.Value == "DESC" || t.Token.Value == "ASC" ||
				t.Token.Value == "BETWEEN" || t.Token.Value == "AND" ||
				t.Token.Value == "ROW" || t.Token.Value == "NULLS" ||
				t.Token.Value == "FIRST" || t.Token.Value == "LAST" ||
				// FETCH clause keywords (SQL-99 F861, F862)
				t.Token.Value == "FETCH" || t.Token.Value == "NEXT" ||
				t.Token.Value == "ONLY" || t.Token.Value == "TIES" ||
				t.Token.Value == "PERCENT" || t.Token.Value == "OFFSET" ||
				// Row locking keywords (SQL:2003, PostgreSQL, MySQL)
				t.Token.Value == "UPDATE" || t.Token.Value == "SHARE" ||
				t.Token.Value == "NOWAIT" || t.Token.Value == "SKIP" ||
				t.Token.Value == "LOCKED" || t.Token.Value == "OF" ||
				t.Token.Value == "NO" || t.Token.Value == "KEY" ||
				t.Token.Value == "FOR" {
				//lint:ignore SA1019 intentional use during #215 migration
				tokenType = token.Type(t.Token.Value)
			} else {
				tokenType = "IDENT"
			}
		case models.TokenTypeKeyword:
			// Use the keyword value as the token type
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
		case models.TokenTypeAnd:
			tokenType = "AND"
		case models.TokenTypeBetween:
			tokenType = "BETWEEN"
		// FETCH clause token types (SQL-99 F861, F862)
		case models.TokenTypeFetch:
			tokenType = "FETCH"
		case models.TokenTypeNext:
			tokenType = "NEXT"
		case models.TokenTypeTies:
			tokenType = "TIES"
		case models.TokenTypePercent:
			tokenType = "PERCENT"
		case models.TokenTypeOnly:
			tokenType = "ONLY"
		case models.TokenTypeOffset:
			tokenType = "OFFSET"
		case models.TokenTypeFirst:
			tokenType = "FIRST"
		case models.TokenTypeLast:
			tokenType = "LAST"
		case models.TokenTypeRows:
			tokenType = "ROWS"
		case models.TokenTypeRow:
			tokenType = "ROW"
		// Row locking token types (SQL:2003, PostgreSQL, MySQL)
		case models.TokenTypeFor:
			tokenType = "FOR"
		case models.TokenTypeUpdate:
			tokenType = "UPDATE"
		case models.TokenTypeShare:
			tokenType = "SHARE"
		case models.TokenTypeNoWait:
			tokenType = "NOWAIT"
		case models.TokenTypeSkip:
			tokenType = "SKIP"
		case models.TokenTypeLocked:
			tokenType = "LOCKED"
		case models.TokenTypeOf:
			tokenType = "OF"
		case models.TokenTypeSum, models.TokenTypeCount, models.TokenTypeAvg,
			models.TokenTypeMin, models.TokenTypeMax:
			tokenType = "IDENT"                    // Treat aggregate functions as identifiers for function calls
			modelType = models.TokenTypeIdentifier // Normalize to identifier for parser
		case models.TokenTypeString, models.TokenTypeSingleQuotedString, models.TokenTypeDoubleQuotedString:
			tokenType = "STRING"
		case models.TokenTypeNumber:
			tokenType = "INT"
		case models.TokenTypeOperator:
			//lint:ignore SA1019 intentional use during #215 migration
			tokenType = token.Type(t.Token.Value)
		case models.TokenTypeMul, models.TokenTypeAsterisk:
			tokenType = "*"
			modelType = models.TokenTypeAsterisk // Normalize MUL to ASTERISK for parser
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
				Type:      tokenType,
				Literal:   t.Token.Value,
				ModelType: modelType,
			})
		}
	}
	return result
}

func TestParser_BasicWindowFunction(t *testing.T) {
	sql := `SELECT name, ROW_NUMBER() OVER (ORDER BY id) FROM users`

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	// Convert tokens for parser
	convertedTokens := convertTokensForWindowFunctions(tokens)

	// Parse tokens
	parser := &Parser{}
	astObj, err := parser.Parse(convertedTokens)
	if err != nil {
		t.Fatalf("Failed to parse window function: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	// Verify we have a statement
	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	// Verify it's a SELECT statement
	selectStmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("Expected SelectStatement, got %T", astObj.Statements[0])
	}

	// Verify we have 2 columns
	if len(selectStmt.Columns) != 2 {
		t.Fatalf("Expected 2 columns, got %d", len(selectStmt.Columns))
	}

	// Verify the second column is a window function
	funcCall, ok := selectStmt.Columns[1].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("Expected FunctionCall, got %T", selectStmt.Columns[1])
	}

	// Verify function name
	if funcCall.Name != "ROW_NUMBER" {
		t.Errorf("Expected function name 'ROW_NUMBER', got '%s'", funcCall.Name)
	}

	// Verify OVER clause exists
	if funcCall.Over == nil {
		t.Fatal("Expected OVER clause")
	}

	// Verify ORDER BY clause
	if len(funcCall.Over.OrderBy) != 1 {
		t.Errorf("Expected 1 ORDER BY expression, got %d", len(funcCall.Over.OrderBy))
	}
}

func TestParser_WindowFunctionWithPartition(t *testing.T) {
	sql := `SELECT name, RANK() OVER (PARTITION BY department ORDER BY salary DESC) FROM employees`

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	// Convert tokens for parser
	convertedTokens := convertTokensForWindowFunctions(tokens)

	// Parse tokens
	parser := &Parser{}
	astObj, err := parser.Parse(convertedTokens)
	if err != nil {
		t.Fatalf("Failed to parse window function with partition: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	// Verify we have a statement
	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	// Verify it's a SELECT statement
	selectStmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("Expected SelectStatement, got %T", astObj.Statements[0])
	}

	// Verify the second column is a window function
	funcCall, ok := selectStmt.Columns[1].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("Expected FunctionCall, got %T", selectStmt.Columns[1])
	}

	// Verify function name
	if funcCall.Name != "RANK" {
		t.Errorf("Expected function name 'RANK', got '%s'", funcCall.Name)
	}

	// Verify OVER clause exists
	if funcCall.Over == nil {
		t.Fatal("Expected OVER clause")
	}

	// Verify PARTITION BY clause
	if len(funcCall.Over.PartitionBy) != 1 {
		t.Errorf("Expected 1 PARTITION BY expression, got %d", len(funcCall.Over.PartitionBy))
	}

	// Verify ORDER BY clause
	if len(funcCall.Over.OrderBy) != 1 {
		t.Errorf("Expected 1 ORDER BY expression, got %d", len(funcCall.Over.OrderBy))
	}
}

func TestParser_WindowFunctionWithFrame(t *testing.T) {
	sql := `SELECT name, SUM(salary) OVER (ORDER BY hire_date ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) FROM employees`

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	// Convert tokens for parser
	convertedTokens := convertTokensForWindowFunctions(tokens)

	// Parse tokens
	parser := &Parser{}
	astObj, err := parser.Parse(convertedTokens)
	if err != nil {
		t.Fatalf("Failed to parse window function with frame: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	// Verify we have a statement
	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	// Verify it's a SELECT statement
	selectStmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("Expected SelectStatement, got %T", astObj.Statements[0])
	}

	// Verify the second column is a window function
	funcCall, ok := selectStmt.Columns[1].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("Expected FunctionCall, got %T", selectStmt.Columns[1])
	}

	// Verify function name
	if funcCall.Name != "SUM" {
		t.Errorf("Expected function name 'SUM', got '%s'", funcCall.Name)
	}

	// Verify OVER clause exists
	if funcCall.Over == nil {
		t.Fatal("Expected OVER clause")
	}

	// Verify ORDER BY clause
	if len(funcCall.Over.OrderBy) != 1 {
		t.Errorf("Expected 1 ORDER BY expression, got %d", len(funcCall.Over.OrderBy))
	}

	// Verify frame clause exists
	if funcCall.Over.FrameClause == nil {
		t.Fatal("Expected frame clause")
	}

	// Verify frame type
	if funcCall.Over.FrameClause.Type != "ROWS" {
		t.Errorf("Expected frame type 'ROWS', got '%s'", funcCall.Over.FrameClause.Type)
	}

	// Verify start bound
	if funcCall.Over.FrameClause.Start.Type != "PRECEDING" {
		t.Errorf("Expected start bound type 'PRECEDING', got '%s'", funcCall.Over.FrameClause.Start.Type)
	}

	// Verify end bound
	if funcCall.Over.FrameClause.End == nil {
		t.Fatal("Expected end bound")
	}
	if funcCall.Over.FrameClause.End.Type != "CURRENT ROW" {
		t.Errorf("Expected end bound type 'CURRENT ROW', got '%s'", funcCall.Over.FrameClause.End.Type)
	}
}

func TestParser_AnalyticFunctions(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		funcName string
	}{
		{
			name:     "LAG function",
			sql:      `SELECT name, LAG(salary, 1) OVER (ORDER BY hire_date) FROM employees`,
			funcName: "LAG",
		},
		{
			name:     "LEAD function",
			sql:      `SELECT name, LEAD(salary, 1) OVER (ORDER BY hire_date) FROM employees`,
			funcName: "LEAD",
		},
		{
			name:     "FIRST_VALUE function",
			sql:      `SELECT name, FIRST_VALUE(salary) OVER (ORDER BY hire_date) FROM employees`,
			funcName: "FIRST_VALUE",
		},
		{
			name:     "LAST_VALUE function",
			sql:      `SELECT name, LAST_VALUE(salary) OVER (ORDER BY hire_date) FROM employees`,
			funcName: "LAST_VALUE",
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
			convertedTokens := convertTokensForWindowFunctions(tokens)

			// Parse tokens
			parser := &Parser{}
			astObj, err := parser.Parse(convertedTokens)
			if err != nil {
				t.Fatalf("Failed to parse %s: %v", tt.funcName, err)
			}
			defer ast.ReleaseAST(astObj)

			// Verify we have a statement
			if len(astObj.Statements) == 0 {
				t.Fatal("No statements parsed")
			}

			// Verify it's a SELECT statement
			selectStmt, ok := astObj.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("Expected SelectStatement, got %T", astObj.Statements[0])
			}

			// Verify the second column is a window function
			funcCall, ok := selectStmt.Columns[1].(*ast.FunctionCall)
			if !ok {
				t.Fatalf("Expected FunctionCall, got %T", selectStmt.Columns[1])
			}

			// Verify function name
			if funcCall.Name != tt.funcName {
				t.Errorf("Expected function name '%s', got '%s'", tt.funcName, funcCall.Name)
			}

			// Verify OVER clause exists
			if funcCall.Over == nil {
				t.Fatal("Expected OVER clause")
			}

			// Verify ORDER BY clause
			if len(funcCall.Over.OrderBy) != 1 {
				t.Errorf("Expected 1 ORDER BY expression, got %d", len(funcCall.Over.OrderBy))
			}
		})
	}
}

func TestParser_RankingFunctions(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		funcName string
	}{
		{
			name:     "ROW_NUMBER function",
			sql:      `SELECT name, ROW_NUMBER() OVER (ORDER BY salary DESC) FROM employees`,
			funcName: "ROW_NUMBER",
		},
		{
			name:     "RANK function",
			sql:      `SELECT name, RANK() OVER (ORDER BY salary DESC) FROM employees`,
			funcName: "RANK",
		},
		{
			name:     "DENSE_RANK function",
			sql:      `SELECT name, DENSE_RANK() OVER (ORDER BY salary DESC) FROM employees`,
			funcName: "DENSE_RANK",
		},
		{
			name:     "NTILE function",
			sql:      `SELECT name, NTILE(4) OVER (ORDER BY salary DESC) FROM employees`,
			funcName: "NTILE",
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
			convertedTokens := convertTokensForWindowFunctions(tokens)

			// Parse tokens
			parser := &Parser{}
			astObj, err := parser.Parse(convertedTokens)
			if err != nil {
				t.Fatalf("Failed to parse %s: %v", tt.funcName, err)
			}
			defer ast.ReleaseAST(astObj)

			// Verify we have a statement
			if len(astObj.Statements) == 0 {
				t.Fatal("No statements parsed")
			}

			// Verify it's a SELECT statement
			selectStmt, ok := astObj.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("Expected SelectStatement, got %T", astObj.Statements[0])
			}

			// Verify the second column is a window function
			funcCall, ok := selectStmt.Columns[1].(*ast.FunctionCall)
			if !ok {
				t.Fatalf("Expected FunctionCall, got %T", selectStmt.Columns[1])
			}

			// Verify function name
			if funcCall.Name != tt.funcName {
				t.Errorf("Expected function name '%s', got '%s'", tt.funcName, funcCall.Name)
			}

			// Verify OVER clause exists
			if funcCall.Over == nil {
				t.Fatal("Expected OVER clause")
			}

			// Verify ORDER BY clause
			if len(funcCall.Over.OrderBy) != 1 {
				t.Errorf("Expected 1 ORDER BY expression, got %d", len(funcCall.Over.OrderBy))
			}
		})
	}
}

func TestParser_ComplexWindowFunction(t *testing.T) {
	sql := `SELECT 
		department,
		name, 
		salary,
		ROW_NUMBER() OVER (PARTITION BY department ORDER BY salary DESC),
		SUM(salary) OVER (PARTITION BY department ORDER BY hire_date ROWS UNBOUNDED PRECEDING)
	FROM employees`

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	// Convert tokens for parser
	convertedTokens := convertTokensForWindowFunctions(tokens)

	// Parse tokens
	parser := &Parser{}
	astObj, err := parser.Parse(convertedTokens)
	if err != nil {
		t.Fatalf("Failed to parse complex window function: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	// Verify we have a statement
	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	// Verify it's a SELECT statement
	selectStmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("Expected SelectStatement, got %T", astObj.Statements[0])
	}

	// Verify we have 5 columns
	if len(selectStmt.Columns) != 5 {
		t.Fatalf("Expected 5 columns, got %d", len(selectStmt.Columns))
	}

	// Verify the 4th column is ROW_NUMBER window function
	funcCall1, ok := selectStmt.Columns[3].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("Expected FunctionCall for 4th column, got %T", selectStmt.Columns[3])
	}

	if funcCall1.Name != "ROW_NUMBER" {
		t.Errorf("Expected function name 'ROW_NUMBER', got '%s'", funcCall1.Name)
	}

	// Verify PARTITION BY and ORDER BY
	if funcCall1.Over == nil {
		t.Fatal("Expected OVER clause for ROW_NUMBER")
	}
	if len(funcCall1.Over.PartitionBy) != 1 {
		t.Errorf("Expected 1 PARTITION BY expression, got %d", len(funcCall1.Over.PartitionBy))
	}
	if len(funcCall1.Over.OrderBy) != 1 {
		t.Errorf("Expected 1 ORDER BY expression, got %d", len(funcCall1.Over.OrderBy))
	}

	// Verify the 5th column is SUM window function with frame
	funcCall2, ok := selectStmt.Columns[4].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("Expected FunctionCall for 5th column, got %T", selectStmt.Columns[4])
	}

	if funcCall2.Name != "SUM" {
		t.Errorf("Expected function name 'SUM', got '%s'", funcCall2.Name)
	}

	// Verify OVER clause with frame
	if funcCall2.Over == nil {
		t.Fatal("Expected OVER clause for SUM")
	}
	if funcCall2.Over.FrameClause == nil {
		t.Fatal("Expected frame clause for SUM")
	}
	if funcCall2.Over.FrameClause.Start.Type != "UNBOUNDED PRECEDING" {
		t.Errorf("Expected start bound 'UNBOUNDED PRECEDING', got '%s'", funcCall2.Over.FrameClause.Start.Type)
	}
}
