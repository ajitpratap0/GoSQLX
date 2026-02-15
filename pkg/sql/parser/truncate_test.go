package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestParser_TruncateTable_Basic(t *testing.T) {
	sql := "TRUNCATE TABLE users"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	result, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	if len(result.Statements) != 1 {
		t.Fatalf("Expected 1 statement, got %d", len(result.Statements))
	}

	truncateStmt, ok := result.Statements[0].(*ast.TruncateStatement)
	if !ok {
		t.Fatalf("Expected TruncateStatement, got %T", result.Statements[0])
	}

	if len(truncateStmt.Tables) != 1 || truncateStmt.Tables[0] != "users" {
		t.Errorf("Expected tables [users], got %v", truncateStmt.Tables)
	}

	if truncateStmt.RestartIdentity {
		t.Error("RestartIdentity should be false")
	}

	if truncateStmt.ContinueIdentity {
		t.Error("ContinueIdentity should be false")
	}

	if truncateStmt.CascadeType != "" {
		t.Errorf("CascadeType should be empty, got %q", truncateStmt.CascadeType)
	}
}

func TestParser_TruncateTable_WithoutTableKeyword(t *testing.T) {
	sql := "TRUNCATE users"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	result, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	if len(result.Statements) != 1 {
		t.Fatalf("Expected 1 statement, got %d", len(result.Statements))
	}

	truncateStmt, ok := result.Statements[0].(*ast.TruncateStatement)
	if !ok {
		t.Fatalf("Expected TruncateStatement, got %T", result.Statements[0])
	}

	if len(truncateStmt.Tables) != 1 || truncateStmt.Tables[0] != "users" {
		t.Errorf("Expected tables [users], got %v", truncateStmt.Tables)
	}
}

func TestParser_TruncateTable_MultipleTables(t *testing.T) {
	sql := "TRUNCATE TABLE users, orders, products"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	result, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	if len(result.Statements) != 1 {
		t.Fatalf("Expected 1 statement, got %d", len(result.Statements))
	}

	truncateStmt, ok := result.Statements[0].(*ast.TruncateStatement)
	if !ok {
		t.Fatalf("Expected TruncateStatement, got %T", result.Statements[0])
	}

	expectedTables := []string{"users", "orders", "products"}
	if len(truncateStmt.Tables) != len(expectedTables) {
		t.Fatalf("Expected %d tables, got %d", len(expectedTables), len(truncateStmt.Tables))
	}

	for i, table := range expectedTables {
		if truncateStmt.Tables[i] != table {
			t.Errorf("Expected table %q at index %d, got %q", table, i, truncateStmt.Tables[i])
		}
	}
}

func TestParser_TruncateTable_RestartIdentity(t *testing.T) {
	sql := "TRUNCATE TABLE users RESTART IDENTITY"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	result, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	truncateStmt, ok := result.Statements[0].(*ast.TruncateStatement)
	if !ok {
		t.Fatalf("Expected TruncateStatement, got %T", result.Statements[0])
	}

	if !truncateStmt.RestartIdentity {
		t.Error("RestartIdentity should be true")
	}

	if truncateStmt.ContinueIdentity {
		t.Error("ContinueIdentity should be false")
	}
}

func TestParser_TruncateTable_ContinueIdentity(t *testing.T) {
	sql := "TRUNCATE TABLE users CONTINUE IDENTITY"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	result, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	truncateStmt, ok := result.Statements[0].(*ast.TruncateStatement)
	if !ok {
		t.Fatalf("Expected TruncateStatement, got %T", result.Statements[0])
	}

	if truncateStmt.RestartIdentity {
		t.Error("RestartIdentity should be false")
	}

	if !truncateStmt.ContinueIdentity {
		t.Error("ContinueIdentity should be true")
	}
}

func TestParser_TruncateTable_Cascade(t *testing.T) {
	sql := "TRUNCATE TABLE users CASCADE"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	result, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	truncateStmt, ok := result.Statements[0].(*ast.TruncateStatement)
	if !ok {
		t.Fatalf("Expected TruncateStatement, got %T", result.Statements[0])
	}

	if truncateStmt.CascadeType != "CASCADE" {
		t.Errorf("Expected CascadeType 'CASCADE', got %q", truncateStmt.CascadeType)
	}
}

func TestParser_TruncateTable_Restrict(t *testing.T) {
	sql := "TRUNCATE TABLE users RESTRICT"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	result, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	truncateStmt, ok := result.Statements[0].(*ast.TruncateStatement)
	if !ok {
		t.Fatalf("Expected TruncateStatement, got %T", result.Statements[0])
	}

	if truncateStmt.CascadeType != "RESTRICT" {
		t.Errorf("Expected CascadeType 'RESTRICT', got %q", truncateStmt.CascadeType)
	}
}

func TestParser_TruncateTable_FullSyntax(t *testing.T) {
	sql := "TRUNCATE TABLE users RESTART IDENTITY CASCADE"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	result, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	truncateStmt, ok := result.Statements[0].(*ast.TruncateStatement)
	if !ok {
		t.Fatalf("Expected TruncateStatement, got %T", result.Statements[0])
	}

	if len(truncateStmt.Tables) != 1 || truncateStmt.Tables[0] != "users" {
		t.Errorf("Expected tables [users], got %v", truncateStmt.Tables)
	}

	if !truncateStmt.RestartIdentity {
		t.Error("RestartIdentity should be true")
	}

	if truncateStmt.ContinueIdentity {
		t.Error("ContinueIdentity should be false")
	}

	if truncateStmt.CascadeType != "CASCADE" {
		t.Errorf("Expected CascadeType 'CASCADE', got %q", truncateStmt.CascadeType)
	}
}

func TestParser_TruncateTable_MultipleTablesWithRestrict(t *testing.T) {
	sql := "TRUNCATE TABLE users, orders CONTINUE IDENTITY RESTRICT"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	result, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	truncateStmt, ok := result.Statements[0].(*ast.TruncateStatement)
	if !ok {
		t.Fatalf("Expected TruncateStatement, got %T", result.Statements[0])
	}

	expectedTables := []string{"users", "orders"}
	if len(truncateStmt.Tables) != len(expectedTables) {
		t.Fatalf("Expected %d tables, got %d", len(expectedTables), len(truncateStmt.Tables))
	}

	for i, table := range expectedTables {
		if truncateStmt.Tables[i] != table {
			t.Errorf("Expected table %q at index %d, got %q", table, i, truncateStmt.Tables[i])
		}
	}

	if truncateStmt.RestartIdentity {
		t.Error("RestartIdentity should be false")
	}

	if !truncateStmt.ContinueIdentity {
		t.Error("ContinueIdentity should be true")
	}

	if truncateStmt.CascadeType != "RESTRICT" {
		t.Errorf("Expected CascadeType 'RESTRICT', got %q", truncateStmt.CascadeType)
	}
}

func TestParser_TruncateStatement_TokenLiteral(t *testing.T) {
	stmt := &ast.TruncateStatement{
		Tables: []string{"users"},
	}

	if stmt.TokenLiteral() != "TRUNCATE TABLE" {
		t.Errorf("Expected TokenLiteral 'TRUNCATE TABLE', got %q", stmt.TokenLiteral())
	}
}

func TestParser_TruncateStatement_Children(t *testing.T) {
	stmt := &ast.TruncateStatement{
		Tables: []string{"users", "orders"},
	}

	children := stmt.Children()
	if children != nil {
		t.Errorf("Expected Children() to return nil, got %v", children)
	}
}

// TestParser_TruncateTable_TableDriven tests various TRUNCATE TABLE scenarios
func TestParser_TruncateTable_TableDriven(t *testing.T) {
	tests := []struct {
		name             string
		sql              string
		expectedTables   []string
		restartIdentity  bool
		continueIdentity bool
		cascadeType      string
		shouldErr        bool
	}{
		{
			name:           "basic truncate",
			sql:            "TRUNCATE TABLE users",
			expectedTables: []string{"users"},
		},
		{
			name:           "without TABLE keyword",
			sql:            "TRUNCATE users",
			expectedTables: []string{"users"},
		},
		{
			name:           "multiple tables",
			sql:            "TRUNCATE TABLE a, b, c",
			expectedTables: []string{"a", "b", "c"},
		},
		{
			name:            "restart identity",
			sql:             "TRUNCATE TABLE t1 RESTART IDENTITY",
			expectedTables:  []string{"t1"},
			restartIdentity: true,
		},
		{
			name:             "continue identity",
			sql:              "TRUNCATE TABLE t1 CONTINUE IDENTITY",
			expectedTables:   []string{"t1"},
			continueIdentity: true,
		},
		{
			name:           "cascade",
			sql:            "TRUNCATE TABLE t1 CASCADE",
			expectedTables: []string{"t1"},
			cascadeType:    "CASCADE",
		},
		{
			name:           "restrict",
			sql:            "TRUNCATE TABLE t1 RESTRICT",
			expectedTables: []string{"t1"},
			cascadeType:    "RESTRICT",
		},
		{
			name:            "full syntax with restart",
			sql:             "TRUNCATE TABLE users RESTART IDENTITY CASCADE",
			expectedTables:  []string{"users"},
			restartIdentity: true,
			cascadeType:     "CASCADE",
		},
		{
			name:             "full syntax with continue",
			sql:              "TRUNCATE TABLE users CONTINUE IDENTITY RESTRICT",
			expectedTables:   []string{"users"},
			continueIdentity: true,
			cascadeType:      "RESTRICT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("Failed to tokenize: %v", err)
			}

			parser := &Parser{}
			result, err := parser.ParseFromModelTokens(tokens)

			if tt.shouldErr {
				if err == nil {
					t.Fatal("Expected error, got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Failed to parse: %v", err)
			}

			if len(result.Statements) != 1 {
				t.Fatalf("Expected 1 statement, got %d", len(result.Statements))
			}

			truncateStmt, ok := result.Statements[0].(*ast.TruncateStatement)
			if !ok {
				t.Fatalf("Expected TruncateStatement, got %T", result.Statements[0])
			}

			if len(truncateStmt.Tables) != len(tt.expectedTables) {
				t.Fatalf("Expected %d tables, got %d", len(tt.expectedTables), len(truncateStmt.Tables))
			}

			for i, table := range tt.expectedTables {
				if truncateStmt.Tables[i] != table {
					t.Errorf("Expected table %q at index %d, got %q", table, i, truncateStmt.Tables[i])
				}
			}

			if truncateStmt.RestartIdentity != tt.restartIdentity {
				t.Errorf("Expected RestartIdentity=%v, got %v", tt.restartIdentity, truncateStmt.RestartIdentity)
			}

			if truncateStmt.ContinueIdentity != tt.continueIdentity {
				t.Errorf("Expected ContinueIdentity=%v, got %v", tt.continueIdentity, truncateStmt.ContinueIdentity)
			}

			if truncateStmt.CascadeType != tt.cascadeType {
				t.Errorf("Expected CascadeType=%q, got %q", tt.cascadeType, truncateStmt.CascadeType)
			}
		})
	}
}
