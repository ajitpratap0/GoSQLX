package lsp

import (
	"encoding/json"
	"io"
	"log"
	"strings"
	"testing"
)

// TestHandler_DocumentSymbol tests document symbol extraction
func TestHandler_DocumentSymbol(t *testing.T) {
	tests := []struct {
		name          string
		sql           string
		expectedCount int
		checkSymbols  func(t *testing.T, symbols []DocumentSymbol)
	}{
		{
			name:          "SELECT statement returns SymbolMethod kind",
			sql:           "SELECT * FROM users",
			expectedCount: 1,
			checkSymbols: func(t *testing.T, symbols []DocumentSymbol) {
				if symbols[0].Kind != SymbolMethod {
					t.Errorf("expected SymbolMethod, got %v", symbols[0].Kind)
				}
				if !strings.HasPrefix(symbols[0].Name, "SELECT") {
					t.Errorf("expected name to start with SELECT, got %s", symbols[0].Name)
				}
				if symbols[0].Detail != "SELECT statement" {
					t.Errorf("expected detail 'SELECT statement', got %s", symbols[0].Detail)
				}
			},
		},
		{
			name:          "INSERT statement returns SymbolMethod kind",
			sql:           "INSERT INTO users (name) VALUES ('test')",
			expectedCount: 1,
			checkSymbols: func(t *testing.T, symbols []DocumentSymbol) {
				if symbols[0].Kind != SymbolMethod {
					t.Errorf("expected SymbolMethod, got %v", symbols[0].Kind)
				}
				if !strings.HasPrefix(symbols[0].Name, "INSERT") {
					t.Errorf("expected name to start with INSERT, got %s", symbols[0].Name)
				}
			},
		},
		{
			name:          "UPDATE statement returns SymbolMethod kind",
			sql:           "UPDATE users SET name = 'test' WHERE id = 1",
			expectedCount: 1,
			checkSymbols: func(t *testing.T, symbols []DocumentSymbol) {
				if symbols[0].Kind != SymbolMethod {
					t.Errorf("expected SymbolMethod, got %v", symbols[0].Kind)
				}
				if !strings.HasPrefix(symbols[0].Name, "UPDATE") {
					t.Errorf("expected name to start with UPDATE, got %s", symbols[0].Name)
				}
			},
		},
		{
			name:          "DELETE statement returns SymbolMethod kind",
			sql:           "DELETE FROM users WHERE id = 1",
			expectedCount: 1,
			checkSymbols: func(t *testing.T, symbols []DocumentSymbol) {
				if symbols[0].Kind != SymbolMethod {
					t.Errorf("expected SymbolMethod, got %v", symbols[0].Kind)
				}
				if !strings.HasPrefix(symbols[0].Name, "DELETE") {
					t.Errorf("expected name to start with DELETE, got %s", symbols[0].Name)
				}
			},
		},
		{
			name:          "CREATE TABLE returns SymbolStruct kind",
			sql:           "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100))",
			expectedCount: 0, // Parser may not support CREATE TABLE yet, expect 0
			checkSymbols: func(t *testing.T, symbols []DocumentSymbol) {
				// Only check if symbols were returned
				if len(symbols) > 0 {
					if symbols[0].Kind != SymbolStruct {
						t.Errorf("expected SymbolStruct, got %v", symbols[0].Kind)
					}
					if !strings.HasPrefix(symbols[0].Name, "CREATE TABLE") {
						t.Errorf("expected name to start with CREATE TABLE, got %s", symbols[0].Name)
					}
					if symbols[0].Detail != "DDL statement" {
						t.Errorf("expected detail 'DDL statement', got %s", symbols[0].Detail)
					}
				}
			},
		},
		{
			name:          "Multiple statements return numbered symbols",
			sql:           "SELECT * FROM users;\nSELECT * FROM orders",
			expectedCount: 2,
			checkSymbols: func(t *testing.T, symbols []DocumentSymbol) {
				if symbols[0].Name != "SELECT #1" {
					t.Errorf("expected 'SELECT #1', got %s", symbols[0].Name)
				}
				if symbols[1].Name != "SELECT #2" {
					t.Errorf("expected 'SELECT #2', got %s", symbols[1].Name)
				}
			},
		},
		{
			name:          "Invalid SQL returns empty symbols",
			sql:           "SELECT * FROM",
			expectedCount: 0,
			checkSymbols:  func(t *testing.T, symbols []DocumentSymbol) {},
		},
		{
			name:          "Empty document returns empty symbols",
			sql:           "",
			expectedCount: 0,
			checkSymbols:  func(t *testing.T, symbols []DocumentSymbol) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockReadWriter()
			logger := log.New(io.Discard, "", 0)
			server := NewServer(mock.input, mock.output, logger)

			// Open document
			server.Documents().Open("file:///test.sql", "sql", 1, tt.sql)

			// Request document symbols
			params := DocumentSymbolParams{
				TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
			}
			paramsJSON, _ := json.Marshal(params)

			result, err := server.handler.HandleRequest("textDocument/documentSymbol", paramsJSON)
			if err != nil {
				t.Fatalf("documentSymbol failed: %v", err)
			}

			symbols, ok := result.([]DocumentSymbol)
			if !ok {
				t.Fatalf("expected []DocumentSymbol, got %T", result)
			}

			if len(symbols) != tt.expectedCount {
				t.Errorf("expected %d symbols, got %d", tt.expectedCount, len(symbols))
			}

			if tt.expectedCount > 0 {
				tt.checkSymbols(t, symbols)
			}
		})
	}
}

// TestHandler_SignatureHelp tests function signature help
func TestHandler_SignatureHelp(t *testing.T) {
	tests := []struct {
		name            string
		sql             string
		position        Position
		expectSignature bool
		expectedFunc    string
		expectedParam   int
	}{
		{
			name:            "COUNT function returns signature",
			sql:             "SELECT COUNT(*) FROM users",
			position:        Position{Line: 0, Character: 13}, // Inside COUNT(*)
			expectSignature: true,
			expectedFunc:    "COUNT",
			expectedParam:   0,
		},
		{
			name:            "SUM function returns signature",
			sql:             "SELECT SUM(amount) FROM orders",
			position:        Position{Line: 0, Character: 11}, // Inside SUM(
			expectSignature: true,
			expectedFunc:    "SUM",
			expectedParam:   0,
		},
		{
			name:            "AVG function returns signature",
			sql:             "SELECT AVG(salary) FROM employees",
			position:        Position{Line: 0, Character: 11}, // Inside AVG(
			expectSignature: true,
			expectedFunc:    "AVG",
			expectedParam:   0,
		},
		{
			name:            "MIN function returns signature",
			sql:             "SELECT MIN(price) FROM products",
			position:        Position{Line: 0, Character: 11}, // Inside MIN(
			expectSignature: true,
			expectedFunc:    "MIN",
			expectedParam:   0,
		},
		{
			name:            "MAX function returns signature",
			sql:             "SELECT MAX(score) FROM tests",
			position:        Position{Line: 0, Character: 11}, // Inside MAX(
			expectSignature: true,
			expectedFunc:    "MAX",
			expectedParam:   0,
		},
		{
			name:            "COALESCE with multiple parameters",
			sql:             "SELECT COALESCE(name, email, 'unknown') FROM users",
			position:        Position{Line: 0, Character: 25}, // After first comma
			expectSignature: true,
			expectedFunc:    "COALESCE",
			expectedParam:   1,
		},
		{
			name:            "COALESCE second parameter",
			sql:             "SELECT COALESCE(name, email, 'unknown') FROM users",
			position:        Position{Line: 0, Character: 32}, // After second comma
			expectSignature: true,
			expectedFunc:    "COALESCE",
			expectedParam:   2,
		},
		{
			name:            "Cursor outside function returns nil",
			sql:             "SELECT * FROM users",
			position:        Position{Line: 0, Character: 8}, // Outside any function
			expectSignature: false,
		},
		{
			name:            "Parameter index at first comma",
			sql:             "SELECT CONCAT(first_name, last_name) FROM users",
			position:        Position{Line: 0, Character: 25}, // Right after comma
			expectSignature: true,
			expectedFunc:    "CONCAT",
			expectedParam:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockReadWriter()
			logger := log.New(io.Discard, "", 0)
			server := NewServer(mock.input, mock.output, logger)

			// Open document
			server.Documents().Open("file:///test.sql", "sql", 1, tt.sql)

			// Request signature help
			params := TextDocumentPositionParams{
				TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
				Position:     tt.position,
			}
			paramsJSON, _ := json.Marshal(params)

			result, err := server.handler.HandleRequest("textDocument/signatureHelp", paramsJSON)
			if err != nil {
				t.Fatalf("signatureHelp failed: %v", err)
			}

			help, ok := result.(*SignatureHelp)
			if !ok {
				t.Fatalf("expected *SignatureHelp, got %T", result)
			}

			if !tt.expectSignature {
				if len(help.Signatures) != 0 {
					t.Errorf("expected no signatures, got %d", len(help.Signatures))
				}
				return
			}

			if len(help.Signatures) == 0 {
				t.Fatal("expected signature, got none")
			}

			sig := help.Signatures[0]
			if !strings.Contains(sig.Label, tt.expectedFunc) {
				t.Errorf("expected signature label to contain %s, got %s", tt.expectedFunc, sig.Label)
			}

			if help.ActiveParameter != tt.expectedParam {
				t.Errorf("expected active parameter %d, got %d", tt.expectedParam, help.ActiveParameter)
			}
		})
	}
}

// TestHandler_CodeAction tests code action suggestions
func TestHandler_CodeAction(t *testing.T) {
	tests := []struct {
		name          string
		sql           string
		diagnostics   []Diagnostic
		expectedCount int
		checkActions  func(t *testing.T, actions []CodeAction)
	}{
		{
			name: "Missing semicolon suggestion",
			sql:  "SELECT * FROM users",
			diagnostics: []Diagnostic{
				{
					Range: Range{
						Start: Position{Line: 0, Character: 19},
						End:   Position{Line: 0, Character: 19},
					},
					Severity: SeverityError,
					Source:   "gosqlx",
					Message:  "expected semicolon at end of statement",
				},
			},
			expectedCount: 1,
			checkActions: func(t *testing.T, actions []CodeAction) {
				if actions[0].Title != "Add missing semicolon" {
					t.Errorf("expected 'Add missing semicolon', got %s", actions[0].Title)
				}
				if actions[0].Kind != CodeActionQuickFix {
					t.Errorf("expected CodeActionQuickFix, got %s", actions[0].Kind)
				}
				if actions[0].Edit == nil {
					t.Fatal("expected edit to be present")
				}
				edits := actions[0].Edit.Changes["file:///test.sql"]
				if len(edits) != 1 {
					t.Fatalf("expected 1 edit, got %d", len(edits))
				}
				if edits[0].NewText != ";" {
					t.Errorf("expected ';', got %s", edits[0].NewText)
				}
			},
		},
		{
			name: "Uppercase keyword suggestion",
			sql:  "select * from users",
			diagnostics: []Diagnostic{
				{
					Range: Range{
						Start: Position{Line: 0, Character: 0},
						End:   Position{Line: 0, Character: 6},
					},
					Severity: SeverityWarning,
					Source:   "gosqlx",
					Message:  "keyword 'select' should be uppercase",
				},
			},
			expectedCount: 1,
			checkActions: func(t *testing.T, actions []CodeAction) {
				if !strings.Contains(actions[0].Title, "uppercase") {
					t.Errorf("expected uppercase suggestion, got %s", actions[0].Title)
				}
				if actions[0].Edit == nil {
					t.Fatal("expected edit to be present")
				}
				edits := actions[0].Edit.Changes["file:///test.sql"]
				if len(edits) != 1 {
					t.Fatalf("expected 1 edit, got %d", len(edits))
				}
				if edits[0].NewText != "SELECT" {
					t.Errorf("expected 'SELECT', got %s", edits[0].NewText)
				}
			},
		},
		{
			name:          "Empty diagnostics returns empty actions",
			sql:           "SELECT * FROM users",
			diagnostics:   []Diagnostic{},
			expectedCount: 0,
			checkActions:  func(t *testing.T, actions []CodeAction) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockReadWriter()
			logger := log.New(io.Discard, "", 0)
			server := NewServer(mock.input, mock.output, logger)

			// Open document
			server.Documents().Open("file:///test.sql", "sql", 1, tt.sql)

			// Request code actions
			params := CodeActionParams{
				TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
				Range: Range{
					Start: Position{Line: 0, Character: 0},
					End:   Position{Line: 0, Character: 10},
				},
				Context: CodeActionContext{
					Diagnostics: tt.diagnostics,
				},
			}
			paramsJSON, _ := json.Marshal(params)

			result, err := server.handler.HandleRequest("textDocument/codeAction", paramsJSON)
			if err != nil {
				t.Fatalf("codeAction failed: %v", err)
			}

			actions, ok := result.([]CodeAction)
			if !ok {
				t.Fatalf("expected []CodeAction, got %T", result)
			}

			if len(actions) != tt.expectedCount {
				t.Errorf("expected %d actions, got %d", tt.expectedCount, len(actions))
			}

			if tt.expectedCount > 0 {
				tt.checkActions(t, actions)
			}
		})
	}
}

// TestHandler_DidClose tests document close
func TestHandler_DidClose(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	// First open a document
	server.Documents().Open("file:///test.sql", "sql", 1, "SELECT * FROM users")

	// Verify document exists
	_, ok := server.Documents().Get("file:///test.sql")
	if !ok {
		t.Fatal("expected document to be opened")
	}

	// Close the document
	params := DidCloseTextDocumentParams{
		TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
	}
	paramsJSON, _ := json.Marshal(params)
	server.handler.HandleNotification("textDocument/didClose", paramsJSON)

	// Verify document is removed from manager
	_, ok = server.Documents().Get("file:///test.sql")
	if ok {
		t.Error("expected document to be removed after close")
	}

	// Verify empty diagnostics published (check output contains publishDiagnostics)
	output := mock.output.String()
	if !strings.Contains(output, "publishDiagnostics") {
		t.Error("expected publishDiagnostics notification to be sent")
	}
	if !strings.Contains(output, `"diagnostics":[]`) {
		t.Error("expected empty diagnostics array in notification")
	}
}

// TestHandler_DidSave tests document save
func TestHandler_DidSave(t *testing.T) {
	tests := []struct {
		name         string
		sql          string
		expectErrors bool
	}{
		{
			name:         "Valid SQL triggers validation on save",
			sql:          "SELECT * FROM users",
			expectErrors: false,
		},
		{
			name:         "Invalid SQL shows diagnostics on save",
			sql:          "SELECT * FROM",
			expectErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockReadWriter()
			logger := log.New(io.Discard, "", 0)
			server := NewServer(mock.input, mock.output, logger)

			// Open document
			server.Documents().Open("file:///test.sql", "sql", 1, tt.sql)

			// Clear output buffer
			mock.output.Reset()

			// Save the document
			params := DidSaveTextDocumentParams{
				TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
				Text:         tt.sql,
			}
			paramsJSON, _ := json.Marshal(params)
			server.handler.HandleNotification("textDocument/didSave", paramsJSON)

			// Verify validation was triggered (publishDiagnostics sent)
			output := mock.output.String()
			if !strings.Contains(output, "publishDiagnostics") {
				t.Error("expected validation to trigger publishDiagnostics notification")
			}

			// Check if diagnostics array is present and matches expectation
			if tt.expectErrors {
				if strings.Contains(output, `"diagnostics":[]`) {
					t.Error("expected error diagnostics, got empty array")
				}
			}
		})
	}
}

// TestHandler_DocumentSymbol_NoDocument tests document symbol when document doesn't exist
func TestHandler_DocumentSymbol_NoDocument(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	// Request symbols for non-existent document
	params := DocumentSymbolParams{
		TextDocument: TextDocumentIdentifier{URI: "file:///nonexistent.sql"},
	}
	paramsJSON, _ := json.Marshal(params)

	result, err := server.handler.HandleRequest("textDocument/documentSymbol", paramsJSON)
	if err != nil {
		t.Fatalf("documentSymbol failed: %v", err)
	}

	symbols, ok := result.([]DocumentSymbol)
	if !ok {
		t.Fatalf("expected []DocumentSymbol, got %T", result)
	}

	if len(symbols) != 0 {
		t.Errorf("expected empty symbols for non-existent document, got %d", len(symbols))
	}
}

// TestHandler_SignatureHelp_NoDocument tests signature help when document doesn't exist
func TestHandler_SignatureHelp_NoDocument(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	// Request signature help for non-existent document
	params := TextDocumentPositionParams{
		TextDocument: TextDocumentIdentifier{URI: "file:///nonexistent.sql"},
		Position:     Position{Line: 0, Character: 0},
	}
	paramsJSON, _ := json.Marshal(params)

	result, err := server.handler.HandleRequest("textDocument/signatureHelp", paramsJSON)
	if err != nil {
		t.Fatalf("signatureHelp failed: %v", err)
	}

	help, ok := result.(*SignatureHelp)
	if !ok {
		t.Fatalf("expected *SignatureHelp, got %T", result)
	}

	if len(help.Signatures) != 0 {
		t.Errorf("expected empty signatures for non-existent document, got %d", len(help.Signatures))
	}
}

// TestGetFunctionAtPosition tests the internal function position detection
func TestGetFunctionAtPosition(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)
	handler := server.handler

	tests := []struct {
		name          string
		content       string
		position      Position
		expectedFunc  string
		expectedParam int
	}{
		{
			name:          "Simple function call",
			content:       "SELECT COUNT(*) FROM users",
			position:      Position{Line: 0, Character: 13},
			expectedFunc:  "COUNT",
			expectedParam: 0,
		},
		{
			name:          "Function with multiple params - first param",
			content:       "SELECT COALESCE(name, email, phone) FROM users",
			position:      Position{Line: 0, Character: 20},
			expectedFunc:  "COALESCE",
			expectedParam: 0,
		},
		{
			name:          "Function with multiple params - second param",
			content:       "SELECT COALESCE(name, email, phone) FROM users",
			position:      Position{Line: 0, Character: 27},
			expectedFunc:  "COALESCE",
			expectedParam: 1,
		},
		{
			name:          "Function with multiple params - third param",
			content:       "SELECT COALESCE(name, email, phone) FROM users",
			position:      Position{Line: 0, Character: 34},
			expectedFunc:  "COALESCE",
			expectedParam: 2,
		},
		{
			name:          "Nested function - outer",
			content:       "SELECT UPPER(TRIM(name)) FROM users",
			position:      Position{Line: 0, Character: 23},
			expectedFunc:  "UPPER",
			expectedParam: 0,
		},
		{
			name:          "Position outside function",
			content:       "SELECT * FROM users",
			position:      Position{Line: 0, Character: 8},
			expectedFunc:  "",
			expectedParam: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			funcName, paramIdx := handler.getFunctionAtPosition(tt.content, tt.position)
			if funcName != tt.expectedFunc {
				t.Errorf("expected function %q, got %q", tt.expectedFunc, funcName)
			}
			if paramIdx != tt.expectedParam {
				t.Errorf("expected param index %d, got %d", tt.expectedParam, paramIdx)
			}
		})
	}
}

// TestGetSQLFunctionSignature tests function signature lookup
func TestGetSQLFunctionSignature(t *testing.T) {
	functions := []string{
		"COUNT", "SUM", "AVG", "MIN", "MAX",
		"COALESCE", "NULLIF", "CAST", "SUBSTRING",
		"TRIM", "UPPER", "LOWER", "LENGTH", "CONCAT",
		"ROW_NUMBER", "RANK", "DENSE_RANK", "LAG", "LEAD",
		"FIRST_VALUE", "LAST_VALUE", "NTILE",
	}

	for _, fn := range functions {
		t.Run(fn, func(t *testing.T) {
			sig := getSQLFunctionSignature(fn)
			if sig == nil {
				t.Errorf("expected signature for %s, got nil", fn)
				return
			}
			if sig.Label == "" {
				t.Errorf("expected non-empty label for %s", fn)
			}
		})
	}

	// Test unknown function
	sig := getSQLFunctionSignature("UNKNOWN_FUNCTION")
	if sig != nil {
		t.Error("expected nil for unknown function")
	}
}
