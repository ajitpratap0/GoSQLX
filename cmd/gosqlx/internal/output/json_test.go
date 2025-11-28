package output

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestFormatValidationJSON_Success(t *testing.T) {
	result := &ValidationResult{
		TotalFiles:   2,
		ValidFiles:   2,
		InvalidFiles: 0,
		TotalBytes:   1024,
		Duration:     100 * time.Millisecond,
		Files: []FileValidationResult{
			{Path: "test1.sql", Valid: true, Size: 512},
			{Path: "test2.sql", Valid: true, Size: 512},
		},
	}

	jsonData, err := FormatValidationJSON(result, []string{"test1.sql", "test2.sql"}, true)
	if err != nil {
		t.Fatalf("FormatValidationJSON failed: %v", err)
	}

	// Parse the JSON to verify structure
	var output JSONValidationOutput
	if err := json.Unmarshal(jsonData, &output); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Verify structure
	if output.Command != "validate" {
		t.Errorf("Expected command 'validate', got '%s'", output.Command)
	}

	if output.Status != "success" {
		t.Errorf("Expected status 'success', got '%s'", output.Status)
	}

	if output.Results.Valid != true {
		t.Errorf("Expected valid=true, got %v", output.Results.Valid)
	}

	if output.Results.TotalFiles != 2 {
		t.Errorf("Expected 2 total files, got %d", output.Results.TotalFiles)
	}

	if output.Results.ValidFiles != 2 {
		t.Errorf("Expected 2 valid files, got %d", output.Results.ValidFiles)
	}

	if output.Results.InvalidFiles != 0 {
		t.Errorf("Expected 0 invalid files, got %d", output.Results.InvalidFiles)
	}

	if len(output.Errors) != 0 {
		t.Errorf("Expected 0 errors, got %d", len(output.Errors))
	}

	if output.Stats == nil {
		t.Error("Expected stats to be present")
	}

	if output.Stats != nil {
		if output.Stats.TotalBytes != 1024 {
			t.Errorf("Expected 1024 bytes, got %d", output.Stats.TotalBytes)
		}
	}
}

func TestFormatValidationJSON_WithErrors(t *testing.T) {
	result := &ValidationResult{
		TotalFiles:   2,
		ValidFiles:   1,
		InvalidFiles: 1,
		TotalBytes:   512,
		Duration:     50 * time.Millisecond,
		Files: []FileValidationResult{
			{Path: "test1.sql", Valid: true, Size: 512},
			{Path: "test2.sql", Valid: false, Size: 0, Error: &testError{msg: "parsing failed: syntax error"}},
		},
	}

	jsonData, err := FormatValidationJSON(result, []string{"test1.sql", "test2.sql"}, false)
	if err != nil {
		t.Fatalf("FormatValidationJSON failed: %v", err)
	}

	var output JSONValidationOutput
	if err := json.Unmarshal(jsonData, &output); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if output.Status != "failure" {
		t.Errorf("Expected status 'failure', got '%s'", output.Status)
	}

	if output.Results.Valid != false {
		t.Errorf("Expected valid=false, got %v", output.Results.Valid)
	}

	if len(output.Errors) != 1 {
		t.Fatalf("Expected 1 error, got %d", len(output.Errors))
	}

	if output.Errors[0].File != "test2.sql" {
		t.Errorf("Expected error file 'test2.sql', got '%s'", output.Errors[0].File)
	}

	if output.Errors[0].Type != "parsing" {
		t.Errorf("Expected error type 'parsing', got '%s'", output.Errors[0].Type)
	}

	if output.Stats != nil {
		t.Error("Expected stats to be nil when not requested")
	}
}

func TestFormatParseJSON_Success(t *testing.T) {
	// Create a simple AST
	sqlQuery := "SELECT id, name FROM users WHERE active = true"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sqlQuery))
	if err != nil {
		t.Fatalf("Tokenization failed: %v", err)
	}

	convertedTokens, err := parser.ConvertTokensForParser(tokens)
	if err != nil {
		t.Fatalf("Token conversion failed: %v", err)
	}

	p := parser.NewParser()
	astObj, err := p.Parse(convertedTokens)
	if err != nil {
		t.Fatalf("Parsing failed: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	jsonData, err := FormatParseJSON(astObj, sqlQuery, false, nil)
	if err != nil {
		t.Fatalf("FormatParseJSON failed: %v", err)
	}

	var output JSONParseOutput
	if err := json.Unmarshal(jsonData, &output); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if output.Command != "parse" {
		t.Errorf("Expected command 'parse', got '%s'", output.Command)
	}

	if output.Status != "success" {
		t.Errorf("Expected status 'success', got '%s'", output.Status)
	}

	if output.Results == nil {
		t.Fatal("Expected results to be present")
	}

	if output.Results.AST == nil {
		t.Fatal("Expected AST to be present")
	}

	if output.Results.AST.Type != "AST" {
		t.Errorf("Expected AST type 'AST', got '%s'", output.Results.AST.Type)
	}

	if len(output.Results.AST.Statements) != 1 {
		t.Errorf("Expected 1 statement, got %d", len(output.Results.AST.Statements))
	}

	if output.Results.Metadata.ParserVersion == "" {
		t.Error("Expected parser version to be set")
	}

	if output.Error != nil {
		t.Errorf("Expected no error, got %v", output.Error)
	}
}

func TestFormatParseErrorJSON(t *testing.T) {
	testErr := &testError{msg: "tokenization failed: invalid character"}

	jsonData, err := FormatParseErrorJSON(testErr, "SELECT * FROM")
	if err != nil {
		t.Fatalf("FormatParseErrorJSON failed: %v", err)
	}

	var output JSONParseOutput
	if err := json.Unmarshal(jsonData, &output); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if output.Status != "error" {
		t.Errorf("Expected status 'error', got '%s'", output.Status)
	}

	if output.Error == nil {
		t.Fatal("Expected error to be present")
	}

	if output.Error.Type != "tokenization" {
		t.Errorf("Expected error type 'tokenization', got '%s'", output.Error.Type)
	}

	if output.Results != nil {
		t.Error("Expected results to be nil on error")
	}
}

func TestCategorizeError(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected string
	}{
		{
			name:     "tokenization error",
			errMsg:   "tokenization failed: invalid character",
			expected: "tokenization",
		},
		{
			name:     "parsing error",
			errMsg:   "parsing failed: unexpected token",
			expected: "parsing",
		},
		{
			name:     "syntax error",
			errMsg:   "syntax error at line 5",
			expected: "syntax",
		},
		{
			name:     "io error - read",
			errMsg:   "failed to read file: permission denied",
			expected: "io",
		},
		{
			name:     "io error - open",
			errMsg:   "cannot open file",
			expected: "io",
		},
		{
			name:     "unknown error",
			errMsg:   "some unknown error",
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := categorizeError(tt.errMsg)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestDetermineInputType(t *testing.T) {
	tests := []struct {
		name     string
		files    []string
		expected string
	}{
		{
			name:     "empty files",
			files:    []string{},
			expected: "stdin",
		},
		{
			name:     "stdin marker",
			files:    []string{"-"},
			expected: "stdin",
		},
		{
			name:     "single file",
			files:    []string{"test.sql"},
			expected: "file",
		},
		{
			name:     "multiple files",
			files:    []string{"test1.sql", "test2.sql"},
			expected: "files",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineInputType(tt.files)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestDetermineStatus(t *testing.T) {
	tests := []struct {
		name     string
		result   *ValidationResult
		expected string
	}{
		{
			name: "success",
			result: &ValidationResult{
				ValidFiles:   2,
				InvalidFiles: 0,
			},
			expected: "success",
		},
		{
			name: "failure",
			result: &ValidationResult{
				ValidFiles:   1,
				InvalidFiles: 1,
			},
			expected: "failure",
		},
		{
			name: "no files",
			result: &ValidationResult{
				ValidFiles:   0,
				InvalidFiles: 0,
			},
			expected: "no_files",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineStatus(tt.result)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestConvertStatementToJSON(t *testing.T) {
	// Create a simple SELECT statement
	sqlQuery := "SELECT id, name FROM users WHERE active = true ORDER BY id LIMIT 10"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sqlQuery))
	if err != nil {
		t.Fatalf("Tokenization failed: %v", err)
	}

	convertedTokens, err := parser.ConvertTokensForParser(tokens)
	if err != nil {
		t.Fatalf("Token conversion failed: %v", err)
	}

	p := parser.NewParser()
	astObj, err := p.Parse(convertedTokens)
	if err != nil {
		t.Fatalf("Parsing failed: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) == 0 {
		t.Fatal("Expected at least one statement")
	}

	jsonStmt := convertStatementToJSON(astObj.Statements[0])

	if jsonStmt.Type != "SelectStatement" {
		t.Errorf("Expected type 'SelectStatement', got '%s'", jsonStmt.Type)
	}

	if jsonStmt.Details == nil {
		t.Fatal("Expected details to be present")
	}

	// Check for expected details
	if hasWhere, ok := jsonStmt.Details["has_where"].(bool); !ok || !hasWhere {
		t.Error("Expected has_where to be true")
	}

	if hasOrderBy, ok := jsonStmt.Details["has_order_by"].(bool); !ok || !hasOrderBy {
		t.Error("Expected has_order_by to be true")
	}

	if hasLimit, ok := jsonStmt.Details["has_limit"].(bool); !ok || !hasLimit {
		t.Error("Expected has_limit to be true")
	}
}

// testError is a simple error type for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
