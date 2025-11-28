package linter

import (
	"errors"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestNewContext tests the NewContext constructor with various SQL inputs
func TestNewContext(t *testing.T) {
	tests := []struct {
		name             string
		sql              string
		filename         string
		expectedSQL      string
		expectedLines    []string
		expectedFilename string
	}{
		{
			name:             "simple SQL",
			sql:              "SELECT * FROM users",
			filename:         "query.sql",
			expectedSQL:      "SELECT * FROM users",
			expectedLines:    []string{"SELECT * FROM users"},
			expectedFilename: "query.sql",
		},
		{
			name:             "empty string",
			sql:              "",
			filename:         "empty.sql",
			expectedSQL:      "",
			expectedLines:    []string{""},
			expectedFilename: "empty.sql",
		},
		{
			name:             "single line",
			sql:              "SELECT id, name FROM users WHERE active = true",
			filename:         "single.sql",
			expectedSQL:      "SELECT id, name FROM users WHERE active = true",
			expectedLines:    []string{"SELECT id, name FROM users WHERE active = true"},
			expectedFilename: "single.sql",
		},
		{
			name: "multiple lines",
			sql: `SELECT id, name
FROM users
WHERE active = true`,
			filename: "multi.sql",
			expectedSQL: `SELECT id, name
FROM users
WHERE active = true`,
			expectedLines:    []string{"SELECT id, name", "FROM users", "WHERE active = true"},
			expectedFilename: "multi.sql",
		},
		{
			name:             "Windows line endings",
			sql:              "SELECT *\r\nFROM users\r\nWHERE id = 1",
			filename:         "windows.sql",
			expectedSQL:      "SELECT *\r\nFROM users\r\nWHERE id = 1",
			expectedLines:    []string{"SELECT *\r", "FROM users\r", "WHERE id = 1"},
			expectedFilename: "windows.sql",
		},
		{
			name:             "Unix line endings",
			sql:              "SELECT *\nFROM users\nWHERE id = 1",
			filename:         "unix.sql",
			expectedSQL:      "SELECT *\nFROM users\nWHERE id = 1",
			expectedLines:    []string{"SELECT *", "FROM users", "WHERE id = 1"},
			expectedFilename: "unix.sql",
		},
		{
			name:             "mixed line endings",
			sql:              "SELECT *\nFROM users\r\nWHERE id = 1\nORDER BY name",
			filename:         "mixed.sql",
			expectedSQL:      "SELECT *\nFROM users\r\nWHERE id = 1\nORDER BY name",
			expectedLines:    []string{"SELECT *", "FROM users\r", "WHERE id = 1", "ORDER BY name"},
			expectedFilename: "mixed.sql",
		},
		{
			name: "Unicode content",
			sql: `SELECT name, 価格
FROM 製品
WHERE カテゴリ = '電子機器'`,
			filename: "unicode.sql",
			expectedSQL: `SELECT name, 価格
FROM 製品
WHERE カテゴリ = '電子機器'`,
			expectedLines:    []string{"SELECT name, 価格", "FROM 製品", "WHERE カテゴリ = '電子機器'"},
			expectedFilename: "unicode.sql",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewContext(tt.sql, tt.filename)

			// Verify SQL is stored correctly
			if ctx.SQL != tt.expectedSQL {
				t.Errorf("SQL = %q, want %q", ctx.SQL, tt.expectedSQL)
			}

			// Verify filename is stored correctly
			if ctx.Filename != tt.expectedFilename {
				t.Errorf("Filename = %q, want %q", ctx.Filename, tt.expectedFilename)
			}

			// Verify lines are split correctly
			if len(ctx.Lines) != len(tt.expectedLines) {
				t.Fatalf("Lines count = %d, want %d", len(ctx.Lines), len(tt.expectedLines))
			}

			for i, line := range ctx.Lines {
				if line != tt.expectedLines[i] {
					t.Errorf("Lines[%d] = %q, want %q", i, line, tt.expectedLines[i])
				}
			}

			// Verify tokens and AST are initially nil/empty
			if ctx.Tokens != nil {
				t.Errorf("Tokens should be nil, got %v", ctx.Tokens)
			}
			if ctx.AST != nil {
				t.Errorf("AST should be nil, got %v", ctx.AST)
			}
			if ctx.ParseErr != nil {
				t.Errorf("ParseErr should be nil, got %v", ctx.ParseErr)
			}
		})
	}
}

// TestContext_WithTokens tests adding tokens to the context
func TestContext_WithTokens(t *testing.T) {
	tests := []struct {
		name           string
		sql            string
		tokens         []models.TokenWithSpan
		expectedTokens []models.TokenWithSpan
	}{
		{
			name: "add tokens to context",
			sql:  "SELECT * FROM users",
			tokens: []models.TokenWithSpan{
				{
					Token: models.Token{Type: models.TokenTypeWord, Value: "SELECT"},
					Start: models.Location{Line: 1, Column: 1},
					End:   models.Location{Line: 1, Column: 7},
				},
				{
					Token: models.Token{Type: models.TokenTypeMul, Value: "*"},
					Start: models.Location{Line: 1, Column: 8},
					End:   models.Location{Line: 1, Column: 9},
				},
			},
			expectedTokens: []models.TokenWithSpan{
				{
					Token: models.Token{Type: models.TokenTypeWord, Value: "SELECT"},
					Start: models.Location{Line: 1, Column: 1},
					End:   models.Location{Line: 1, Column: 7},
				},
				{
					Token: models.Token{Type: models.TokenTypeMul, Value: "*"},
					Start: models.Location{Line: 1, Column: 8},
					End:   models.Location{Line: 1, Column: 9},
				},
			},
		},
		{
			name:           "add empty token list",
			sql:            "SELECT * FROM users",
			tokens:         []models.TokenWithSpan{},
			expectedTokens: []models.TokenWithSpan{},
		},
		{
			name:           "add nil token list",
			sql:            "SELECT * FROM users",
			tokens:         nil,
			expectedTokens: nil,
		},
		{
			name: "verify tokens are stored correctly",
			sql:  "INSERT INTO users VALUES (1)",
			tokens: []models.TokenWithSpan{
				{
					Token: models.Token{Type: models.TokenTypeWord, Value: "INSERT"},
					Start: models.Location{Line: 1, Column: 1},
					End:   models.Location{Line: 1, Column: 7},
				},
			},
			expectedTokens: []models.TokenWithSpan{
				{
					Token: models.Token{Type: models.TokenTypeWord, Value: "INSERT"},
					Start: models.Location{Line: 1, Column: 1},
					End:   models.Location{Line: 1, Column: 7},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewContext(tt.sql, "test.sql")
			result := ctx.WithTokens(tt.tokens)

			// Verify method chaining returns the same instance
			if result != ctx {
				t.Error("WithTokens should return the same context instance for chaining")
			}

			// Verify tokens are stored correctly
			if len(ctx.Tokens) != len(tt.expectedTokens) {
				t.Fatalf("Tokens count = %d, want %d", len(ctx.Tokens), len(tt.expectedTokens))
			}

			for i, token := range ctx.Tokens {
				if token.Token.Type != tt.expectedTokens[i].Token.Type {
					t.Errorf("Tokens[%d].Type = %v, want %v", i, token.Token.Type, tt.expectedTokens[i].Token.Type)
				}
				if token.Token.Value != tt.expectedTokens[i].Token.Value {
					t.Errorf("Tokens[%d].Value = %q, want %q", i, token.Token.Value, tt.expectedTokens[i].Token.Value)
				}
			}
		})
	}
}

// TestContext_WithAST tests adding AST and parse errors to the context
func TestContext_WithAST(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		astObj      *ast.AST
		parseErr    error
		expectAST   bool
		expectError bool
	}{
		{
			name:        "add AST without error",
			sql:         "SELECT * FROM users",
			astObj:      &ast.AST{},
			parseErr:    nil,
			expectAST:   true,
			expectError: false,
		},
		{
			name:        "add AST with parse error",
			sql:         "SELECT * FROM",
			astObj:      nil,
			parseErr:    errors.New("unexpected end of input"),
			expectAST:   false,
			expectError: true,
		},
		{
			name:        "add nil AST with error",
			sql:         "INVALID SQL",
			astObj:      nil,
			parseErr:    errors.New("syntax error"),
			expectAST:   false,
			expectError: true,
		},
		{
			name:        "add AST and error both present",
			sql:         "SELECT * FROM users WHERE",
			astObj:      &ast.AST{},
			parseErr:    errors.New("incomplete WHERE clause"),
			expectAST:   true,
			expectError: true,
		},
		{
			name:        "add nil AST without error",
			sql:         "SELECT * FROM users",
			astObj:      nil,
			parseErr:    nil,
			expectAST:   false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewContext(tt.sql, "test.sql")
			result := ctx.WithAST(tt.astObj, tt.parseErr)

			// Verify method chaining returns the same instance
			if result != ctx {
				t.Error("WithAST should return the same context instance for chaining")
			}

			// Verify AST is stored correctly
			if tt.expectAST && ctx.AST == nil {
				t.Error("Expected AST to be set, but it was nil")
			}
			if !tt.expectAST && ctx.AST != nil {
				t.Errorf("Expected AST to be nil, but got %v", ctx.AST)
			}

			// Verify error is stored correctly
			if tt.expectError && ctx.ParseErr == nil {
				t.Error("Expected ParseErr to be set, but it was nil")
			}
			if !tt.expectError && ctx.ParseErr != nil {
				t.Errorf("Expected ParseErr to be nil, but got %v", ctx.ParseErr)
			}

			// Verify error message if present
			if tt.expectError && tt.parseErr != nil {
				if ctx.ParseErr.Error() != tt.parseErr.Error() {
					t.Errorf("ParseErr = %q, want %q", ctx.ParseErr.Error(), tt.parseErr.Error())
				}
			}
		})
	}
}

// TestContext_GetLine tests retrieving specific lines from the context
func TestContext_GetLine(t *testing.T) {
	tests := []struct {
		name         string
		sql          string
		lineNum      int
		expectedLine string
	}{
		{
			name:         "get first line (line 1)",
			sql:          "SELECT *\nFROM users\nWHERE id = 1",
			lineNum:      1,
			expectedLine: "SELECT *",
		},
		{
			name:         "get middle line",
			sql:          "SELECT *\nFROM users\nWHERE id = 1",
			lineNum:      2,
			expectedLine: "FROM users",
		},
		{
			name:         "get last line",
			sql:          "SELECT *\nFROM users\nWHERE id = 1",
			lineNum:      3,
			expectedLine: "WHERE id = 1",
		},
		{
			name:         "get line 0 (out of bounds)",
			sql:          "SELECT *\nFROM users",
			lineNum:      0,
			expectedLine: "",
		},
		{
			name:         "get negative line number",
			sql:          "SELECT *\nFROM users",
			lineNum:      -1,
			expectedLine: "",
		},
		{
			name:         "get line beyond last line",
			sql:          "SELECT *\nFROM users",
			lineNum:      10,
			expectedLine: "",
		},
		{
			name:         "get line from single-line SQL",
			sql:          "SELECT * FROM users WHERE active = true",
			lineNum:      1,
			expectedLine: "SELECT * FROM users WHERE active = true",
		},
		{
			name:         "get line from empty SQL",
			sql:          "",
			lineNum:      1,
			expectedLine: "",
		},
		{
			name: "get line with Unicode content",
			sql: `SELECT name, 価格
FROM 製品
WHERE カテゴリ = '電子機器'`,
			lineNum:      2,
			expectedLine: "FROM 製品",
		},
		{
			name:         "get line with trailing whitespace preserved",
			sql:          "SELECT *   \nFROM users  \nWHERE id = 1",
			lineNum:      1,
			expectedLine: "SELECT *   ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewContext(tt.sql, "test.sql")
			line := ctx.GetLine(tt.lineNum)

			if line != tt.expectedLine {
				t.Errorf("GetLine(%d) = %q, want %q", tt.lineNum, line, tt.expectedLine)
			}
		})
	}
}

// TestContext_GetLineCount tests counting lines in the context
func TestContext_GetLineCount(t *testing.T) {
	tests := []struct {
		name          string
		sql           string
		expectedCount int
	}{
		{
			name: "count lines in multi-line SQL",
			sql: `SELECT id, name
FROM users
WHERE active = true
ORDER BY name`,
			expectedCount: 4,
		},
		{
			name:          "count lines in single-line SQL",
			sql:           "SELECT * FROM users WHERE active = true",
			expectedCount: 1,
		},
		{
			name:          "count lines in empty string",
			sql:           "",
			expectedCount: 1, // Empty string splits to [""]
		},
		{
			name:          "count lines with only newlines",
			sql:           "\n\n\n",
			expectedCount: 4, // Four empty strings
		},
		{
			name:          "count lines with Windows line endings",
			sql:           "SELECT *\r\nFROM users\r\nWHERE id = 1",
			expectedCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewContext(tt.sql, "test.sql")
			count := ctx.GetLineCount()

			if count != tt.expectedCount {
				t.Errorf("GetLineCount() = %d, want %d", count, tt.expectedCount)
			}
		})
	}
}

// TestContext_Integration tests the full workflow of building a context
func TestContext_Integration(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		filename string
	}{
		{
			name:     "full workflow with simple SQL",
			sql:      "SELECT * FROM users",
			filename: "query.sql",
		},
		{
			name: "full workflow with multi-line SQL",
			sql: `SELECT id, name, email
FROM users
WHERE active = true
ORDER BY name`,
			filename: "complex_query.sql",
		},
		{
			name: "full workflow with Unicode SQL",
			sql: `SELECT 名前, 価格
FROM 製品
WHERE カテゴリ = '電子機器'`,
			filename: "unicode_query.sql",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 1: Create context
			ctx := NewContext(tt.sql, tt.filename)
			if ctx.SQL != tt.sql {
				t.Errorf("SQL = %q, want %q", ctx.SQL, tt.sql)
			}
			if ctx.Filename != tt.filename {
				t.Errorf("Filename = %q, want %q", ctx.Filename, tt.filename)
			}

			// Step 2: Add tokens
			tokens := []models.TokenWithSpan{
				{
					Token: models.Token{Type: models.TokenTypeWord, Value: "SELECT"},
					Start: models.Location{Line: 1, Column: 1},
					End:   models.Location{Line: 1, Column: 7},
				},
			}
			result := ctx.WithTokens(tokens)
			if result != ctx {
				t.Error("WithTokens should return the same context instance")
			}
			if len(ctx.Tokens) != 1 {
				t.Errorf("Tokens count = %d, want 1", len(ctx.Tokens))
			}

			// Step 3: Add AST
			astObj := &ast.AST{}
			result = ctx.WithAST(astObj, nil)
			if result != ctx {
				t.Error("WithAST should return the same context instance")
			}
			if ctx.AST == nil {
				t.Error("AST should be set")
			}
			if ctx.ParseErr != nil {
				t.Errorf("ParseErr should be nil, got %v", ctx.ParseErr)
			}

			// Step 4: Verify all fields are populated correctly
			if ctx.SQL != tt.sql {
				t.Errorf("Final SQL = %q, want %q", ctx.SQL, tt.sql)
			}
			if ctx.Filename != tt.filename {
				t.Errorf("Final Filename = %q, want %q", ctx.Filename, tt.filename)
			}
			if len(ctx.Lines) == 0 {
				t.Error("Lines should not be empty")
			}
			if len(ctx.Tokens) == 0 {
				t.Error("Tokens should not be empty")
			}
			if ctx.AST == nil {
				t.Error("AST should not be nil")
			}

			// Step 5: Test method chaining - all in one line
			ctx2 := NewContext(tt.sql, tt.filename).WithTokens(tokens).WithAST(astObj, nil)
			if ctx2.SQL != tt.sql {
				t.Errorf("Chained SQL = %q, want %q", ctx2.SQL, tt.sql)
			}
			if ctx2.AST == nil {
				t.Error("Chained AST should not be nil")
			}
			if len(ctx2.Tokens) == 0 {
				t.Error("Chained Tokens should not be empty")
			}
		})
	}
}
