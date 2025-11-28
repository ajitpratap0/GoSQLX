package cmd

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// TestSQLFormatter_BasicFormatting tests basic formatter functionality
func TestSQLFormatter_BasicFormatting(t *testing.T) {
	tests := []struct {
		name           string
		sql            string
		indentSpaces   int
		uppercase      bool
		expectKeywords []string
		shouldSkip     bool
	}{
		{
			name:           "simple SELECT with default options",
			sql:            "SELECT id, name FROM users WHERE active = true",
			indentSpaces:   2,
			uppercase:      false,
			expectKeywords: []string{"select", "from", "where"},
		},
		{
			name:           "SELECT with uppercase keywords",
			sql:            "select id from users",
			indentSpaces:   2,
			uppercase:      true,
			expectKeywords: []string{"SELECT", "FROM"},
		},
		{
			name:           "SELECT with different indent",
			sql:            "SELECT id FROM users",
			indentSpaces:   4,
			uppercase:      false,
			expectKeywords: []string{"select", "from"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldSkip {
				t.Skip("Skipping due to parser limitations")
			}

			// Tokenize and parse
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("Tokenization failed: %v", err)
			}

			convertedTokens, err := parser.ConvertTokensForParser(tokens)
			if err != nil {
				t.Fatalf("Token conversion failed: %v", err)
			}

			p := parser.NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.Parse(convertedTokens)
			if err != nil {
				t.Skipf("Parsing failed (may not be supported yet): %v", err)
				return
			}
			astObj.Statements = result.Statements

			// Format the AST
			indent := strings.Repeat(" ", tt.indentSpaces)
			formatter := NewSQLFormatter(FormatterOptions{
				Indent:      indent,
				UppercaseKw: tt.uppercase,
			})

			output, err := formatter.Format(astObj)
			if err != nil {
				t.Fatalf("Formatting failed: %v", err)
			}

			// Verify expected keywords are present
			for _, keyword := range tt.expectKeywords {
				if !strings.Contains(output, keyword) {
					t.Errorf("Expected keyword '%s' not found in output:\n%s", keyword, output)
				}
			}

			// Basic sanity checks
			if output == "" {
				t.Error("Formatter produced empty output")
			}
		})
	}
}

// TestSQLFormatter_JOINStatements tests JOIN formatting
func TestSQLFormatter_JOINStatements(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		expectWords []string
	}{
		{
			name:        "INNER JOIN",
			sql:         "SELECT u.name, o.total FROM users u INNER JOIN orders o ON u.id = o.user_id",
			expectWords: []string{"select", "from", "inner join", "on"},
		},
		{
			name:        "LEFT JOIN",
			sql:         "SELECT u.name, o.total FROM users u LEFT JOIN orders o ON u.id = o.user_id",
			expectWords: []string{"select", "from", "left join", "on"},
		},
		{
			name:        "Multiple JOINs",
			sql:         "SELECT u.name FROM users u INNER JOIN orders o ON u.id = o.user_id LEFT JOIN products p ON o.product_id = p.id",
			expectWords: []string{"select", "from", "inner join", "left join"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("Tokenization failed: %v", err)
			}

			convertedTokens, err := parser.ConvertTokensForParser(tokens)
			if err != nil {
				t.Fatalf("Token conversion failed: %v", err)
			}

			p := parser.NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.Parse(convertedTokens)
			if err != nil {
				t.Skipf("Parsing failed (may not be supported yet): %v", err)
				return
			}
			astObj.Statements = result.Statements

			formatter := NewSQLFormatter(FormatterOptions{
				Indent:      "  ",
				UppercaseKw: false,
			})

			output, err := formatter.Format(astObj)
			if err != nil {
				t.Fatalf("Formatting failed: %v", err)
			}

			for _, word := range tt.expectWords {
				if !strings.Contains(strings.ToLower(output), word) {
					t.Errorf("Expected '%s' in output:\n%s", word, output)
				}
			}
		})
	}
}

// TestSQLFormatter_WithClauses tests CTE (WITH clause) formatting
func TestSQLFormatter_WithClauses(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		expectWords []string
	}{
		{
			name:        "simple WITH clause",
			sql:         "WITH temp AS (SELECT id FROM users) SELECT * FROM temp",
			expectWords: []string{"with", "as", "select"},
		},
		{
			name:        "recursive CTE",
			sql:         "WITH RECURSIVE cte AS (SELECT 1 as n UNION ALL SELECT n + 1 FROM cte WHERE n < 10) SELECT * FROM cte",
			expectWords: []string{"with", "recursive", "as", "union"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("Tokenization failed: %v", err)
			}

			convertedTokens, err := parser.ConvertTokensForParser(tokens)
			if err != nil {
				t.Fatalf("Token conversion failed: %v", err)
			}

			p := parser.NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.Parse(convertedTokens)
			if err != nil {
				t.Skipf("Parsing failed (may not be supported yet): %v", err)
				return
			}
			astObj.Statements = result.Statements

			formatter := NewSQLFormatter(FormatterOptions{
				Indent:      "  ",
				UppercaseKw: false,
			})

			output, err := formatter.Format(astObj)
			if err != nil {
				t.Fatalf("Formatting failed: %v", err)
			}

			for _, word := range tt.expectWords {
				if !strings.Contains(strings.ToLower(output), word) {
					t.Errorf("Expected '%s' in output:\n%s", word, output)
				}
			}
		})
	}
}

// TestSQLFormatter_WindowFunctions tests window function formatting
func TestSQLFormatter_WindowFunctions(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		expectWords []string
	}{
		{
			name:        "ROW_NUMBER with OVER",
			sql:         "SELECT name, ROW_NUMBER() OVER (ORDER BY salary DESC) as rank FROM employees",
			expectWords: []string{"select", "over", "order by"},
		},
		{
			name:        "RANK with PARTITION BY",
			sql:         "SELECT dept, name, RANK() OVER (PARTITION BY dept ORDER BY salary) FROM employees",
			expectWords: []string{"select", "over", "partition by", "order by"},
		},
		{
			name:        "Window frame",
			sql:         "SELECT date, SUM(amount) OVER (ORDER BY date ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) FROM transactions",
			expectWords: []string{"select", "over", "order by", "rows", "between"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("Tokenization failed: %v", err)
			}

			convertedTokens, err := parser.ConvertTokensForParser(tokens)
			if err != nil {
				t.Fatalf("Token conversion failed: %v", err)
			}

			p := parser.NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.Parse(convertedTokens)
			if err != nil {
				t.Skipf("Parsing failed (may not be supported yet): %v", err)
				return
			}
			astObj.Statements = result.Statements

			formatter := NewSQLFormatter(FormatterOptions{
				Indent:      "  ",
				UppercaseKw: false,
			})

			output, err := formatter.Format(astObj)
			if err != nil {
				t.Fatalf("Formatting failed: %v", err)
			}

			for _, word := range tt.expectWords {
				if !strings.Contains(strings.ToLower(output), word) {
					t.Errorf("Expected '%s' in output:\n%s", word, output)
				}
			}
		})
	}
}

// TestSQLFormatter_InsertStatements tests INSERT formatting
func TestSQLFormatter_InsertStatements(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		expectWords []string
	}{
		{
			name:        "basic INSERT",
			sql:         "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')",
			expectWords: []string{"insert", "into", "values"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("Tokenization failed: %v", err)
			}

			convertedTokens, err := parser.ConvertTokensForParser(tokens)
			if err != nil {
				t.Fatalf("Token conversion failed: %v", err)
			}

			p := parser.NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.Parse(convertedTokens)
			if err != nil {
				t.Skipf("Parsing failed (may not be supported yet): %v", err)
				return
			}
			astObj.Statements = result.Statements

			formatter := NewSQLFormatter(FormatterOptions{
				Indent:      "  ",
				UppercaseKw: false,
			})

			output, err := formatter.Format(astObj)
			if err != nil {
				t.Fatalf("Formatting failed: %v", err)
			}

			for _, word := range tt.expectWords {
				if !strings.Contains(strings.ToLower(output), word) {
					t.Errorf("Expected '%s' in output:\n%s", word, output)
				}
			}
		})
	}
}

// TestSQLFormatter_DDLStatements tests DDL statement formatting
func TestSQLFormatter_DDLStatements(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		expectWords []string
	}{
		{
			name:        "CREATE TABLE",
			sql:         "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100))",
			expectWords: []string{"create", "table"},
		},
		{
			name:        "ALTER TABLE",
			sql:         "ALTER TABLE users ADD COLUMN email VARCHAR(255)",
			expectWords: []string{"alter", "table"},
		},
		{
			name:        "DROP TABLE",
			sql:         "DROP TABLE temp_data",
			expectWords: []string{"drop", "table"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("Tokenization failed: %v", err)
			}

			convertedTokens, err := parser.ConvertTokensForParser(tokens)
			if err != nil {
				t.Fatalf("Token conversion failed: %v", err)
			}

			p := parser.NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.Parse(convertedTokens)
			if err != nil {
				t.Skipf("Parsing failed (may not be supported yet): %v", err)
				return
			}
			astObj.Statements = result.Statements

			formatter := NewSQLFormatter(FormatterOptions{
				Indent:      "  ",
				UppercaseKw: false,
			})

			output, err := formatter.Format(astObj)
			if err != nil {
				t.Fatalf("Formatting failed: %v", err)
			}

			for _, word := range tt.expectWords {
				if !strings.Contains(strings.ToLower(output), word) {
					t.Errorf("Expected '%s' in output:\n%s", word, output)
				}
			}
		})
	}
}

// TestSQLFormatter_ComplexExpressions tests complex expression formatting
func TestSQLFormatter_ComplexExpressions(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		expectWords []string
	}{
		{
			name:        "nested expressions",
			sql:         "SELECT (a + b) * (c - d) FROM table1",
			expectWords: []string{"select", "from"},
		},
		{
			name:        "CASE expression",
			sql:         "SELECT CASE WHEN x > 10 THEN 'high' ELSE 'low' END FROM table1",
			expectWords: []string{"select", "case", "when", "then", "else", "end"},
		},
		{
			name:        "IN list",
			sql:         "SELECT * FROM users WHERE status IN ('active', 'pending')",
			expectWords: []string{"select", "from", "where", "in"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("Tokenization failed: %v", err)
			}

			convertedTokens, err := parser.ConvertTokensForParser(tokens)
			if err != nil {
				t.Fatalf("Token conversion failed: %v", err)
			}

			p := parser.NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.Parse(convertedTokens)
			if err != nil {
				t.Skipf("Parsing failed (may not be supported yet): %v", err)
				return
			}
			astObj.Statements = result.Statements

			formatter := NewSQLFormatter(FormatterOptions{
				Indent:      "  ",
				UppercaseKw: false,
			})

			output, err := formatter.Format(astObj)
			if err != nil {
				t.Fatalf("Formatting failed: %v", err)
			}

			for _, word := range tt.expectWords {
				if !strings.Contains(strings.ToLower(output), word) {
					t.Errorf("Expected '%s' in output:\n%s", word, output)
				}
			}
		})
	}
}

// TestSQLFormatter_ErrorHandling tests error handling
func TestSQLFormatter_ErrorHandling(t *testing.T) {
	t.Run("empty AST", func(t *testing.T) {
		formatter := NewSQLFormatter(FormatterOptions{
			Indent: "  ",
		})

		astObj := ast.NewAST()
		defer ast.ReleaseAST(astObj)

		output, err := formatter.Format(astObj)
		// Empty AST should produce empty output or error
		if err == nil && output != "" {
			t.Errorf("Expected empty output for empty AST, got: %s", output)
		}
	})
}

// TestSQLFormatter_Options tests different formatter options
func TestSQLFormatter_Options(t *testing.T) {
	sql := "SELECT id, name FROM users WHERE active = true"

	t.Run("different indent sizes", func(t *testing.T) {
		indentSizes := []int{2, 4, 8}

		for _, indentSize := range indentSizes {
			tkz := tokenizer.GetTokenizer()
			tokens, _ := tkz.Tokenize([]byte(sql))
			convertedTokens, _ := parser.ConvertTokensForParser(tokens)
			p := parser.NewParser()
			astObj := ast.NewAST()
			result, err := p.Parse(convertedTokens)
			if err != nil {
				tokenizer.PutTokenizer(tkz)
				ast.ReleaseAST(astObj)
				t.Skip("Parser not fully supported")
				return
			}
			astObj.Statements = result.Statements

			indent := strings.Repeat(" ", indentSize)
			formatter := NewSQLFormatter(FormatterOptions{
				Indent:      indent,
				UppercaseKw: false,
			})
			output, _ := formatter.Format(astObj)

			tokenizer.PutTokenizer(tkz)
			ast.ReleaseAST(astObj)

			if output == "" {
				t.Errorf("Formatter with indent=%d produced empty output", indentSize)
			}
		}
	})

	t.Run("uppercase vs lowercase", func(t *testing.T) {
		for _, uppercase := range []bool{true, false} {
			tkz := tokenizer.GetTokenizer()
			tokens, _ := tkz.Tokenize([]byte(sql))
			convertedTokens, _ := parser.ConvertTokensForParser(tokens)
			p := parser.NewParser()
			astObj := ast.NewAST()
			result, err := p.Parse(convertedTokens)
			if err != nil {
				tokenizer.PutTokenizer(tkz)
				ast.ReleaseAST(astObj)
				t.Skip("Parser not fully supported")
				return
			}
			astObj.Statements = result.Statements

			formatter := NewSQLFormatter(FormatterOptions{
				Indent:      "  ",
				UppercaseKw: uppercase,
			})
			output, _ := formatter.Format(astObj)

			tokenizer.PutTokenizer(tkz)
			ast.ReleaseAST(astObj)

			if uppercase {
				if !strings.Contains(output, "SELECT") {
					t.Error("Expected uppercase keywords with uppercase=true")
				}
			} else {
				if !strings.Contains(output, "select") {
					t.Error("Expected lowercase keywords with uppercase=false")
				}
			}
		}
	})
}
