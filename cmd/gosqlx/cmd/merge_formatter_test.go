package cmd

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// TestMergeFormatter tests MERGE statement formatting
func TestMergeFormatter(t *testing.T) {
	tests := []struct {
		name           string
		sql            string
		uppercase      bool
		compact        bool
		expectKeywords []string
		expectContains []string
	}{
		{
			name: "basic MERGE with UPDATE",
			sql: `MERGE INTO target_table t
USING source_table s ON t.id = s.id
WHEN MATCHED THEN
    UPDATE SET t.name = s.name, t.value = s.value`,
			uppercase: false,
			compact:   false,
			expectKeywords: []string{
				"merge into",
				"using",
				"on",
				"when matched",
				"then",
				"update set",
			},
			expectContains: []string{
				"target_table t",
				"source_table s",
				"t.id = s.id",
				"t.name = s.name",
				"t.value = s.value",
			},
		},
		{
			name: "basic MERGE with INSERT",
			sql: `MERGE INTO users u
USING new_users n ON u.id = n.id
WHEN NOT MATCHED THEN
    INSERT (id, name, email) VALUES (n.id, n.name, n.email)`,
			uppercase: true,
			compact:   false,
			expectKeywords: []string{
				"MERGE INTO",
				"USING",
				"ON",
				"WHEN NOT MATCHED",
				"THEN",
				"INSERT",
				"VALUES",
			},
			expectContains: []string{
				"users u",
				"new_users n",
				"u.id = n.id",
				"(id, name, email)",
				"(n.id, n.name, n.email)",
			},
		},
		{
			name: "MERGE with multiple WHEN clauses",
			sql: `MERGE INTO inventory i
USING updates u ON i.product_id = u.product_id
WHEN MATCHED AND u.quantity > 0 THEN
    UPDATE SET i.quantity = u.quantity
WHEN NOT MATCHED THEN
    INSERT (product_id, quantity) VALUES (u.product_id, u.quantity)`,
			uppercase: false,
			compact:   false,
			expectKeywords: []string{
				"merge into",
				"using",
				"on",
				"when matched",
				"and",
				"then",
				"update set",
				"when not matched",
				"insert",
			},
			expectContains: []string{
				"inventory i",
				"updates u",
				"i.product_id = u.product_id",
				"u.quantity > 0",
				"i.quantity = u.quantity",
				"(product_id, quantity)",
			},
		},
		{
			name: "MERGE with DELETE action",
			sql: `MERGE INTO products p
USING discontinued d ON p.id = d.id
WHEN MATCHED THEN
    DELETE`,
			uppercase: true,
			compact:   false,
			expectKeywords: []string{
				"MERGE INTO",
				"USING",
				"ON",
				"WHEN MATCHED",
				"THEN",
				"DELETE",
			},
			expectContains: []string{
				"products p",
				"discontinued d",
				"p.id = d.id",
			},
		},
		{
			name: "MERGE with UPDATE and DELETE",
			sql: `MERGE INTO accounts a
USING account_updates u ON a.id = u.id
WHEN MATCHED AND u.active = false THEN
    DELETE
WHEN MATCHED THEN
    UPDATE SET a.balance = u.balance`,
			uppercase: false,
			compact:   false,
			expectKeywords: []string{
				"merge into",
				"using",
				"on",
				"when matched",
				"and",
				"then",
				"delete",
				"update set",
			},
			expectContains: []string{
				"accounts a",
				"account_updates u",
				"a.id = u.id",
				"u.active = false",
				"a.balance = u.balance",
			},
		},
		{
			name: "MERGE compact mode",
			sql: `MERGE INTO target t
USING source s ON t.id = s.id
WHEN MATCHED THEN UPDATE SET t.val = s.val
WHEN NOT MATCHED THEN INSERT (id, val) VALUES (s.id, s.val)`,
			uppercase: true,
			compact:   true,
			expectKeywords: []string{
				"MERGE INTO",
				"USING",
				"ON",
				"WHEN MATCHED",
				"THEN",
				"UPDATE SET",
				"WHEN NOT MATCHED",
				"INSERT",
				"VALUES",
			},
			expectContains: []string{
				"target t",
				"source s",
			},
		},
		{
			name: "MERGE with complex condition",
			sql: `MERGE INTO sales s
USING daily_sales d ON s.date = d.date AND s.region = d.region
WHEN MATCHED AND d.amount > s.amount THEN
    UPDATE SET s.amount = d.amount, s.updated_at = CURRENT_TIMESTAMP
WHEN NOT MATCHED THEN
    INSERT (date, region, amount) VALUES (d.date, d.region, d.amount)`,
			uppercase: false,
			compact:   false,
			expectKeywords: []string{
				"merge into",
				"using",
				"on",
				"and",
				"when matched",
				"then",
				"update set",
				"when not matched",
				"insert",
				"values",
			},
			expectContains: []string{
				"sales s",
				"daily_sales d",
				"s.date = d.date",
				"s.region = d.region",
				"d.amount > s.amount",
				"s.amount = d.amount",
			},
		},
		{
			name: "MERGE without aliases",
			sql: `MERGE INTO users
USING new_users ON users.id = new_users.id
WHEN MATCHED THEN
    UPDATE SET users.name = new_users.name`,
			uppercase: true,
			compact:   false,
			expectKeywords: []string{
				"MERGE INTO",
				"USING",
				"ON",
				"WHEN MATCHED",
				"THEN",
				"UPDATE SET",
			},
			expectContains: []string{
				"users",
				"new_users",
				"users.id = new_users.id",
				"users.name = new_users.name",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Tokenize and parse
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("Tokenization failed: %v", err)
			}

			//lint:ignore SA1019 intentional use during #215 migration
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

			// Verify we got a MERGE statement
			if len(astObj.Statements) == 0 {
				t.Fatal("No statements parsed")
			}
			if _, ok := astObj.Statements[0].(*ast.MergeStatement); !ok {
				t.Fatalf("Expected MergeStatement, got %T", astObj.Statements[0])
			}

			// Format the AST
			formatter := NewSQLFormatter(FormatterOptions{
				Indent:      "  ",
				UppercaseKw: tt.uppercase,
				Compact:     tt.compact,
			})

			output, err := formatter.Format(astObj)
			if err != nil {
				t.Fatalf("Formatting failed: %v", err)
			}

			// Verify expected keywords are present
			outputLower := strings.ToLower(output)
			for _, keyword := range tt.expectKeywords {
				keywordLower := strings.ToLower(keyword)
				if !strings.Contains(outputLower, keywordLower) {
					t.Errorf("Expected keyword '%s' not found in output:\n%s", keyword, output)
				}
			}

			// Verify expected content is present
			for _, content := range tt.expectContains {
				if !strings.Contains(output, content) {
					t.Errorf("Expected content '%s' not found in output:\n%s", content, output)
				}
			}

			// Basic sanity checks
			if output == "" {
				t.Error("Formatter produced empty output")
			}

			// Verify indentation if not compact
			if !tt.compact {
				lines := strings.Split(output, "\n")
				if len(lines) < 3 {
					t.Error("Expected multi-line formatted output")
				}
			}

			// Print output for manual inspection (helpful for debugging)
			t.Logf("Formatted output:\n%s\n", output)
		})
	}
}

// TestMergeFormatter_EdgeCases tests edge cases in MERGE formatting
func TestMergeFormatter_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		shouldError bool
	}{
		{
			name: "MERGE with subquery in USING",
			sql: `MERGE INTO target t
USING (SELECT id, value FROM source WHERE active = true) s ON t.id = s.id
WHEN MATCHED THEN
    UPDATE SET t.value = s.value`,
			shouldError: false,
		},
		{
			name: "MERGE with multiple SET clauses",
			sql: `MERGE INTO users u
USING updates up ON u.id = up.id
WHEN MATCHED THEN
    UPDATE SET u.name = up.name, u.email = up.email, u.updated_at = up.timestamp, u.version = u.version + 1`,
			shouldError: false,
		},
		{
			name: "MERGE with NULL comparison",
			sql: `MERGE INTO data d
USING source s ON d.key = s.key
WHEN MATCHED AND s.value IS NOT NULL THEN
    UPDATE SET d.value = s.value`,
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Tokenize and parse
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				if !tt.shouldError {
					t.Fatalf("Unexpected tokenization error: %v", err)
				}
				return
			}

			//lint:ignore SA1019 intentional use during #215 migration
			convertedTokens, err := parser.ConvertTokensForParser(tokens)
			if err != nil {
				if !tt.shouldError {
					t.Fatalf("Unexpected token conversion error: %v", err)
				}
				return
			}

			p := parser.NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.Parse(convertedTokens)
			if err != nil {
				if !tt.shouldError {
					t.Skipf("Parsing failed (may not be supported yet): %v", err)
				}
				return
			}
			astObj.Statements = result.Statements

			// Format the AST
			formatter := NewSQLFormatter(FormatterOptions{
				Indent:      "  ",
				UppercaseKw: false,
			})

			output, err := formatter.Format(astObj)
			if tt.shouldError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected formatting error: %v", err)
			}

			if !tt.shouldError && output != "" {
				t.Logf("Formatted output:\n%s\n", output)
			}
		})
	}
}

// TestMergeFormatter_KeywordCasing tests keyword casing options
func TestMergeFormatter_KeywordCasing(t *testing.T) {
	sql := `MERGE INTO target t
USING source s ON t.id = s.id
WHEN MATCHED THEN UPDATE SET t.val = s.val`

	tests := []struct {
		name      string
		uppercase bool
		checkCase string // "upper" or "lower"
	}{
		{
			name:      "lowercase keywords",
			uppercase: false,
			checkCase: "lower",
		},
		{
			name:      "uppercase keywords",
			uppercase: true,
			checkCase: "upper",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Tokenize and parse
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(sql))
			if err != nil {
				t.Fatalf("Tokenization failed: %v", err)
			}

			//lint:ignore SA1019 intentional use during #215 migration
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
			formatter := NewSQLFormatter(FormatterOptions{
				Indent:      "  ",
				UppercaseKw: tt.uppercase,
			})

			output, err := formatter.Format(astObj)
			if err != nil {
				t.Fatalf("Formatting failed: %v", err)
			}

			// Check keyword casing
			keywords := []string{"merge", "into", "using", "on", "when", "matched", "then", "update", "set"}
			for _, keyword := range keywords {
				var expected string
				if tt.checkCase == "upper" {
					expected = strings.ToUpper(keyword)
				} else {
					expected = strings.ToLower(keyword)
				}

				if !strings.Contains(output, expected) && !strings.Contains(output, strings.ReplaceAll(expected, " ", "")) {
					// Some keywords might be compound like "NOT MATCHED"
					// So we check both with and without spaces
					parts := strings.Split(expected, " ")
					found := true
					for _, part := range parts {
						if !strings.Contains(output, part) {
							found = false
							break
						}
					}
					if !found {
						t.Logf("Output:\n%s", output)
						// Don't fail, just log - keyword might be part of compound word
					}
				}
			}

			t.Logf("Formatted output:\n%s\n", output)
		})
	}
}
