// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

			p := parser.NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.ParseFromModelTokens(tokens)
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

			p := parser.NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.ParseFromModelTokens(tokens)
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

			p := parser.NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.ParseFromModelTokens(tokens)
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
		rejectWords []string
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
			expectWords: []string{"select", "over", "order by", "rows", "between", "2 preceding", "current row"},
		},
		{
			name:        "Window frame single bound",
			sql:         "SELECT date, SUM(amount) OVER (ORDER BY date ROWS 3 PRECEDING) FROM transactions",
			expectWords: []string{"select", "over", "order by", "rows", "3 preceding"},
			rejectWords: []string{"between"},
		},
		{
			name:        "Window frame GROUPS with EXCLUDE (#609)",
			sql:         "SELECT date, SUM(amount) OVER (ORDER BY date GROUPS BETWEEN 1 PRECEDING AND CURRENT ROW EXCLUDE TIES) FROM transactions",
			expectWords: []string{"groups", "between", "1 preceding", "current row", "exclude ties"},
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

			p := parser.NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.ParseFromModelTokens(tokens)
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

			lower := strings.ToLower(output)
			for _, word := range tt.expectWords {
				if !strings.Contains(lower, word) {
					t.Errorf("Expected '%s' in output:\n%s", word, output)
				}
			}
			for _, word := range tt.rejectWords {
				if strings.Contains(lower, word) {
					t.Errorf("Did not expect '%s' in output:\n%s", word, output)
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

			p := parser.NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.ParseFromModelTokens(tokens)
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

			p := parser.NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.ParseFromModelTokens(tokens)
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

			p := parser.NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.ParseFromModelTokens(tokens)
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
			p := parser.NewParser()
			astObj := ast.NewAST()
			result, err := p.ParseFromModelTokens(tokens)
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
			p := parser.NewParser()
			astObj := ast.NewAST()
			result, err := p.ParseFromModelTokens(tokens)
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

// Regression for #519: the CLI formatter must render grouping parentheses
// instead of falling back to the node's TokenLiteral ("PAREN").
func TestSQLFormatter_ParenthesizedExpression(t *testing.T) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.Tokenize([]byte("SELECT (a + b) * c FROM t WHERE (a = 1 OR b = 2) AND c = 3"))
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}
	p := parser.NewParser()
	defer p.Release()
	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer ast.ReleaseAST(tree)

	out, err := NewSQLFormatter(FormatterOptions{Indent: "  ", UppercaseKw: true}).Format(tree)
	if err != nil {
		t.Fatalf("format: %v", err)
	}
	if strings.Contains(out, "PAREN") {
		t.Fatalf("formatter emitted placeholder PAREN:\n%s", out)
	}
	for _, want := range []string{"(a + b) * c", "(a = 1 OR b = 2) AND c = 3"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestSQLFormatter_NotExistsDoesNotPanic covers NOT EXISTS (subquery), which the parser
// represents as a NOT with the EXISTS on the left and no right operand.
func TestSQLFormatter_NotExistsDoesNotPanic(t *testing.T) {
	sql := "SELECT a FROM t WHERE NOT EXISTS (SELECT 1 FROM u WHERE u.id = t.id)"
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Tokenization failed: %v", err)
	}

	p := parser.NewParser()
	astObj := ast.NewAST()
	defer ast.ReleaseAST(astObj)
	result, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Parsing failed: %v", err)
	}
	astObj.Statements = result.Statements

	formatter := NewSQLFormatter(FormatterOptions{Indent: "  ", UppercaseKw: true})
	output, err := formatter.Format(astObj)
	if err != nil {
		t.Fatalf("Formatting failed: %v", err)
	}
	if !strings.Contains(output, "NOT EXISTS (") {
		t.Errorf("expected NOT EXISTS in output, got:\n%s", output)
	}
}

// TestSQLFormatter_InsertWithCTE_Issue537 checks that the CLI formatter keeps
// the WITH clause of INSERT ... SELECT, whether it is written after the column
// list (#537) or before INSERT.
func TestSQLFormatter_InsertWithCTE_Issue537(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		wantCompact string
	}{
		{
			name:        "inner WITH after column list",
			sql:         "INSERT INTO test(a, b) WITH main AS (SELECT a, b FROM src) SELECT a, b FROM main",
			wantCompact: "INSERT INTO test (a, b) WITH main AS (SELECT a, b FROM src) SELECT a, b FROM main",
		},
		{
			name:        "leading WITH before INSERT",
			sql:         "WITH main AS (SELECT a, b FROM src) INSERT INTO test(a, b) SELECT a, b FROM main",
			wantCompact: "WITH main AS (SELECT a, b FROM src) INSERT INTO test (a, b) SELECT a, b FROM main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)
			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("tokenize(%q): %v", tt.sql, err)
			}
			p := parser.NewParser()
			defer p.Release()
			tree, err := p.ParseFromModelTokens(tokens)
			if err != nil {
				t.Fatalf("parse(%q): %v", tt.sql, err)
			}
			defer ast.ReleaseAST(tree)

			compact, err := NewSQLFormatter(FormatterOptions{Compact: true, UppercaseKw: true}).Format(tree)
			if err != nil {
				t.Fatalf("compact format: %v", err)
			}
			if compact != tt.wantCompact {
				t.Errorf("compact output:\n got: %s\nwant: %s", compact, tt.wantCompact)
			}

			readable, err := NewSQLFormatter(FormatterOptions{Indent: "  ", UppercaseKw: true}).Format(tree)
			if err != nil {
				t.Fatalf("readable format: %v", err)
			}
			for _, want := range []string{"WITH main AS", "FROM src", "INSERT INTO test"} {
				if !strings.Contains(readable, want) {
					t.Errorf("expected %q in readable output:\n%s", want, readable)
				}
			}
		})
	}
}

// TestSQLFormatter_WithCTEChainedSetOperations checks that the CLI formatter
// keeps the WITH clause exactly once for CTE queries with chained set
// operators, at top level and under INSERT.
func TestSQLFormatter_WithCTEChainedSetOperations(t *testing.T) {
	inputs := []string{
		"WITH c AS (SELECT 1 AS a) SELECT a FROM c UNION SELECT 2 UNION SELECT 3",
		"WITH c AS (SELECT 1 AS a) SELECT a FROM c INTERSECT SELECT 2 INTERSECT SELECT 3",
		"WITH c AS (SELECT 1 AS a) SELECT a FROM c EXCEPT SELECT 2 EXCEPT SELECT 3",
		"INSERT INTO t (a) WITH c AS (SELECT 1 AS a) SELECT a FROM c UNION ALL SELECT 2 UNION ALL SELECT 3",
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)
			tokens, err := tkz.Tokenize([]byte(in))
			if err != nil {
				t.Fatalf("tokenize: %v", err)
			}
			p := parser.NewParser()
			defer p.Release()
			tree, err := p.ParseFromModelTokens(tokens)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			defer ast.ReleaseAST(tree)

			for name, opts := range map[string]FormatterOptions{
				"compact":  {Compact: true, UppercaseKw: true},
				"readable": {Indent: "  ", UppercaseKw: true},
			} {
				out, err := NewSQLFormatter(opts).Format(tree)
				if err != nil {
					t.Fatalf("%s format: %v", name, err)
				}
				if n := strings.Count(out, "WITH "); n != 1 {
					t.Errorf("%s output has %d WITH clauses, want 1:\n%s", name, n, out)
				}
				if !strings.Contains(out, "c AS (") {
					t.Errorf("%s output lost the CTE:\n%s", name, out)
				}
			}
		})
	}
}

// TestSQLFormatter_UpdateDeleteWithCTE checks that the CLI formatter keeps a
// leading WITH clause on UPDATE and DELETE, as it does for INSERT (#537).
func TestSQLFormatter_UpdateDeleteWithCTE(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		kw   string
	}{
		{
			name: "update",
			sql:  "WITH c AS (SELECT id FROM s) UPDATE t SET a = 1 WHERE id IN (SELECT id FROM c)",
			kw:   "UPDATE t",
		},
		{
			name: "delete",
			sql:  "WITH c AS (SELECT id FROM s) DELETE FROM t WHERE id IN (SELECT id FROM c)",
			kw:   "DELETE FROM t",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)
			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("tokenize(%q): %v", tt.sql, err)
			}
			p := parser.NewParser()
			defer p.Release()
			tree, err := p.ParseFromModelTokens(tokens)
			if err != nil {
				t.Fatalf("parse(%q): %v", tt.sql, err)
			}
			defer ast.ReleaseAST(tree)

			compact, err := NewSQLFormatter(FormatterOptions{Compact: true, UppercaseKw: true}).Format(tree)
			if err != nil {
				t.Fatalf("compact format: %v", err)
			}
			if compact != tt.sql {
				t.Errorf("compact output:\n got: %s\nwant: %s", compact, tt.sql)
			}

			readable, err := NewSQLFormatter(FormatterOptions{Indent: "  ", UppercaseKw: true}).Format(tree)
			if err != nil {
				t.Fatalf("readable format: %v", err)
			}
			w, k := strings.Index(readable, "WITH c AS"), strings.Index(readable, tt.kw)
			if w < 0 || k < 0 || w > k {
				t.Errorf("expected WITH c AS before %q in readable output:\n%s", tt.kw, readable)
			}
		})
	}
}
