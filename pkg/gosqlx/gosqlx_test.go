package gosqlx

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		wantErr bool
	}{
		{
			name:    "simple select",
			sql:     "SELECT * FROM users",
			wantErr: false,
		},
		{
			name:    "select with where",
			sql:     "SELECT id, name FROM users WHERE age > 18",
			wantErr: false,
		},
		{
			name:    "insert statement",
			sql:     "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')",
			wantErr: false,
		},
		{
			name:    "update statement",
			sql:     "UPDATE users SET name = 'Jane' WHERE id = 1",
			wantErr: false,
		},
		{
			name:    "delete statement",
			sql:     "DELETE FROM users WHERE id = 1",
			wantErr: false,
		},
		{
			name:    "join query",
			sql:     "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id",
			wantErr: false,
		},
		{
			name:    "window function",
			sql:     "SELECT name, ROW_NUMBER() OVER (ORDER BY salary DESC) as rank FROM employees",
			wantErr: false,
		},
		{
			name:    "CTE query",
			sql:     "WITH cte AS (SELECT * FROM users) SELECT * FROM cte",
			wantErr: false,
		},
		{
			name:    "invalid SQL - missing FROM",
			sql:     "SELECT * users",
			wantErr: true,
		},
		{
			name:    "invalid SQL - unclosed quote",
			sql:     "SELECT * FROM users WHERE name = 'unclosed",
			wantErr: true,
		},
		{
			name:    "empty string",
			sql:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := Parse(tt.sql)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Parse() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Parse() unexpected error: %v", err)
				return
			}

			if ast == nil {
				t.Error("Parse() returned nil AST")
				return
			}

			if len(ast.Statements) == 0 {
				t.Error("Parse() returned AST with no statements")
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		wantErr bool
	}{
		{
			name:    "valid SELECT",
			sql:     "SELECT * FROM users",
			wantErr: false,
		},
		{
			name:    "valid INSERT",
			sql:     "INSERT INTO users (name) VALUES ('test')",
			wantErr: false,
		},
		{
			name:    "valid complex query",
			sql:     "SELECT COUNT(*) FROM orders WHERE status = 'pending' GROUP BY user_id",
			wantErr: false,
		},
		{
			name:    "invalid syntax",
			sql:     "SELEKT * FROM users",
			wantErr: true,
		},
		{
			name:    "invalid - missing table name",
			sql:     "SELECT * FROM",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.sql)

			if tt.wantErr && err == nil {
				t.Errorf("Validate() expected error but got none")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestParseBytes(t *testing.T) {
	sql := []byte("SELECT * FROM users")
	ast, err := ParseBytes(sql)

	if err != nil {
		t.Fatalf("ParseBytes() unexpected error: %v", err)
	}

	if ast == nil {
		t.Fatal("ParseBytes() returned nil AST")
	}

	if len(ast.Statements) == 0 {
		t.Error("ParseBytes() returned AST with no statements")
	}
}

func TestMustParse(t *testing.T) {
	t.Run("valid SQL", func(t *testing.T) {
		// Should not panic
		ast := MustParse("SELECT * FROM users")
		if ast == nil {
			t.Error("MustParse() returned nil")
		}
	})

	t.Run("invalid SQL panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("MustParse() should panic on invalid SQL")
			}
		}()

		MustParse("INVALID SQL")
	})
}

func TestParseMultiple(t *testing.T) {
	t.Run("all valid queries", func(t *testing.T) {
		queries := []string{
			"SELECT * FROM users",
			"SELECT * FROM orders",
			"SELECT * FROM products",
		}

		asts, err := ParseMultiple(queries)
		if err != nil {
			t.Fatalf("ParseMultiple() unexpected error: %v", err)
		}

		if len(asts) != len(queries) {
			t.Errorf("ParseMultiple() returned %d ASTs, want %d", len(asts), len(queries))
		}

		for i, ast := range asts {
			if ast == nil {
				t.Errorf("ParseMultiple() AST %d is nil", i)
			}
			if len(ast.Statements) == 0 {
				t.Errorf("ParseMultiple() AST %d has no statements", i)
			}
		}
	})

	t.Run("one invalid query", func(t *testing.T) {
		queries := []string{
			"SELECT * FROM users",
			"INVALID SQL",
			"SELECT * FROM products",
		}

		_, err := ParseMultiple(queries)
		if err == nil {
			t.Error("ParseMultiple() expected error for invalid SQL")
		}

		// Should mention which query failed
		if !strings.Contains(err.Error(), "query 1") {
			t.Errorf("ParseMultiple() error should mention query index: %v", err)
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		asts, err := ParseMultiple([]string{})
		if err != nil {
			t.Fatalf("ParseMultiple() unexpected error: %v", err)
		}

		if len(asts) != 0 {
			t.Errorf("ParseMultiple() should return empty slice for no queries")
		}
	})
}

func TestValidateMultiple(t *testing.T) {
	t.Run("all valid", func(t *testing.T) {
		queries := []string{
			"SELECT * FROM users",
			"INSERT INTO users (name) VALUES ('test')",
			"UPDATE users SET active = true",
		}

		err := ValidateMultiple(queries)
		if err != nil {
			t.Errorf("ValidateMultiple() unexpected error: %v", err)
		}
	})

	t.Run("one invalid", func(t *testing.T) {
		queries := []string{
			"SELECT * FROM users",
			"INVALID SQL",
		}

		err := ValidateMultiple(queries)
		if err == nil {
			t.Error("ValidateMultiple() expected error")
		}

		// Should mention which query failed
		if !strings.Contains(err.Error(), "query 1") {
			t.Errorf("ValidateMultiple() error should mention query index: %v", err)
		}
	})
}

// Benchmark the convenience API vs lower-level API
func BenchmarkParse(b *testing.B) {
	sql := "SELECT id, name, email FROM users WHERE age > 18"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Parse(sql)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseMultiple(b *testing.B) {
	queries := []string{
		"SELECT * FROM users",
		"SELECT * FROM orders",
		"SELECT * FROM products",
		"SELECT * FROM categories",
		"SELECT * FROM reviews",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseMultiple(queries)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidate(b *testing.B) {
	sql := "SELECT id, name FROM users WHERE age > 18"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := Validate(sql)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Example demonstrating the simple Parse API
func ExampleParse() {
	sql := "SELECT * FROM users WHERE active = true"

	ast, err := Parse(sql)
	if err != nil {
		panic(err)
	}

	// Use the AST
	_ = ast
	// Output:
}

// Example demonstrating SQL validation
func ExampleValidate() {
	if err := Validate("SELECT * FROM users"); err != nil {
		panic(err)
	}

	// Output:
}

// Example demonstrating batch parsing
func ExampleParseMultiple() {
	queries := []string{
		"SELECT * FROM users",
		"SELECT * FROM orders",
	}

	asts, err := ParseMultiple(queries)
	if err != nil {
		panic(err)
	}

	for i, ast := range asts {
		_ = i
		_ = ast
	}

	// Output:
}

func TestFormat(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		options FormatOptions
		wantErr bool
	}{
		{
			name:    "valid SQL with default options",
			sql:     "SELECT * FROM users",
			options: DefaultFormatOptions(),
			wantErr: false,
		},
		{
			name: "add semicolon",
			sql:  "SELECT * FROM users",
			options: FormatOptions{
				AddSemicolon: true,
			},
			wantErr: false,
		},
		{
			name: "complex query",
			sql:  "SELECT u.id, u.name FROM users u JOIN orders o ON u.id = o.user_id WHERE u.active = true",
			options: FormatOptions{
				IndentSize: 4,
			},
			wantErr: false,
		},
		{
			name:    "invalid SQL",
			sql:     "INVALID SQL",
			options: DefaultFormatOptions(),
			wantErr: true,
		},
		{
			name:    "empty SQL",
			sql:     "",
			options: DefaultFormatOptions(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Format(tt.sql, tt.options)

			if tt.wantErr {
				if err == nil {
					t.Error("Format() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Format() unexpected error: %v", err)
				return
			}

			if result == "" {
				t.Error("Format() returned empty string")
			}

			// If AddSemicolon is true, verify semicolon is present
			if tt.options.AddSemicolon && !strings.HasSuffix(strings.TrimSpace(result), ";") {
				t.Error("Format() should add semicolon when requested")
			}
		})
	}
}

func TestDefaultFormatOptions(t *testing.T) {
	opts := DefaultFormatOptions()

	if opts.IndentSize != 2 {
		t.Errorf("DefaultFormatOptions() IndentSize = %d, want 2", opts.IndentSize)
	}

	if opts.UppercaseKeywords != false {
		t.Error("DefaultFormatOptions() UppercaseKeywords should be false")
	}

	if opts.AddSemicolon != false {
		t.Error("DefaultFormatOptions() AddSemicolon should be false")
	}

	if opts.SingleLineLimit != 80 {
		t.Errorf("DefaultFormatOptions() SingleLineLimit = %d, want 80", opts.SingleLineLimit)
	}
}

func BenchmarkFormat(b *testing.B) {
	sql := "SELECT id, name, email FROM users WHERE age > 18"
	opts := DefaultFormatOptions()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Format(sql, opts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Example demonstrating SQL formatting
func ExampleFormat() {
	sql := "SELECT * FROM users WHERE active = true"
	opts := DefaultFormatOptions()
	opts.AddSemicolon = true

	formatted, err := Format(sql, opts)
	if err != nil {
		panic(err)
	}

	_ = formatted
	// Output:
}
