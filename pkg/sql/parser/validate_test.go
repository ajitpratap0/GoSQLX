package parser_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		wantErr bool
	}{
		{"simple select", "SELECT 1", false},
		{"select from", "SELECT * FROM users", false},
		{"insert", "INSERT INTO t(a) VALUES(1)", false},
		{"invalid", "SELECT FROM WHERE", true},
		{"empty", "", false},
		{"multiple statements", "SELECT 1; SELECT 2", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parser.Validate(tt.sql)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate(%q) error = %v, wantErr %v", tt.sql, err, tt.wantErr)
			}
		})
	}
}

func TestValidateBytes(t *testing.T) {
	err := parser.ValidateBytes([]byte("SELECT * FROM users WHERE id = 1"))
	if err != nil {
		t.Fatalf("ValidateBytes failed: %v", err)
	}

	err = parser.ValidateBytes([]byte("SELECT FROM WHERE"))
	if err == nil {
		t.Fatal("ValidateBytes should fail for invalid SQL")
	}
}

func TestParseBytes(t *testing.T) {
	result, err := parser.ParseBytes([]byte("SELECT * FROM users"))
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}
	defer ast.ReleaseAST(result)

	if len(result.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(result.Statements))
	}
}

func TestParseBytesInvalid(t *testing.T) {
	_, err := parser.ParseBytes([]byte("SELECT FROM WHERE"))
	if err == nil {
		t.Fatal("ParseBytes should fail for invalid SQL")
	}
}

func TestParseBytesWithTokens(t *testing.T) {
	result, tokens, err := parser.ParseBytesWithTokens([]byte("SELECT 1"))
	if err != nil {
		t.Fatalf("ParseBytesWithTokens failed: %v", err)
	}
	defer ast.ReleaseAST(result)

	if len(tokens) == 0 {
		t.Fatal("expected tokens")
	}
}

func BenchmarkValidate(b *testing.B) {
	sql := "SELECT u.id, u.name, u.email FROM users u JOIN orders o ON u.id = o.user_id WHERE u.active = true AND o.total > 100 ORDER BY o.created_at DESC LIMIT 50"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parser.Validate(sql)
	}
}

func BenchmarkParseForComparison(b *testing.B) {
	sql := "SELECT u.id, u.name, u.email FROM users u JOIN orders o ON u.id = o.user_id WHERE u.active = true AND o.total > 100 ORDER BY o.created_at DESC LIMIT 50"
	input := []byte(sql)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := parser.ParseBytes(input)
		if err == nil {
			ast.ReleaseAST(result)
		}
	}
}

func BenchmarkParseBytes(b *testing.B) {
	sql := []byte("SELECT u.id, u.name, u.email FROM users u JOIN orders o ON u.id = o.user_id WHERE u.active = true AND o.total > 100 ORDER BY o.created_at DESC LIMIT 50")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := parser.ParseBytes(sql)
		if err == nil {
			ast.ReleaseAST(result)
		}
	}
}

func BenchmarkValidateLargeSQL(b *testing.B) {
	// Build a large SQL query
	var sb strings.Builder
	sb.WriteString("SELECT ")
	for i := 0; i < 100; i++ {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString("col_")
		sb.WriteString(strings.Repeat("x", 5))
	}
	sb.WriteString(" FROM large_table WHERE id > 0")
	sql := sb.String()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parser.Validate(sql)
	}
}
