package parser

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// helper to parse SQL and return error
func parseSQLCheck(t *testing.T, sql string) error {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenize error for %q: %v", sql, err)
	}
	p := GetParser()
	defer PutParser(p)
	_, err = p.ParseFromModelTokens(tokens)
	return err
}

func parseSQLStrict(t *testing.T, sql string) error {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenize error for %q: %v", sql, err)
	}
	p := NewParser(WithStrictMode())
	_, err = p.ParseFromModelTokens(tokens)
	return err
}

// =============================================================================
// Issue #296 — Parser rejects malformed SQL with descriptive errors
// =============================================================================

func TestMalformedSQL_SelectFromWithoutColumns(t *testing.T) {
	err := parseSQLCheck(t, "SELECT FROM users")
	if err == nil {
		t.Fatal("expected error for 'SELECT FROM users', got nil")
	}
	if !strings.Contains(err.Error(), "column expression") {
		t.Errorf("expected error about column expression, got: %v", err)
	}
}

func TestMalformedSQL_IncompleteWhere(t *testing.T) {
	err := parseSQLCheck(t, "SELECT * FROM users WHERE")
	if err == nil {
		t.Fatal("expected error for 'SELECT * FROM users WHERE', got nil")
	}
	if !strings.Contains(err.Error(), "expression after WHERE") {
		t.Errorf("expected error about expression after WHERE, got: %v", err)
	}
}

func TestMalformedSQL_SelectFromNoTable(t *testing.T) {
	err := parseSQLCheck(t, "SELECT * FROM")
	if err == nil {
		t.Fatal("expected error for 'SELECT * FROM', got nil")
	}
	if !strings.Contains(err.Error(), "table name") {
		t.Errorf("expected error about table name, got: %v", err)
	}
}

func TestMalformedSQL_WhereWithSemicolon(t *testing.T) {
	err := parseSQLCheck(t, "SELECT * FROM t WHERE;")
	if err == nil {
		t.Fatal("expected error for incomplete WHERE with semicolon")
	}
	if !strings.Contains(err.Error(), "expression after WHERE") {
		t.Errorf("expected error about expression after WHERE, got: %v", err)
	}
}

func TestMalformedSQL_WhereFollowedByGroupBy(t *testing.T) {
	err := parseSQLCheck(t, "SELECT * FROM t WHERE GROUP BY id")
	if err == nil {
		t.Fatal("expected error for WHERE followed by GROUP BY")
	}
	if !strings.Contains(err.Error(), "expression after WHERE") {
		t.Errorf("expected error about expression after WHERE, got: %v", err)
	}
}

func TestMalformedSQL_WhereFollowedByOrderBy(t *testing.T) {
	err := parseSQLCheck(t, "SELECT * FROM t WHERE ORDER BY id")
	if err == nil {
		t.Fatal("expected error for WHERE followed by ORDER BY")
	}
	if !strings.Contains(err.Error(), "expression after WHERE") {
		t.Errorf("expected error about expression after WHERE, got: %v", err)
	}
}

// =============================================================================
// Regression tests — valid SQL must still parse correctly
// =============================================================================

func TestValidSQL_SelectStar(t *testing.T) {
	if err := parseSQLCheck(t, "SELECT * FROM users"); err != nil {
		t.Fatalf("valid SQL failed: %v", err)
	}
}

func TestValidSQL_SelectMultipleTables(t *testing.T) {
	if err := parseSQLCheck(t, "SELECT * FROM t1, t2"); err != nil {
		t.Fatalf("valid SQL failed: %v", err)
	}
}

func TestValidSQL_SelectThreeTables(t *testing.T) {
	if err := parseSQLCheck(t, "SELECT * FROM t1, t2, t3"); err != nil {
		t.Fatalf("valid SQL failed: %v", err)
	}
}

func TestValidSQL_SelectWithoutFrom(t *testing.T) {
	if err := parseSQLCheck(t, "SELECT 1"); err != nil {
		t.Fatalf("valid SQL failed: %v", err)
	}
}

func TestValidSQL_SelectExpression(t *testing.T) {
	if err := parseSQLCheck(t, "SELECT 1 + 2"); err != nil {
		t.Fatalf("valid SQL failed: %v", err)
	}
}

func TestValidSQL_SelectDistinct(t *testing.T) {
	if err := parseSQLCheck(t, "SELECT DISTINCT * FROM t"); err != nil {
		t.Fatalf("valid SQL failed: %v", err)
	}
}

func TestValidSQL_SelectWithWhere(t *testing.T) {
	if err := parseSQLCheck(t, "SELECT * FROM t WHERE 1=1"); err != nil {
		t.Fatalf("valid SQL failed: %v", err)
	}
}

func TestValidSQL_SelectWithWhereComplex(t *testing.T) {
	if err := parseSQLCheck(t, "SELECT * FROM users WHERE active = true AND age > 18"); err != nil {
		t.Fatalf("valid SQL failed: %v", err)
	}
}

func TestValidSQL_SelectColumns(t *testing.T) {
	if err := parseSQLCheck(t, "SELECT id, name, email FROM users"); err != nil {
		t.Fatalf("valid SQL failed: %v", err)
	}
}

func TestValidSQL_MultipleStatements(t *testing.T) {
	if err := parseSQLCheck(t, "SELECT 1; SELECT 2"); err != nil {
		t.Fatalf("valid SQL failed: %v", err)
	}
}

func TestValidSQL_EmptyStatementsLenient(t *testing.T) {
	if err := parseSQLCheck(t, ";;; SELECT 1 ;;;"); err != nil {
		t.Fatalf("lenient mode should accept empty statements: %v", err)
	}
}

func TestValidSQL_TrailingSemicolon(t *testing.T) {
	if err := parseSQLCheck(t, "SELECT 1;"); err != nil {
		t.Fatalf("valid SQL failed: %v", err)
	}
}

// =============================================================================
// Issue #300 — Strict mode for empty statements
// =============================================================================

func TestStrictMode_RejectsLeadingSemicolons(t *testing.T) {
	err := parseSQLStrict(t, "; SELECT 1")
	if err == nil {
		t.Fatal("strict mode should reject leading semicolons")
	}
	if !strings.Contains(err.Error(), "empty statement") {
		t.Errorf("expected 'empty statement' error, got: %v", err)
	}
}

func TestStrictMode_RejectsConsecutiveSemicolons(t *testing.T) {
	err := parseSQLStrict(t, "SELECT 1;; SELECT 2")
	if err == nil {
		t.Fatal("strict mode should reject consecutive semicolons")
	}
	if !strings.Contains(err.Error(), "empty statement") {
		t.Errorf("expected 'empty statement' error, got: %v", err)
	}
}

func TestStrictMode_RejectsOnlySemicolons(t *testing.T) {
	err := parseSQLStrict(t, ";;;")
	if err == nil {
		t.Fatal("strict mode should reject only semicolons")
	}
}

func TestStrictMode_AcceptsValidSQL(t *testing.T) {
	if err := parseSQLStrict(t, "SELECT 1"); err != nil {
		t.Fatalf("strict mode should accept valid SQL: %v", err)
	}
}

func TestStrictMode_AcceptsMultipleStatements(t *testing.T) {
	if err := parseSQLStrict(t, "SELECT 1; SELECT 2"); err != nil {
		t.Fatalf("strict mode should accept multiple statements: %v", err)
	}
}

func TestStrictMode_AcceptsSingleTrailingSemicolon(t *testing.T) {
	if err := parseSQLStrict(t, "SELECT 1;"); err != nil {
		t.Fatalf("strict mode should accept single trailing semicolon: %v", err)
	}
}

func TestStrictMode_WithApplyOptions(t *testing.T) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.Tokenize([]byte("; SELECT 1"))
	if err != nil {
		t.Fatal(err)
	}
	p := GetParser()
	defer PutParser(p)
	p.ApplyOptions(WithStrictMode())
	_, err = p.ParseFromModelTokens(tokens)
	if err == nil {
		t.Fatal("ApplyOptions(WithStrictMode()) should enable strict mode")
	}
}

// =============================================================================
// Issue #306 — ParseWithPositions strict mode trailing semicolon
// =============================================================================

func parseSQLStrictWithPositions(t *testing.T, sql string) error {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenize error for %q: %v", sql, err)
	}
	p := NewParser(WithStrictMode())
	_, err = p.ParseFromModelTokensWithPositions(tokens)
	return err
}

func TestStrictMode_ParseWithPositions_TrailingSemicolon(t *testing.T) {
	if err := parseSQLStrictWithPositions(t, "SELECT 1;"); err != nil {
		t.Fatalf("ParseWithPositions strict mode should accept trailing semicolon: %v", err)
	}
}

func TestStrictMode_ParseWithPositions_ValidSQL(t *testing.T) {
	if err := parseSQLStrictWithPositions(t, "SELECT 1"); err != nil {
		t.Fatalf("ParseWithPositions strict mode should accept valid SQL: %v", err)
	}
}

func TestStrictMode_ParseWithPositions_RejectsLeadingSemicolon(t *testing.T) {
	err := parseSQLStrictWithPositions(t, "; SELECT 1")
	if err == nil {
		t.Fatal("ParseWithPositions strict mode should reject leading semicolons")
	}
}

func TestStrictMode_ParseWithPositions_MultipleStatements(t *testing.T) {
	if err := parseSQLStrictWithPositions(t, "SELECT 1; SELECT 2"); err != nil {
		t.Fatalf("ParseWithPositions strict mode should accept multiple statements: %v", err)
	}
}

// =============================================================================
// Issue #306 — WHERE clause guard keywords (FETCH, FOR)
// =============================================================================

func TestMalformedSQL_WhereFollowedByFetch(t *testing.T) {
	err := parseSQLCheck(t, "SELECT * FROM t WHERE FETCH FIRST 10 ROWS ONLY")
	if err == nil {
		t.Fatal("expected error for WHERE followed by FETCH")
	}
	if !strings.Contains(err.Error(), "expression after WHERE") {
		t.Errorf("expected error about expression after WHERE, got: %v", err)
	}
}

func TestMalformedSQL_WhereFollowedByFor(t *testing.T) {
	err := parseSQLCheck(t, "SELECT * FROM t WHERE FOR UPDATE")
	if err == nil {
		t.Fatal("expected error for WHERE followed by FOR")
	}
	if !strings.Contains(err.Error(), "expression after WHERE") {
		t.Errorf("expected error about expression after WHERE, got: %v", err)
	}
}

func TestNewParser_WithStrictMode(t *testing.T) {
	p := NewParser(WithStrictMode())
	if !p.strict {
		t.Fatal("NewParser(WithStrictMode()) should set strict=true")
	}
}
