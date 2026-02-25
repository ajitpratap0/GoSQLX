package parser_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func parseTopSQL(t *testing.T, sql string, dialect string) error {
	t.Helper()
	// Use the specified dialect for tokenisation; fall back to SQL Server
	// when dialect is empty because TOP is a SQL-Server-family keyword.
	tokDialect := keywords.SQLDialect(dialect)
	if dialect == "" {
		tokDialect = keywords.DialectSQLServer
	}
	tkz, err := tokenizer.NewWithDialect(tokDialect)
	if err != nil {
		t.Fatalf("failed to create tokenizer: %v", err)
	}
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenize failed: %v", err)
	}
	p := parser.NewParser(parser.WithDialect(dialect))
	_, parseErr := p.ParseFromModelTokens(tokens)
	return parseErr
}

func TestTopVerification(t *testing.T) {
	// Test 1: sqlserver dialect — must succeed
	err := parseTopSQL(t, "SELECT TOP 10 id FROM users", "sqlserver")
	if err != nil {
		t.Errorf("BLOCKER FAIL (sqlserver): %v", err)
	} else {
		t.Log("PASS: SELECT TOP 10 succeeds with sqlserver dialect")
	}

	// Test 2: Oracle dialect — must fail with correct message (ROWNUM, not LIMIT)
	err = parseTopSQL(t, "SELECT TOP 10 id FROM users", "oracle")
	if err == nil {
		t.Error("FAIL: Oracle should reject TOP")
	} else if strings.Contains(err.Error(), "ROWNUM") {
		t.Logf("PASS (oracle): %v", err)
	} else {
		t.Errorf("FAIL: Oracle error should mention ROWNUM, got: %v", err)
	}

	// Test 3: mysql dialect — must fail with correct message (LIMIT/OFFSET)
	err = parseTopSQL(t, "SELECT TOP 10 id FROM users", "mysql")
	if err == nil {
		t.Error("FAIL: MySQL should reject TOP")
	} else if strings.Contains(err.Error(), "LIMIT") {
		t.Logf("PASS (mysql): %v", err)
	} else {
		t.Errorf("FAIL: MySQL error should mention LIMIT, got: %v", err)
	}
}
