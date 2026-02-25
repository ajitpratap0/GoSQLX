package parser_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

func TestTopVerification(t *testing.T) {
	// Test 1: no dialect — must succeed (permissive)
	p1 := parser.NewParser("SELECT TOP 10 id FROM users", parser.WithDialect(""))
	_, err := p1.Parse()
	if err != nil {
		t.Errorf("BLOCKER FAIL (no dialect): %v", err)
	} else {
		t.Log("PASS: SELECT TOP 10 succeeds with no dialect")
	}

	// Test 2: Oracle dialect — must fail with correct message (ROWNUM, not LIMIT)
	p2 := parser.NewParser("SELECT TOP 10 id FROM users", parser.WithDialect("oracle"))
	_, err = p2.Parse()
	if err == nil {
		t.Error("FAIL: Oracle should reject TOP")
	} else if strings.Contains(err.Error(), "ROWNUM") {
		t.Logf("PASS (oracle): %v", err)
	} else {
		t.Errorf("FAIL: Oracle error should mention ROWNUM, got: %v", err)
	}

	// Test 3: sqlserver — must succeed
	p3 := parser.NewParser("SELECT TOP 10 id FROM users", parser.WithDialect("sqlserver"))
	_, err = p3.Parse()
	if err != nil {
		t.Errorf("FAIL (sqlserver): %v", err)
	} else {
		t.Log("PASS: SELECT TOP 10 succeeds with sqlserver dialect")
	}
}
