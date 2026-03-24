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

package parser

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestParserWithDialectOption(t *testing.T) {
	p := NewParser(WithDialect("mysql"))
	if p.Dialect() != "mysql" {
		t.Errorf("expected mysql, got %s", p.Dialect())
	}

	p2 := NewParser()
	if p2.Dialect() != "postgresql" {
		t.Errorf("expected postgresql default, got %s", p2.Dialect())
	}
}

func TestTokenizerWithDialect(t *testing.T) {
	tkz, err := tokenizer.NewWithDialect(keywords.DialectMySQL)
	if err != nil {
		t.Fatal(err)
	}
	if tkz.Dialect() != keywords.DialectMySQL {
		t.Errorf("expected mysql, got %s", tkz.Dialect())
	}
}

func TestTokenizerSetDialect(t *testing.T) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tkz.SetDialect(keywords.DialectMySQL)
	if tkz.Dialect() != keywords.DialectMySQL {
		t.Errorf("expected mysql, got %s", tkz.Dialect())
	}
}

func TestTokenizerDefaultDialect(t *testing.T) {
	tkz, err := tokenizer.NewWithDialect("")
	if err != nil {
		t.Fatal(err)
	}
	if tkz.Dialect() != keywords.DialectPostgreSQL {
		t.Errorf("expected postgresql default, got %s", tkz.Dialect())
	}
}

func TestParseWithDialect(t *testing.T) {
	// Basic SQL should parse with any dialect
	for _, dialect := range []keywords.SQLDialect{
		keywords.DialectPostgreSQL,
		keywords.DialectMySQL,
		keywords.DialectSQLServer,
	} {
		t.Run(string(dialect), func(t *testing.T) {
			ast, err := ParseWithDialect("SELECT 1", dialect)
			if err != nil {
				t.Fatalf("ParseWithDialect(%s) failed: %v", dialect, err)
			}
			if ast == nil {
				t.Fatal("expected non-nil AST")
			}
		})
	}
}

func TestValidateWithDialect(t *testing.T) {
	err := ValidateWithDialect("SELECT * FROM users WHERE id = 1", keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("ValidateWithDialect(mysql) failed: %v", err)
	}

	err = ValidateWithDialect("SELECT * FROM users WHERE id = 1", keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("ValidateWithDialect(postgresql) failed: %v", err)
	}
}

func TestDefaultBehaviorUnchanged(t *testing.T) {
	// Validate() without dialect should still work (backward compatibility)
	err := Validate("SELECT * FROM users")
	if err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}

	ast, err := ParseBytes([]byte("SELECT 1"))
	if err != nil {
		t.Fatalf("ParseBytes() failed: %v", err)
	}
	if ast == nil {
		t.Fatal("expected non-nil AST")
	}
}

func TestMySQLKeywordsRecognized(t *testing.T) {
	// UNSIGNED is a MySQL-specific keyword; tokenizer should recognize it
	tkz, err := tokenizer.NewWithDialect(keywords.DialectMySQL)
	if err != nil {
		t.Fatal(err)
	}

	tokens, err := tkz.Tokenize([]byte("SELECT UNSIGNED"))
	if err != nil {
		t.Fatalf("tokenize failed: %v", err)
	}

	// Should have at least 2 tokens (SELECT, UNSIGNED)
	if len(tokens) < 2 {
		t.Fatalf("expected at least 2 tokens, got %d", len(tokens))
	}
}

func TestPostgreSQLKeywordsRecognized(t *testing.T) {
	tkz, err := tokenizer.NewWithDialect(keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}

	tokens, err := tkz.Tokenize([]byte("SELECT ILIKE"))
	if err != nil {
		t.Fatalf("tokenize failed: %v", err)
	}

	if len(tokens) < 2 {
		t.Fatalf("expected at least 2 tokens, got %d", len(tokens))
	}
}

// ---------------------------------------------------------------------------
// Dialect gate tests - reject invalid cross-dialect syntax
// ---------------------------------------------------------------------------

// TestRejectUnknownDialect ensures that ParseWithDialect and ValidateWithDialect
// return errors for dialect names that don't exist.
func TestRejectUnknownDialect(t *testing.T) {
	_, err := ParseWithDialect("SELECT 1", keywords.SQLDialect("fakesql"))
	if err == nil {
		t.Fatal("expected error for unknown dialect 'fakesql', got nil")
	}
	if !containsAny(err.Error(), "unknown", "dialect") {
		t.Errorf("error should mention 'unknown' or 'dialect', got: %v", err)
	}

	err = ValidateWithDialect("SELECT 1", keywords.SQLDialect("fakesql"))
	if err == nil {
		t.Fatal("expected error from ValidateWithDialect for unknown dialect")
	}
}

// TestIsValidDialect covers the IsValidDialect helper.
func TestIsValidDialect(t *testing.T) {
	validDialects := []string{
		"postgresql", "mysql", "sqlserver", "oracle", "sqlite",
		"snowflake", "bigquery", "redshift", "generic", "mariadb", "",
	}
	for _, d := range validDialects {
		if !keywords.IsValidDialect(d) {
			t.Errorf("IsValidDialect(%q) should return true", d)
		}
	}
	invalidDialects := []string{"fakesql", "postgres", "mssql", "pg", "db2"}
	for _, d := range invalidDialects {
		if keywords.IsValidDialect(d) {
			t.Errorf("IsValidDialect(%q) should return false", d)
		}
	}
}

// ---------------------------------------------------------------------------
// LIMIT dialect gate
// ---------------------------------------------------------------------------

// TestRejectLimitInSQLServer checks that LIMIT is rejected when the dialect is
// explicitly set to SQL Server.
func TestRejectLimitInSQLServer(t *testing.T) {
	sql := "SELECT id, name FROM users LIMIT 10"
	_, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err == nil {
		t.Fatal("expected error: LIMIT should be rejected in SQL Server dialect")
	}
	if !containsAny(err.Error(), "LIMIT", "SQL Server", "TOP", "FETCH") {
		t.Errorf("error should mention LIMIT or SQL Server, got: %v", err)
	}
}

// TestAcceptLimitInMySQL checks that LIMIT is accepted in MySQL dialect.
func TestAcceptLimitInMySQL(t *testing.T) {
	sql := "SELECT id, name FROM users LIMIT 10"
	_, err := ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("LIMIT should be valid in MySQL dialect, got error: %v", err)
	}
}

// TestAcceptLimitInPostgreSQL checks that LIMIT is accepted in PostgreSQL dialect.
func TestAcceptLimitInPostgreSQL(t *testing.T) {
	sql := "SELECT id, name FROM users LIMIT 10"
	_, err := ParseWithDialect(sql, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("LIMIT should be valid in PostgreSQL dialect, got error: %v", err)
	}
}

// TestAcceptLimitDefaultDialect checks that LIMIT still works when no dialect is
// set (backward compatibility).
func TestAcceptLimitDefaultDialect(t *testing.T) {
	sql := "SELECT id, name FROM users LIMIT 10"
	_, err := ParseBytes([]byte(sql))
	if err != nil {
		t.Fatalf("LIMIT should be valid in default dialect, got error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TOP dialect gate
// ---------------------------------------------------------------------------

// TestRejectTopInMySQL checks that TOP is rejected when dialect is MySQL.
func TestRejectTopInMySQL(t *testing.T) {
	sql := "SELECT TOP 10 id, name FROM users"
	_, err := ParseWithDialect(sql, keywords.DialectMySQL)
	if err == nil {
		t.Fatal("expected error: TOP should be rejected in MySQL dialect")
	}
	if !containsAny(err.Error(), "TOP", "mysql", "LIMIT") {
		t.Errorf("error should mention TOP or MySQL, got: %v", err)
	}
}

// TestRejectTopInPostgreSQL checks that TOP is rejected when dialect is PostgreSQL.
func TestRejectTopInPostgreSQL(t *testing.T) {
	sql := "SELECT TOP 10 id, name FROM users"
	_, err := ParseWithDialect(sql, keywords.DialectPostgreSQL)
	if err == nil {
		t.Fatal("expected error: TOP should be rejected in PostgreSQL dialect")
	}
	if !containsAny(err.Error(), "TOP", "postgresql", "LIMIT") {
		t.Errorf("error should mention TOP or PostgreSQL, got: %v", err)
	}
}

// TestAcceptTopInSQLServer checks that TOP is accepted in SQL Server dialect.
func TestAcceptTopInSQLServer(t *testing.T) {
	sql := "SELECT TOP 10 id, name FROM users"
	_, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("TOP should be valid in SQL Server dialect, got error: %v", err)
	}
}

// TestRejectTopInSQLite checks that TOP is rejected when dialect is SQLite.
func TestRejectTopInSQLite(t *testing.T) {
	sql := "SELECT TOP 10 id, name FROM users"
	_, err := ParseWithDialect(sql, keywords.DialectSQLite)
	if err == nil {
		t.Fatal("expected error: TOP should be rejected in SQLite dialect")
	}
	if !containsAny(err.Error(), "TOP", "sqlite", "LIMIT") {
		t.Errorf("error should mention TOP or SQLite, got: %v", err)
	}
}

// TestRejectTopInOracle checks that TOP is rejected when dialect is Oracle.
func TestRejectTopInOracle(t *testing.T) {
	sql := "SELECT TOP 10 id, name FROM users"
	_, err := ParseWithDialect(sql, keywords.DialectOracle)
	if err == nil {
		t.Fatal("expected error: TOP should be rejected in Oracle dialect")
	}
	if !containsAny(err.Error(), "TOP", "oracle", "LIMIT") {
		t.Errorf("error should mention TOP or Oracle, got: %v", err)
	}
}

// TestRejectLimitInOracle checks that LIMIT is rejected when dialect is Oracle.
func TestRejectLimitInOracle(t *testing.T) {
	sql := "SELECT id, name FROM users LIMIT 10"
	_, err := ParseWithDialect(sql, keywords.DialectOracle)
	if err == nil {
		t.Fatal("expected error: LIMIT should be rejected in Oracle dialect")
	}
	if !containsAny(err.Error(), "LIMIT", "Oracle", "ROWNUM", "FETCH") {
		t.Errorf("error should mention LIMIT or Oracle, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ILIKE dialect gate
// ---------------------------------------------------------------------------

// TestRejectILIKEInMySQL checks that ILIKE is rejected in MySQL mode.
func TestRejectILIKEInMySQL(t *testing.T) {
	sql := "SELECT * FROM users WHERE name ILIKE '%alice%'"
	_, err := ParseWithDialect(sql, keywords.DialectMySQL)
	if err == nil {
		t.Fatal("expected error: ILIKE should be rejected in MySQL dialect")
	}
	if !containsAny(err.Error(), "ILIKE", "PostgreSQL", "LIKE", "mysql") {
		t.Errorf("error should mention ILIKE or MySQL, got: %v", err)
	}
}

// TestRejectILIKEInSQLServer checks that ILIKE is rejected in SQL Server mode.
func TestRejectILIKEInSQLServer(t *testing.T) {
	sql := "SELECT * FROM users WHERE name ILIKE '%alice%'"
	_, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err == nil {
		t.Fatal("expected error: ILIKE should be rejected in SQL Server dialect")
	}
	if !containsAny(err.Error(), "ILIKE", "PostgreSQL", "LIKE") {
		t.Errorf("error should mention ILIKE, got: %v", err)
	}
}

// TestRejectNotILIKEInMySQL checks that NOT ILIKE is rejected in MySQL mode.
func TestRejectNotILIKEInMySQL(t *testing.T) {
	sql := "SELECT * FROM users WHERE name NOT ILIKE '%alice%'"
	_, err := ParseWithDialect(sql, keywords.DialectMySQL)
	if err == nil {
		t.Fatal("expected error: NOT ILIKE should be rejected in MySQL dialect")
	}
}

// TestAcceptILIKEInPostgreSQL checks that ILIKE is accepted in PostgreSQL mode.
func TestAcceptILIKEInPostgreSQL(t *testing.T) {
	sql := "SELECT * FROM users WHERE name ILIKE '%alice%'"
	_, err := ParseWithDialect(sql, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("ILIKE should be valid in PostgreSQL dialect, got error: %v", err)
	}
}

// TestAcceptILIKEDefaultDialect checks that ILIKE works when no dialect is set
// (default is treated as PostgreSQL for backward compatibility).
func TestAcceptILIKEDefaultDialect(t *testing.T) {
	sql := "SELECT * FROM users WHERE name ILIKE '%alice%'"
	// When no dialect is set (p.dialect == ""), the gate should not fire.
	p := NewParser() // dialect == ""
	tkz, err := tokenizer.NewWithDialect(keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatal(err)
	}
	result, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("ILIKE should be valid with default (empty) dialect, got error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil AST")
	}
}

// ---------------------------------------------------------------------------
// Backtick and bracket reserved-word regression tests (DIALECT-1, DIALECT-2)
// ---------------------------------------------------------------------------

// TestMySQL_BacktickReservedWordAsTable verifies that MySQL backtick-quoted
// reserved words are accepted as column and table names.
func TestMySQL_BacktickReservedWordAsTable(t *testing.T) {
	// `table` and `key` are reserved words but valid as quoted identifiers
	sql := "SELECT `select`, `from` FROM `table`"
	_, err := ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("backtick-quoted reserved word as table name failed: %v", err)
	}
}

// TestSQLServer_BracketReservedWordAsTable verifies that SQL Server bracket-quoted
// reserved words are accepted as column and table names.
func TestSQLServer_BracketReservedWordAsTable(t *testing.T) {
	sql := "SELECT [select], [from] FROM [table]"
	_, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("bracket-quoted reserved word as table name failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Oracle keywords
// ---------------------------------------------------------------------------

// TestOracleKeywordListNonNil checks that Oracle dialect returns a non-empty
// keyword list (previously returned nil).
func TestOracleKeywordListNonNil(t *testing.T) {
	kws := keywords.DialectKeywords(keywords.DialectOracle)
	if kws == nil {
		t.Fatal("DialectKeywords(DialectOracle) returned nil; expected non-empty keyword list")
	}
	if len(kws) == 0 {
		t.Fatal("DialectKeywords(DialectOracle) returned empty slice")
	}
	// Verify a few known Oracle keywords are present
	found := make(map[string]bool)
	for _, kw := range kws {
		found[kw.Word] = true
	}
	for _, expected := range []string{"ROWNUM", "SYSDATE", "DUAL", "NVL", "DECODE"} {
		if !found[expected] {
			t.Errorf("expected Oracle keyword %q not found in list", expected)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// containsAny reports whether s contains any of the given substrings using a
// case-insensitive comparison.  Both s and each element of substrs are
// lowercased before matching, so the caller does not need to normalise them.
//
// Example:
//
//	containsAny("LIMIT clause not supported", "limit", "SQL Server") // true
//	containsAny("unknown dialect", "TOP", "FETCH")                   // false
func containsAny(s string, substrs ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}
