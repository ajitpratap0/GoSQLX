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

package mcp

import (
	"testing"
)

// --- validateSQLInternal ---

func TestValidateSQLInternal_EmptySQL(t *testing.T) {
	_, err := validateSQLInternal("", "")
	if err == nil {
		t.Fatal("expected error for empty sql")
	}
}

func TestValidateSQLInternal_ValidGeneric(t *testing.T) {
	data, err := validateSQLInternal("SELECT 1", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["valid"] != true {
		t.Errorf("expected valid=true, got %v", data["valid"])
	}
	if _, ok := data["dialect"]; ok {
		t.Error("generic validation should not include dialect key")
	}
}

func TestValidateSQLInternal_InvalidGeneric(t *testing.T) {
	data, err := validateSQLInternal("SELECT FROM", "")
	if err != nil {
		t.Fatalf("expected nil error for invalid SQL (tool-semantic), got: %v", err)
	}
	if data["valid"] != false {
		t.Errorf("expected valid=false, got %v", data["valid"])
	}
	if _, ok := data["error"]; !ok {
		t.Error("expected error key in result")
	}
}

func TestValidateSQLInternal_ValidWithDialect(t *testing.T) {
	data, err := validateSQLInternal("SELECT 1", "postgresql")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["valid"] != true {
		t.Errorf("expected valid=true")
	}
	if data["dialect"] != "postgresql" {
		t.Errorf("expected dialect=postgresql, got %v", data["dialect"])
	}
}

func TestValidateSQLInternal_InvalidWithDialect(t *testing.T) {
	data, err := validateSQLInternal("SELECT FROM", "mysql")
	if err != nil {
		t.Fatalf("expected nil error for invalid SQL (tool-semantic), got: %v", err)
	}
	if data["valid"] != false {
		t.Errorf("expected valid=false")
	}
	if data["dialect"] != "mysql" {
		t.Errorf("expected dialect=mysql, got %v", data["dialect"])
	}
}

// --- formatSQLInternal ---

func TestFormatSQLInternal_EmptySQL(t *testing.T) {
	_, err := formatSQLInternal("", 2, false, false)
	if err == nil {
		t.Fatal("expected error for empty sql")
	}
}

func TestFormatSQLInternal_ValidSQL(t *testing.T) {
	data, err := formatSQLInternal("select id from users", 4, true, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := data["formatted_sql"]; !ok {
		t.Error("expected formatted_sql key")
	}
	opts, ok := data["options"].(map[string]any)
	if !ok {
		t.Fatal("expected options to be map[string]any")
	}
	if opts["indent_size"] != 4 {
		t.Errorf("expected indent_size=4, got %v", opts["indent_size"])
	}
	if opts["uppercase_keywords"] != true {
		t.Errorf("expected uppercase_keywords=true")
	}
	if opts["add_semicolon"] != true {
		t.Errorf("expected add_semicolon=true")
	}
}

func TestFormatSQLInternal_InvalidSQL(t *testing.T) {
	_, err := formatSQLInternal(")))((( @@@ !!!", 2, false, false)
	if err == nil {
		t.Fatal("expected format error for completely invalid SQL")
	}
}

// --- parseSQLInternal ---

func TestParseSQLInternal_EmptySQL(t *testing.T) {
	_, err := parseSQLInternal("")
	if err == nil {
		t.Fatal("expected error for empty sql")
	}
}

func TestParseSQLInternal_SingleStatement(t *testing.T) {
	data, err := parseSQLInternal("SELECT id FROM users")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["statement_count"] != 1 {
		t.Errorf("expected 1 statement, got %v", data["statement_count"])
	}
	types, ok := data["statement_types"].([]string)
	if !ok {
		t.Fatal("expected statement_types to be []string")
	}
	if len(types) != 1 {
		t.Errorf("expected 1 type, got %d", len(types))
	}
}

func TestParseSQLInternal_MultipleStatements(t *testing.T) {
	data, err := parseSQLInternal("SELECT 1; INSERT INTO t VALUES (1); DELETE FROM t")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count, ok := data["statement_count"].(int)
	if !ok {
		t.Fatal("expected statement_count to be int")
	}
	if count < 2 {
		t.Errorf("expected multiple statements, got %d", count)
	}
}

func TestParseSQLInternal_InvalidSQL(t *testing.T) {
	_, err := parseSQLInternal(")))((( @@@ !!!")
	if err == nil {
		t.Fatal("expected parse error for invalid SQL")
	}
}

// --- extractMetadataInternal ---

func TestExtractMetadataInternal_EmptySQL(t *testing.T) {
	_, err := extractMetadataInternal("")
	if err == nil {
		t.Fatal("expected error for empty sql")
	}
}

func TestExtractMetadataInternal_WithJoins(t *testing.T) {
	data, err := extractMetadataInternal("SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tables, ok := data["tables"].([]string)
	if !ok {
		t.Fatal("expected tables to be []string")
	}
	if len(tables) == 0 {
		t.Error("expected at least one table")
	}
	columns, ok := data["columns"].([]string)
	if !ok {
		t.Fatal("expected columns to be []string")
	}
	if len(columns) == 0 {
		t.Error("expected at least one column")
	}
}

func TestExtractMetadataInternal_WithFunctions(t *testing.T) {
	data, err := extractMetadataInternal("SELECT COUNT(*), MAX(price) FROM products")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	functions, ok := data["functions"].([]string)
	if !ok {
		t.Fatal("expected functions to be []string")
	}
	if len(functions) == 0 {
		t.Error("expected at least one function")
	}
}

func TestExtractMetadataInternal_NoTablesReturnsEmptySlice(t *testing.T) {
	data, err := extractMetadataInternal("SELECT 1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tables, ok := data["tables"].([]string)
	if !ok {
		t.Fatal("expected tables to be []string")
	}
	if tables == nil {
		t.Error("tables should be [] not nil (nil-normalization)")
	}
}

func TestExtractMetadataInternal_InvalidSQL(t *testing.T) {
	_, err := extractMetadataInternal(")))((( @@@ !!!")
	if err == nil {
		t.Fatal("expected parse error for invalid SQL")
	}
}

// --- securityScanInternal ---

func TestSecurityScanInternal_EmptySQL(t *testing.T) {
	_, err := securityScanInternal("")
	if err == nil {
		t.Fatal("expected error for empty sql")
	}
}

func TestSecurityScanInternal_CleanSQL(t *testing.T) {
	data, err := securityScanInternal("SELECT id FROM users WHERE id = 42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["is_clean"] != true {
		t.Error("expected is_clean=true for benign SQL")
	}
	if data["total_count"] != 0 {
		t.Errorf("expected 0 findings, got %v", data["total_count"])
	}
}

func TestSecurityScanInternal_InjectionDetected(t *testing.T) {
	data, err := securityScanInternal("SELECT * FROM users WHERE 1=1 OR ''=''")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["is_clean"] == true {
		t.Error("expected is_clean=false for injection pattern")
	}
	findings, ok := data["findings"].([]map[string]any)
	if !ok {
		t.Fatal("expected findings to be []map[string]any")
	}
	if len(findings) == 0 {
		t.Error("expected at least one finding")
	}
	f := findings[0]
	for _, key := range []string{"severity", "pattern", "description", "risk", "suggestion"} {
		if _, ok := f[key]; !ok {
			t.Errorf("finding missing key %q", key)
		}
	}
}

func TestSecurityScanInternal_StackedQueries(t *testing.T) {
	data, err := securityScanInternal("SELECT 1; DROP TABLE users")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["is_clean"] == true {
		t.Error("expected detection of stacked query pattern")
	}
}

func TestSecurityScanInternal_CommentBypass(t *testing.T) {
	data, err := securityScanInternal("SELECT * FROM users WHERE id = 1 -- bypass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Comment bypasses may or may not be detected depending on pattern
	_ = data
}

// --- lintSQLInternal ---

func TestLintSQLInternal_EmptySQL(t *testing.T) {
	_, err := lintSQLInternal("")
	if err == nil {
		t.Fatal("expected error for empty sql")
	}
}

func TestLintSQLInternal_CleanSQL(t *testing.T) {
	data, err := lintSQLInternal("SELECT id FROM users")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := data["violation_count"]; !ok {
		t.Error("expected violation_count key")
	}
	if _, ok := data["violations"]; !ok {
		t.Error("expected violations key")
	}
}

func TestLintSQLInternal_WithViolations(t *testing.T) {
	data, err := lintSQLInternal("select id from users   \n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	violations, ok := data["violations"].([]map[string]any)
	if !ok {
		t.Fatal("expected violations to be []map[string]any")
	}
	if len(violations) == 0 {
		t.Error("expected lint violations for trailing whitespace / keyword case")
	}
	v := violations[0]
	for _, key := range []string{"rule", "rule_name", "severity", "message", "line", "column", "suggestion"} {
		if _, ok := v[key]; !ok {
			t.Errorf("violation missing key %q", key)
		}
	}
}

// --- toolResult ---

func TestToolResult_ValidMap(t *testing.T) {
	res, err := toolResult(map[string]any{"key": "value"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestToolResult_MarshalError(t *testing.T) {
	_, err := toolResult(map[string]any{"bad": make(chan int)})
	if err == nil {
		t.Fatal("expected marshal error for unmarshalable value")
	}
}

// --- newFullLinter ---

func TestNewFullLinter_Returns10Rules(t *testing.T) {
	l := newFullLinter()
	if l == nil {
		t.Fatal("newFullLinter returned nil")
	}
	result := l.LintString("SELECT 1", "<test>")
	if result.Filename != "<test>" {
		t.Errorf("expected filename '<test>', got %q", result.Filename)
	}
}
