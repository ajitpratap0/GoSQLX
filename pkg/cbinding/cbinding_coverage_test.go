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

// Package main – coverage tests for all 9 exported C binding functions.
// Because CGo cannot be used directly in test files for package main, these
// tests exercise the exported functions through the pure-Go wrappers defined
// in cbinding_testhelpers.go.  Every code path in cbinding.go is reached via
// those wrappers, which internally call the real exported functions using the
// C string layer.
package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// gosqlx_parse via parseSQL wrapper
// ---------------------------------------------------------------------------

func TestCGosqlxParse_ValidSelect(t *testing.T) {
	result := parseSQL("SELECT id, name FROM users WHERE active = true")
	if !result.Success {
		t.Errorf("expected success, got error: %s", result.Error)
	}
	if result.StmtCount != 1 {
		t.Errorf("expected 1 statement, got %d", result.StmtCount)
	}
	if len(result.StmtTypes) == 0 || result.StmtTypes[0] != "SELECT" {
		t.Errorf("expected SELECT type, got %v", result.StmtTypes)
	}
}

func TestCGosqlxParse_InvalidSQL(t *testing.T) {
	result := parseSQL("SELECT FROM WHERE INVALID")
	if result.Success {
		t.Error("expected failure for invalid SQL")
	}
	if result.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestCGosqlxParse_MultipleStatements(t *testing.T) {
	result := parseSQL("SELECT 1; SELECT 2; SELECT 3")
	if !result.Success {
		t.Errorf("expected success: %s", result.Error)
	}
	if result.StmtCount != 3 {
		t.Errorf("expected 3 statements, got %d", result.StmtCount)
	}
}

func TestCGosqlxParse_EmptySQL(t *testing.T) {
	result := parseSQL("")
	// Empty SQL – must not panic; zero statements is acceptable.
	t.Logf("empty SQL parse: success=%v stmts=%d", result.Success, result.StmtCount)
}

func TestCGosqlxParse_AllDMLTypes(t *testing.T) {
	tests := []struct {
		sql      string
		wantType string
	}{
		{"SELECT 1", "SELECT"},
		{"INSERT INTO t (id) VALUES (1)", "INSERT"},
		{"UPDATE t SET x = 1 WHERE id = 1", "UPDATE"},
		{"DELETE FROM t WHERE id = 1", "DELETE"},
		{"CREATE TABLE t (id INT)", "CREATE_TABLE"},
		{"DROP TABLE IF EXISTS t", "DROP"},
		{"TRUNCATE TABLE t", "TRUNCATE"},
	}
	for _, tt := range tests {
		t.Run(tt.wantType, func(t *testing.T) {
			result := parseSQL(tt.sql)
			if !result.Success {
				t.Errorf("expected success for %q: %s", tt.sql, result.Error)
			}
			if len(result.StmtTypes) == 0 || result.StmtTypes[0] != tt.wantType {
				t.Errorf("expected type %s, got %v", tt.wantType, result.StmtTypes)
			}
		})
	}
}

func TestCGosqlxParse_CreateView(t *testing.T) {
	result := parseSQL("CREATE VIEW active_users AS SELECT * FROM users WHERE active = 1")
	if !result.Success {
		t.Errorf("expected success: %s", result.Error)
	}
	if len(result.StmtTypes) == 0 || result.StmtTypes[0] != "CREATE_VIEW" {
		t.Errorf("expected CREATE_VIEW, got %v", result.StmtTypes)
	}
}

func TestCGosqlxParse_WithCTE(t *testing.T) {
	result := parseSQL("WITH cte AS (SELECT id FROM users) SELECT * FROM cte")
	if !result.Success {
		t.Errorf("expected CTE parse success: %s", result.Error)
	}
}

func TestCGosqlxParse_WithWindowFunction(t *testing.T) {
	result := parseSQL("SELECT id, ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) FROM employees")
	if !result.Success {
		t.Errorf("expected window function parse success: %s", result.Error)
	}
}

func TestCGosqlxParse_WithMerge(t *testing.T) {
	result := parseSQL(
		"MERGE INTO target t USING source s ON t.id = s.id " +
			"WHEN MATCHED THEN UPDATE SET t.val = s.val " +
			"WHEN NOT MATCHED THEN INSERT (id, val) VALUES (s.id, s.val)")
	// MERGE support is dialect-dependent; success or failure is acceptable.
	t.Logf("MERGE parse: success=%v error=%s", result.Success, result.Error)
}

func TestCGosqlxParse_ErrorContainsPosition(t *testing.T) {
	result := parseSQL("SELECT * FROM WHERE")
	if result.Success {
		t.Log("SQL parsed successfully (parser is lenient)")
		return
	}
	// When an error carries position info both fields should be non-zero together.
	if result.ErrorLine > 0 && result.ErrorColumn == 0 {
		t.Errorf("if ErrorLine is set, ErrorColumn should also be set")
	}
}

// ---------------------------------------------------------------------------
// gosqlx_validate via validateSQL wrapper
// ---------------------------------------------------------------------------

func TestCGosqlxValidate_Valid(t *testing.T) {
	result := validateSQL("SELECT * FROM users WHERE id > 0")
	if !result.Valid {
		t.Errorf("expected valid, got error: %s", result.Error)
	}
}

func TestCGosqlxValidate_Invalid(t *testing.T) {
	result := validateSQL("GARBAGE SQL !!!")
	if result.Valid {
		t.Error("expected invalid SQL to be flagged")
	}
	if result.Error == "" {
		t.Error("expected error message for invalid SQL")
	}
}

func TestCGosqlxValidate_EmptySQL(t *testing.T) {
	result := validateSQL("")
	// Must not panic; validity of empty SQL is implementation-defined.
	t.Logf("empty SQL validate: valid=%v error=%s", result.Valid, result.Error)
}

func TestCGosqlxValidate_WithJoin(t *testing.T) {
	result := validateSQL("SELECT u.id, o.total FROM users u INNER JOIN orders o ON u.id = o.user_id")
	if !result.Valid {
		t.Errorf("expected valid JOIN query: %s", result.Error)
	}
}

// ---------------------------------------------------------------------------
// gosqlx_format via formatSQL wrapper
// ---------------------------------------------------------------------------

func TestCGosqlxFormat_LowercaseInput(t *testing.T) {
	result := formatSQL("select * from users where id=1")
	if !result.Success {
		t.Errorf("expected format success: %s", result.Error)
	}
	if !strings.Contains(strings.ToUpper(result.Formatted), "SELECT") {
		t.Errorf("expected SELECT in formatted output, got: %s", result.Formatted)
	}
}

func TestCGosqlxFormat_MultipleStatements(t *testing.T) {
	result := formatSQL("select 1; select 2")
	if !result.Success {
		t.Errorf("expected format success for multiple stmts: %s", result.Error)
	}
	if result.Formatted == "" {
		t.Error("formatted output should not be empty")
	}
}

func TestCGosqlxFormat_InvalidSQL(t *testing.T) {
	result := formatSQL("SELCT * FORM")
	if result.Success {
		t.Log("invalid SQL accepted by formatter (lenient behaviour)")
	} else {
		if result.Error == "" {
			t.Error("expected error message for invalid SQL")
		}
	}
}

func TestCGosqlxFormat_ComplexQuery(t *testing.T) {
	result := formatSQL("SELECT u.id,u.name,COUNT(o.id) AS order_count FROM users u LEFT JOIN orders o ON u.id=o.user_id WHERE u.active=1 GROUP BY u.id,u.name HAVING COUNT(o.id)>0 ORDER BY order_count DESC")
	if !result.Success {
		t.Errorf("expected format success: %s", result.Error)
	}
}

// ---------------------------------------------------------------------------
// gosqlx_extract_tables via extractTables wrapper
// ---------------------------------------------------------------------------

func TestCGosqlxExtractTables_SingleTable(t *testing.T) {
	result := extractTables("SELECT * FROM users")
	if _, hasError := result["error"]; hasError {
		t.Errorf("unexpected error: %v", result["error"])
	}
	tables, ok := result["tables"].([]interface{})
	if !ok || len(tables) == 0 {
		t.Errorf("expected tables array, got: %v", result)
	}
}

func TestCGosqlxExtractTables_JoinedTables(t *testing.T) {
	result := extractTables("SELECT u.id FROM users u JOIN orders o ON u.id = o.user_id")
	tables, ok := result["tables"].([]interface{})
	if !ok || len(tables) < 2 {
		t.Errorf("expected at least 2 tables for JOIN, got: %v", result)
	}
}

func TestCGosqlxExtractTables_InvalidSQL(t *testing.T) {
	result := extractTables("GARBAGE SQL")
	// Must return valid JSON — either an error field or an empty tables array.
	if result == nil {
		t.Error("expected non-nil result")
	}
	t.Logf("invalid SQL extract_tables: %v", result)
}

// ---------------------------------------------------------------------------
// gosqlx_extract_columns via extractColumns wrapper
// ---------------------------------------------------------------------------

func TestCGosqlxExtractColumns_BasicSelect(t *testing.T) {
	result := extractColumns("SELECT id, name, email FROM users")
	cols, ok := result["columns"].([]interface{})
	if !ok || len(cols) == 0 {
		t.Errorf("expected columns array, got: %v", result)
	}
}

func TestCGosqlxExtractColumns_WithWhere(t *testing.T) {
	result := extractColumns("SELECT id FROM users WHERE active = 1 AND status = 'active'")
	cols, ok := result["columns"].([]interface{})
	if !ok || len(cols) == 0 {
		t.Errorf("expected columns extracted from WHERE clause, got: %v", result)
	}
}

func TestCGosqlxExtractColumns_InvalidSQL(t *testing.T) {
	result := extractColumns("GARBAGE SQL")
	if result == nil {
		t.Error("expected non-nil result")
	}
	t.Logf("invalid SQL extract_columns: %v", result)
}

// ---------------------------------------------------------------------------
// gosqlx_extract_functions via extractFunctions wrapper
// ---------------------------------------------------------------------------

func TestCGosqlxExtractFunctions_Aggregate(t *testing.T) {
	result := extractFunctions("SELECT COUNT(*), SUM(amount), AVG(price) FROM orders")
	fns, ok := result["functions"].([]interface{})
	if !ok || len(fns) == 0 {
		t.Errorf("expected functions array with COUNT/SUM/AVG, got: %v", result)
	}
}

func TestCGosqlxExtractFunctions_Window(t *testing.T) {
	result := extractFunctions("SELECT ROW_NUMBER() OVER (ORDER BY id) FROM users")
	fns, ok := result["functions"].([]interface{})
	if !ok || len(fns) == 0 {
		t.Errorf("expected functions array with ROW_NUMBER, got: %v", result)
	}
}

func TestCGosqlxExtractFunctions_NoFunctions(t *testing.T) {
	result := extractFunctions("SELECT id FROM users")
	if _, hasKey := result["functions"]; !hasKey {
		t.Fatalf("expected functions key in result, got: %v", result)
	}
}

func TestCGosqlxExtractFunctions_InvalidSQL(t *testing.T) {
	result := extractFunctions("GARBAGE SQL")
	if result == nil {
		t.Error("expected non-nil result")
	}
	t.Logf("invalid SQL extract_functions: %v", result)
}

// ---------------------------------------------------------------------------
// gosqlx_extract_metadata via extractMetadata wrapper
// ---------------------------------------------------------------------------

func TestCGosqlxExtractMetadata_Complete(t *testing.T) {
	result := extractMetadata("SELECT u.id, COUNT(o.id) FROM users u JOIN orders o ON u.id = o.user_id GROUP BY u.id")
	if len(result.Tables) == 0 {
		t.Error("expected tables in metadata")
	}
	if len(result.Functions) == 0 {
		t.Error("expected functions (COUNT) in metadata")
	}
}

func TestCGosqlxExtractMetadata_QualifiedNames(t *testing.T) {
	result := extractMetadata("SELECT u.name FROM users u WHERE u.active = 1")
	// Qualified columns must not cause a crash.
	t.Logf("qualified: tables=%v columns_qualified=%d", result.Tables, len(result.ColumnsQualified))
}

func TestCGosqlxExtractMetadata_InvalidSQL(t *testing.T) {
	raw := extractMetadataRaw("GARBAGE SQL")
	if raw == "" {
		t.Error("expected non-empty JSON response for invalid SQL")
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Errorf("expected valid JSON for invalid SQL, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// gosqlx_version via getVersion wrapper
// ---------------------------------------------------------------------------

func TestCGosqlxVersion_Format(t *testing.T) {
	version := getVersion()
	if version == "" {
		t.Error("version string should not be empty")
	}
	if !strings.Contains(version, ".") {
		t.Errorf("version should be semver (X.Y.Z), got: %s", version)
	}
}

func TestCGosqlxVersion_Idempotent(t *testing.T) {
	v1 := getVersion()
	v2 := getVersion()
	if v1 != v2 {
		t.Errorf("gosqlx_version must return the same value on every call: %q vs %q", v1, v2)
	}
}

// ---------------------------------------------------------------------------
// toJSON helper — tested directly (same package)
// ---------------------------------------------------------------------------

func TestToJSON_SuccessResult(t *testing.T) {
	result := ParseResult{Success: true, StmtCount: 2, StmtTypes: []string{"SELECT", "INSERT"}}
	s := toJSONString(result)
	if !strings.Contains(s, `"success":true`) {
		t.Errorf("expected success:true in JSON, got: %s", s)
	}
	if !strings.Contains(s, `"statement_count":2`) {
		t.Errorf("expected statement_count:2 in JSON, got: %s", s)
	}
}

func TestToJSON_ErrorResult(t *testing.T) {
	result := ParseResult{
		Success:     false,
		Error:       "unexpected token",
		ErrorLine:   1,
		ErrorColumn: 7,
	}
	s := toJSONString(result)
	if !strings.Contains(s, `"success":false`) {
		t.Errorf("expected success:false in JSON, got: %s", s)
	}
	if !strings.Contains(s, `"error"`) {
		t.Errorf("expected error field in JSON, got: %s", s)
	}
}

func TestToJSON_FormatResult(t *testing.T) {
	result := FormatResult{Success: true, Formatted: "SELECT *\nFROM users"}
	s := toJSONString(result)
	if s == "" {
		t.Error("expected non-empty JSON")
	}
	var decoded FormatResult
	if err := json.Unmarshal([]byte(s), &decoded); err != nil {
		t.Errorf("expected valid JSON: %v", err)
	}
}

func TestToJSON_ValidationResult(t *testing.T) {
	result := ValidationResult{Valid: false, Error: "syntax error", ErrorLine: 1, ErrorColumn: 5}
	s := toJSONString(result)
	var decoded ValidationResult
	if err := json.Unmarshal([]byte(s), &decoded); err != nil {
		t.Errorf("expected valid JSON: %v", err)
	}
	if decoded.Valid {
		t.Error("expected valid=false")
	}
}
