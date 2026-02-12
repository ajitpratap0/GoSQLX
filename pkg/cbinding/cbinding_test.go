package main

import (
	"encoding/json"
	"testing"
)

// Note: Cannot test C exports directly in Go tests.
// This file tests the underlying Go logic (struct serialization).

func TestParseResultJSON(t *testing.T) {
	result := ParseResult{
		Success:   true,
		StmtCount: 1,
		StmtTypes: []string{"SELECT"},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded ParseResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if !decoded.Success {
		t.Error("Expected success=true")
	}
	if decoded.StmtCount != 1 {
		t.Errorf("Expected statement_count=1, got %d", decoded.StmtCount)
	}
	if len(decoded.StmtTypes) != 1 || decoded.StmtTypes[0] != "SELECT" {
		t.Errorf("Expected statement_types=[SELECT], got %v", decoded.StmtTypes)
	}
}

func TestParseResultWithError(t *testing.T) {
	result := ParseResult{
		Success:   false,
		Error:     "syntax error near 'SELCT'",
		StmtCount: 0,
		StmtTypes: nil,
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded ParseResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.Success {
		t.Error("Expected success=false")
	}
	if decoded.Error != "syntax error near 'SELCT'" {
		t.Errorf("Unexpected error: %s", decoded.Error)
	}
}

func TestValidationResultJSON(t *testing.T) {
	result := ValidationResult{Valid: true}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded ValidationResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if !decoded.Valid {
		t.Error("Expected valid=true")
	}
	if decoded.Error != "" {
		t.Errorf("Expected empty error, got: %s", decoded.Error)
	}
}

func TestValidationResultInvalid(t *testing.T) {
	result := ValidationResult{Valid: false, Error: "unexpected token"}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded ValidationResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.Valid {
		t.Error("Expected valid=false")
	}
	if decoded.Error != "unexpected token" {
		t.Errorf("Expected 'unexpected token', got: %s", decoded.Error)
	}
}

func TestParseResultOmitEmptyError(t *testing.T) {
	result := ParseResult{
		Success:   true,
		StmtCount: 2,
		StmtTypes: []string{"SELECT", "INSERT"},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Verify "error" key is omitted when empty
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Failed to unmarshal to map: %v", err)
	}

	if _, exists := raw["error"]; exists {
		t.Error("Expected 'error' field to be omitted when empty")
	}
}
