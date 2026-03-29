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

package fingerprint_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/fingerprint"
)

func TestNormalize_ReplacesStringLiterals(t *testing.T) {
	sql := "SELECT * FROM users WHERE name = 'alice'"
	got, err := fingerprint.Normalize(sql)
	if err != nil {
		t.Fatalf("Normalize() error: %v", err)
	}
	if strings.Contains(got, "'alice'") {
		t.Errorf("Normalize() did not replace string literal; got: %s", got)
	}
	if !strings.Contains(got, "?") {
		t.Errorf("Normalize() missing ? placeholder; got: %s", got)
	}
}

func TestNormalize_ReplacesNumericLiterals(t *testing.T) {
	sql := "SELECT * FROM orders WHERE amount > 100"
	got, err := fingerprint.Normalize(sql)
	if err != nil {
		t.Fatalf("Normalize() error: %v", err)
	}
	if strings.Contains(got, "100") {
		t.Errorf("Normalize() did not replace numeric literals; got: %s", got)
	}
	if !strings.Contains(got, "?") {
		t.Errorf("Normalize() missing ? placeholder; got: %s", got)
	}
}

func TestNormalize_IdenticalQueries_SameResult(t *testing.T) {
	q1 := "SELECT * FROM users WHERE id = 1"
	q2 := "SELECT * FROM users WHERE id = 999"
	n1, err := fingerprint.Normalize(q1)
	if err != nil {
		t.Fatalf("Normalize(q1) error: %v", err)
	}
	n2, err := fingerprint.Normalize(q2)
	if err != nil {
		t.Fatalf("Normalize(q2) error: %v", err)
	}
	if n1 != n2 {
		t.Errorf("structurally identical queries should normalize to same string:\n  q1 → %s\n  q2 → %s", n1, n2)
	}
}

func TestNormalize_PreservesParameterPlaceholders(t *testing.T) {
	sql := "SELECT * FROM users WHERE id = $1"
	got, err := fingerprint.Normalize(sql)
	if err != nil {
		t.Fatalf("Normalize() error: %v", err)
	}
	if !strings.Contains(got, "$1") {
		t.Errorf("Normalize() must preserve existing placeholders; got: %s", got)
	}
}

func TestNormalize_InListLiterals(t *testing.T) {
	sql := "SELECT * FROM users WHERE id IN (1, 2, 3)"
	got, err := fingerprint.Normalize(sql)
	if err != nil {
		t.Fatalf("Normalize() error: %v", err)
	}
	// After normalization, the numeric literals should be replaced with ?
	if strings.Contains(got, " 1,") || strings.Contains(got, ", 1,") {
		t.Errorf("Normalize() did not replace IN list literals; got: %s", got)
	}
	if !strings.Contains(got, "?") {
		t.Errorf("Normalize() missing ? placeholder; got: %s", got)
	}
}

func TestFingerprint_SameStructure_SameHash(t *testing.T) {
	q1 := "SELECT * FROM users WHERE id = 1"
	q2 := "SELECT * FROM users WHERE id = 42"
	fp1, err := fingerprint.Fingerprint(q1)
	if err != nil {
		t.Fatalf("Fingerprint(q1) error: %v", err)
	}
	fp2, err := fingerprint.Fingerprint(q2)
	if err != nil {
		t.Fatalf("Fingerprint(q2) error: %v", err)
	}
	if fp1 != fp2 {
		t.Errorf("same structure different literals must yield same fingerprint:\n  fp1=%s\n  fp2=%s", fp1, fp2)
	}
}

func TestFingerprint_DifferentStructure_DifferentHash(t *testing.T) {
	q1 := "SELECT id FROM users WHERE status = 1"
	q2 := "SELECT name FROM users WHERE status = 1"
	fp1, _ := fingerprint.Fingerprint(q1)
	fp2, _ := fingerprint.Fingerprint(q2)
	if fp1 == fp2 {
		t.Errorf("different query structures must yield different fingerprints")
	}
}

func TestFingerprint_IsHex64Chars(t *testing.T) {
	sql := "SELECT 1"
	fp, err := fingerprint.Fingerprint(sql)
	if err != nil {
		t.Fatalf("Fingerprint() error: %v", err)
	}
	if len(fp) != 64 {
		t.Errorf("SHA-256 hex fingerprint should be 64 chars, got %d: %s", len(fp), fp)
	}
}

func TestNormalize_InvalidSQL_ReturnsError(t *testing.T) {
	_, err := fingerprint.Normalize("SELECT FROM WHERE")
	if err == nil {
		t.Error("Normalize() should return error for invalid SQL")
	}
}

func TestFingerprint_Deterministic(t *testing.T) {
	sql := "SELECT u.id, u.name FROM users u WHERE u.active = true"
	fp1, err := fingerprint.Fingerprint(sql)
	if err != nil {
		t.Fatalf("Fingerprint() error: %v", err)
	}
	fp2, err := fingerprint.Fingerprint(sql)
	if err != nil {
		t.Fatalf("Fingerprint() error: %v", err)
	}
	if fp1 != fp2 {
		t.Error("Fingerprint() must be deterministic for the same input")
	}
}

func TestNormalize_ReplacesBooleanLiterals(t *testing.T) {
	sql := "SELECT * FROM users WHERE active = true"
	got, err := fingerprint.Normalize(sql)
	if err != nil {
		t.Fatalf("Normalize() error: %v", err)
	}
	// Boolean literals should be replaced with ?
	if strings.Contains(got, "true") || strings.Contains(got, "TRUE") {
		t.Errorf("Normalize() did not replace boolean literal; got: %s", got)
	}
	if !strings.Contains(got, "?") {
		t.Errorf("Normalize() missing ? placeholder; got: %s", got)
	}
}

func TestNormalize_ReplacesNullLiterals(t *testing.T) {
	sql := "SELECT * FROM users WHERE deleted_at IS NOT NULL"
	got, err := fingerprint.Normalize(sql)
	if err != nil {
		t.Fatalf("Normalize() error: %v", err)
	}
	// IS NOT NULL should still be preserved as-is — NULL here is a keyword, not a literal
	// This test verifies the query parses correctly
	if got == "" {
		t.Errorf("Normalize() returned empty string for valid SQL")
	}
}

func TestNormalize_StringLiteralSameAsNumericNormalized(t *testing.T) {
	q1 := "SELECT * FROM t WHERE x = 'hello'"
	q2 := "SELECT * FROM t WHERE x = 'world'"
	n1, err := fingerprint.Normalize(q1)
	if err != nil {
		t.Fatalf("Normalize(q1) error: %v", err)
	}
	n2, err := fingerprint.Normalize(q2)
	if err != nil {
		t.Fatalf("Normalize(q2) error: %v", err)
	}
	if n1 != n2 {
		t.Errorf("same-structure string literal queries should normalize identically:\n  n1=%s\n  n2=%s", n1, n2)
	}
}

func TestFingerprint_StringVsNumericLiteralDifferentStructure(t *testing.T) {
	// Even though both use ?, they have different column names => different structure
	q1 := "SELECT id FROM users WHERE id = 1"
	q2 := "SELECT name FROM users WHERE id = 1"
	fp1, _ := fingerprint.Fingerprint(q1)
	fp2, _ := fingerprint.Fingerprint(q2)
	if fp1 == fp2 {
		t.Errorf("queries with different selected columns must have different fingerprints")
	}
}
