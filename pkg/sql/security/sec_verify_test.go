package security

import (
	"testing"
)

// Verify SEC-1: ScanSQL detects tautology (OR 1=1)
func TestSEC1_TautologyInScanSQL(t *testing.T) {
	scanner := NewScanner()

	testCases := []struct {
		sql         string
		description string
	}{
		{"SELECT * FROM users WHERE username='admin' OR 1=1 --", "OR 1=1"},
		{"SELECT * FROM users WHERE id=1 OR 'a'='a'", "'a'='a'"},
		{"SELECT * FROM users WHERE col=col", "identifier=identifier"},
		{"SELECT * FROM users WHERE status=1 OR TRUE", "OR TRUE"},
	}

	for _, tc := range testCases {
		result := scanner.ScanSQL(tc.sql)
		found := false
		for _, f := range result.Findings {
			if f.Pattern == PatternTautology {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("SEC-1 FAIL: tautology not detected in: %s", tc.description)
		} else {
			t.Logf("SEC-1 PASS: tautology detected in: %s", tc.description)
		}
	}
}

// Verify SEC-2: Legitimate UNION SELECT is HIGH not CRITICAL
func TestSEC2_LegitimateUnionNotCritical(t *testing.T) {
	scanner := NewScanner()

	// Legitimate UNION between two real tables
	sql := "SELECT * FROM active_users UNION SELECT * FROM archived_users"
	result := scanner.ScanSQL(sql)

	for _, f := range result.Findings {
		if f.Pattern == PatternUnionGeneric {
			if f.Severity == SeverityCritical {
				t.Errorf("SEC-2 FAIL: legitimate UNION SELECT flagged as CRITICAL (got %s)", f.Severity)
			} else {
				t.Logf("SEC-2 PASS: legitimate UNION SELECT flagged as %s (not CRITICAL)", f.Severity)
			}
		}
		if f.Pattern == PatternUnionInjection {
			t.Logf("Also found UnionInjection finding: %s (severity=%s)", f.Description, f.Severity)
		}
	}
}

// Verify SEC-2: Injection UNION SELECT (with information_schema) is CRITICAL
func TestSEC2_InjectionUnionIsCritical(t *testing.T) {
	scanner := NewScanner()

	sql := "SELECT * FROM users UNION SELECT table_name FROM information_schema.tables"
	result := scanner.ScanSQL(sql)

	hasCritical := false
	for _, f := range result.Findings {
		if f.Severity == SeverityCritical {
			hasCritical = true
			t.Logf("SEC-2 PASS: injection UNION with information_schema is CRITICAL: %s", f.Pattern)
		}
	}
	if !hasCritical {
		t.Errorf("SEC-2 FAIL: expected CRITICAL for UNION with information_schema")
	}
}
