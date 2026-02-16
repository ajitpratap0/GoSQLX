package actioncmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempSQL(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "test.sql")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLintFile_FilterSpecificRule(t *testing.T) {
	// Trailing whitespace triggers L001; lowercase keyword triggers L007.
	path := writeTempSQL(t, "select 1; \n")

	violations := lintFile(path, []string{"L001"})
	if len(violations) == 0 {
		t.Fatal("expected at least one L001 violation for trailing whitespace")
	}
	for _, v := range violations {
		if !strings.Contains(v.Message, "L001") {
			t.Errorf("expected only L001 violations, got: %s", v.Message)
		}
	}
}

func TestLintFile_EmptyRulesRunsAll(t *testing.T) {
	// Trailing whitespace (L001) + lowercase keyword (L007).
	path := writeTempSQL(t, "select 1; \n")

	violations := lintFile(path, nil)
	ruleIDs := make(map[string]bool)
	for _, v := range violations {
		if i := strings.Index(v.Message, "["); i >= 0 {
			if j := strings.Index(v.Message[i:], "]"); j > 0 {
				ruleIDs[v.Message[i+1:i+j]] = true
			}
		}
	}
	if len(ruleIDs) < 2 {
		t.Errorf("expected violations from multiple rules, got: %v", ruleIDs)
	}
}

func TestLintFile_InvalidRuleIgnored(t *testing.T) {
	path := writeTempSQL(t, "SELECT 1;\n")

	violations := lintFile(path, []string{"INVALID_RULE"})
	if len(violations) != 0 {
		t.Errorf("expected no violations for invalid rule, got %d", len(violations))
	}
}
