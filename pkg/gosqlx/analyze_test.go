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

package gosqlx

import (
	"testing"
)

func TestAnalyze_SelectStar(t *testing.T) {
	result, err := Analyze("SELECT * FROM users")
	if err != nil {
		t.Fatalf("Analyze returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Analyze returned nil result")
	}

	// Should find OPT-001 (SELECT *)
	found := false
	for _, s := range result.Suggestions {
		if s.RuleID == "OPT-001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected OPT-001 suggestion for SELECT *, but none found")
	}

	if result.Score >= 100 {
		t.Error("expected score < 100 for SELECT * query")
	}
}

func TestAnalyze_CleanQuery(t *testing.T) {
	result, err := Analyze("SELECT id, name FROM users WHERE active = TRUE")
	if err != nil {
		t.Fatalf("Analyze returned unexpected error: %v", err)
	}

	if result.Score != 100 {
		t.Errorf("expected score 100 for clean query, got %d", result.Score)
	}

	if result.QueryComplexity != "simple" {
		t.Errorf("expected 'simple' complexity, got %q", result.QueryComplexity)
	}
}

func TestAnalyze_ComplexQuery(t *testing.T) {
	sql := `SELECT u.name, COUNT(o.id)
		FROM users u
		JOIN orders o ON u.id = o.user_id
		JOIN products p ON o.product_id = p.id
		GROUP BY u.name
		HAVING COUNT(o.id) > 5`
	result, err := Analyze(sql)
	if err != nil {
		t.Fatalf("Analyze returned unexpected error: %v", err)
	}

	if result.QueryComplexity == "simple" {
		t.Error("expected non-simple complexity for query with multiple JOINs and GROUP BY")
	}
}

func TestAnalyze_InvalidSQL(t *testing.T) {
	_, err := Analyze("SELECT * FROM")
	if err == nil {
		t.Error("expected error for invalid SQL, got nil")
	}
}
