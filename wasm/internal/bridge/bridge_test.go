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

package bridge

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	invalidSQL = "SELEC * FORM users WHERE"
	riskySQL   = "SELECT * FROM users WHERE id = 1 OR 1=1; DROP TABLE users; UPDATE accounts SET balance = 0;"
)

func ruleIDs(vs []LintViolation) map[string]bool {
	ids := make(map[string]bool, len(vs))
	for _, v := range vs {
		ids[v.Rule] = true
	}
	return ids
}

func TestLint_ReportsParseError(t *testing.T) {
	resp := Lint(invalidSQL, "generic")
	if resp.ParseError == "" {
		t.Fatalf("expected a parse error for %q, got none (violations: %d)", invalidSQL, len(resp.Violations))
	}
	if resp.Error != "" {
		t.Fatalf("unexpected lint error: %s", resp.Error)
	}
}

func TestLint_RunsFullRuleSet(t *testing.T) {
	// Each query targets an AST-level rule that the old three-rule playground
	// linter (L001, L002, L007) could never report.
	tests := []struct {
		name string
		sql  string
		want []string
	}{
		{name: "select star, update without where, drop", sql: riskySQL, want: []string{"L012", "L013", "L016"}},
		{name: "implicit cross join", sql: "SELECT a.id FROM a, b", want: []string{"L023"}},
		{name: "delete without where", sql: "DELETE FROM users", want: []string{"L011"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := Lint(tt.sql, "generic")
			if resp.ParseError != "" {
				t.Fatalf("unexpected parse error: %s", resp.ParseError)
			}
			got := ruleIDs(resp.Violations)
			for _, id := range tt.want {
				if !got[id] {
					t.Errorf("expected rule %s to fire, got %v", id, got)
				}
			}
		})
	}
}

func TestLint_JSONContract(t *testing.T) {
	b, err := json.Marshal(Lint("select id from users", "postgresql"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	vs, ok := raw["violations"].([]any)
	if !ok || len(vs) == 0 {
		t.Fatalf("expected a non-empty violations array, got %s", b)
	}
	v, ok := vs[0].(map[string]any)
	if !ok {
		t.Fatalf("violation is not an object: %s", b)
	}
	for _, key := range []string{"rule", "rule_name", "severity", "message", "line", "column"} {
		if _, ok := v[key]; !ok {
			t.Errorf("violation missing %q key: %s", key, b)
		}
	}
	if _, ok := raw["parse_error"]; ok {
		t.Errorf("parse_error must be omitted for valid SQL: %s", b)
	}
}

func TestAnalyze_ParseErrorHasNoScores(t *testing.T) {
	resp := Analyze(invalidSQL, "generic")
	if resp.ParseError == "" {
		t.Fatal("expected a parse error")
	}
	if resp.Security != nil || resp.Optimization != nil {
		t.Fatalf("SQL that fails to parse must not be scored: %+v", resp)
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "score") || strings.Contains(string(b), "security") {
		t.Fatalf("parse-error payload must carry no scores: %s", b)
	}
}

func TestAnalyze_SecurityFindingsMatchCounts(t *testing.T) {
	resp := Analyze(riskySQL, "generic")
	if resp.ParseError != "" {
		t.Fatalf("unexpected parse error: %s", resp.ParseError)
	}
	sec := resp.Security
	if sec == nil {
		t.Fatal("missing security report")
	}
	if sec.TotalCount == 0 {
		t.Fatal("expected security findings for a tautology query")
	}
	if len(sec.Findings) != sec.TotalCount {
		t.Fatalf("findings listed (%d) must match total_count (%d)", len(sec.Findings), sec.TotalCount)
	}
	if got := sec.CriticalCount + sec.HighCount + sec.MediumCount + sec.LowCount; got != sec.TotalCount {
		t.Fatalf("severity counts sum to %d, total_count is %d", got, sec.TotalCount)
	}
	for _, f := range sec.Findings {
		if f.Severity == "" || f.Description == "" {
			t.Errorf("finding missing severity or description: %+v", f)
		}
	}
}

func TestAnalyze_SuggestionsUseSnakeCaseKeys(t *testing.T) {
	resp := Analyze(riskySQL, "generic")
	if resp.Optimization == nil || len(resp.Optimization.Suggestions) == 0 {
		t.Fatalf("expected optimization suggestions, got %+v", resp.Optimization)
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw struct {
		Optimization struct {
			Score       *int             `json:"score"`
			Complexity  string           `json:"complexity"`
			Suggestions []map[string]any `json:"suggestions"`
		} `json:"optimization"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if raw.Optimization.Score == nil || raw.Optimization.Complexity == "" {
		t.Fatalf("missing score/complexity: %s", b)
	}
	for _, s := range raw.Optimization.Suggestions {
		for _, key := range []string{"rule_id", "severity", "message"} {
			if v, ok := s[key].(string); !ok || v == "" {
				t.Errorf("suggestion missing %q: %v", key, s)
			}
		}
	}
}

func TestDialect(t *testing.T) {
	if Dialect("postgresql") == "" {
		t.Error("postgresql should resolve to a dialect")
	}
	if Dialect("nope") != "" {
		t.Error("unknown dialect should resolve to the default")
	}
}
