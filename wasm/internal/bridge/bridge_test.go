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

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	sqlkeywords "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
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

// TestLint_DialectOnlySQLRunsASTRules guards #739 for non-generic dialects:
// SQL that parses only in the selected dialect must still get the AST-level
// rules, so the playground can never call it clean when it is not.
func TestLint_DialectOnlySQLRunsASTRules(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		dialect string
		want    []string
	}{
		{name: "sqlserver TOP and brackets", sql: "SELECT TOP 10 * FROM [users]", dialect: "sqlserver", want: []string{"L016", "L017"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse(tt.sql, "generic"); err == nil {
				t.Fatalf("test needs SQL the generic parser rejects; %q parsed", tt.sql)
			}
			resp := Lint(tt.sql, tt.dialect)
			if resp.ParseError != "" || resp.Error != "" {
				t.Fatalf("unexpected error: parse=%q lint=%q", resp.ParseError, resp.Error)
			}
			if len(resp.Violations) == 0 {
				t.Fatal("dialect SQL reported clean: AST rules did not run")
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
	if Dialect("") != "" {
		t.Error("empty dialect should resolve to the default")
	}
	for _, name := range sqlkeywords.DialectNames() {
		if got := Dialect(name); string(got) != name {
			t.Errorf("Dialect(%q) = %q, want %q", name, got, name)
		}
	}
}

func TestFormat(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		dialect string
		want    string
	}{
		{name: "sqlserver keeps TOP", sql: "SELECT TOP 10 * FROM t", dialect: "sqlserver", want: "SELECT TOP 10 *\nFROM t"},
		{name: "leading comment kept", sql: "-- c\nSELECT 1", dialect: "generic", want: "-- c\nSELECT 1"},
		{name: "inline comment moves above the statement", sql: "-- top\nSELECT /* inline */ a FROM t", dialect: "sqlserver", want: "-- top\n/* inline */\nSELECT a\nFROM t"},
		{name: "unknown dialect is generic", sql: "SELECT 1", dialect: "nope", want: "SELECT 1"},
		{name: "empty dialect is generic", sql: "select id,name from users where id>5", dialect: "", want: "SELECT id, name\nFROM users\nWHERE id > 5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := Format(tt.sql, tt.dialect)
			if resp.Error != "" {
				t.Fatalf("unexpected error: %s", resp.Error)
			}
			if resp.Result != tt.want {
				t.Fatalf("Format(%q, %q) = %q, want %q", tt.sql, tt.dialect, resp.Result, tt.want)
			}
		})
	}
}

// TestFormat_UsesDialect guards against formatting with the generic rules:
// TOP does not parse there, so the result depends on the selected dialect.
func TestFormat_UsesDialect(t *testing.T) {
	resp := Format("SELECT TOP 10 * FROM t", "generic")
	if resp.Error == "" {
		t.Fatalf("generic should reject TOP; got %q", resp.Result)
	}
}

func TestFormat_UnplaceableComment(t *testing.T) {
	sql := "SELECT a FROM t /*+ hint */ WHERE x = 1"
	resp := Format(sql, "generic")
	if resp.Result != "" || !strings.Contains(resp.Error, formatter.ErrUnplaceableComment.Error()) {
		t.Fatalf("expected an unplaceable-comment error, got %+v", resp)
	}
}

func TestTranspile(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		from, to string
		want     string
	}{
		{name: "backticks to double quotes", sql: "SELECT `Order Id` FROM t", from: "mysql", to: "postgresql", want: `SELECT "Order Id" FROM t`},
		{name: "string escapes retargeted", sql: `SELECT a FROM t WHERE n = 'it\'s'`, from: "mysql", to: "postgresql", want: "SELECT a FROM t WHERE n = 'it''s'"},
		{name: "pg power to POWER()", sql: "SELECT 2 ^ 3", from: "postgresql", to: "mysql", want: "SELECT POWER(2, 3)"},
		{name: "mysql xor to pg #", sql: "SELECT a ^ b FROM t", from: "mysql", to: "postgresql", want: "SELECT a # b FROM t"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := Transpile(tt.sql, tt.from, tt.to)
			if resp.Error != "" {
				t.Fatalf("unexpected error: %s", resp.Error)
			}
			if resp.Result != tt.want {
				t.Fatalf("Transpile(%q, %s, %s) = %q, want %q", tt.sql, tt.from, tt.to, resp.Result, tt.want)
			}
		})
	}
}

func TestTranspile_Errors(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		from, to string
		contains string
	}{
		{name: "xor has no oracle form", sql: "SELECT a ^ b FROM t", from: "mysql", to: "oracle", contains: "no equivalent in oracle"},
		{name: "source parse error", sql: invalidSQL, from: "mysql", to: "postgresql", contains: "E2002"},
		{name: "unknown source", sql: "SELECT 1", from: "nope", to: "postgresql", contains: `source dialect "nope"`},
		{name: "unknown target", sql: "SELECT 1", from: "mysql", to: "nope", contains: `target dialect "nope"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := Transpile(tt.sql, tt.from, tt.to)
			if resp.Result != "" || !strings.Contains(resp.Error, tt.contains) {
				t.Fatalf("expected an error containing %q, got %+v", tt.contains, resp)
			}
		})
	}
}

func TestTextResponse_JSONContract(t *testing.T) {
	ok, err := json.Marshal(Transpile("SELECT 1", "", ""))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(ok) != `{"result":"SELECT 1"}` {
		t.Fatalf("success payload = %s", ok)
	}
	for _, tt := range []struct {
		name string
		resp TextResponse
	}{
		{"format", Format(invalidSQL, "generic")},
		{"transpile", Transpile(invalidSQL, "mysql", "postgresql")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bad, err := json.Marshal(tt.resp)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var raw map[string]any
			if err := json.Unmarshal(bad, &raw); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			for _, key := range []string{"result", "error"} {
				if _, ok := raw[key]; !ok {
					t.Errorf("error payload missing %q: %s", key, bad)
				}
			}
			if _, ok := raw["error_span"]; ok {
				t.Errorf("error payload contains unused error_span: %s", bad)
			}
		})
	}
}
