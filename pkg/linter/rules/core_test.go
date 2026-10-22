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

package rules_test

import (
	"slices"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules"
)

func ruleIDs(t *testing.T, cfg rules.CoreConfig) []string {
	t.Helper()
	rs := rules.CoreRules(cfg)
	ids := make([]string, len(rs))
	for i, r := range rs {
		ids[i] = r.ID()
	}
	return ids
}

func TestCoreRules_ExactlyL001ToL010(t *testing.T) {
	// The documented output order: whitespace, style, keywords.
	want := []string{"L001", "L002", "L003", "L004", "L005", "L010", "L006", "L008", "L009", "L007"}
	got := ruleIDs(t, rules.DefaultCoreConfig())
	if !slices.Equal(got, want) {
		t.Fatalf("CoreRules IDs = %v, want %v", got, want)
	}

	sorted := slices.Clone(got)
	slices.Sort(sorted)
	wantSet := []string{"L001", "L002", "L003", "L004", "L005", "L006", "L007", "L008", "L009", "L010"}
	if !slices.Equal(sorted, wantSet) {
		t.Fatalf("CoreRules must contain exactly L001..L010 once each, got %v", sorted)
	}
}

func TestCoreRules_ConfigApplied(t *testing.T) {
	if def := rules.DefaultCoreConfig(); def != (rules.CoreConfig{
		MaxConsecutiveBlankLines: 1, MaxIndentDepth: 4, IndentSize: 4, MaxLineLength: 100,
	}) {
		t.Fatalf("DefaultCoreConfig changed: %+v", def)
	}

	sql := "SELECT id, name, email FROM users WHERE id = 1"
	countL005 := func(maxLen int) int {
		cfg := rules.DefaultCoreConfig()
		cfg.MaxLineLength = maxLen
		res := linter.New(rules.CoreRules(cfg)...).LintString(sql, "<test>")
		n := 0
		for _, v := range res.Violations {
			if v.Rule == "L005" {
				n++
			}
		}
		return n
	}
	if n := countL005(100); n != 0 {
		t.Errorf("MaxLineLength 100: got %d L005 violations, want 0", n)
	}
	if n := countL005(20); n != 1 {
		t.Errorf("MaxLineLength 20: got %d L005 violations, want 1", n)
	}
}

func TestCoreRules_FreshInstances(t *testing.T) {
	a := rules.CoreRules(rules.DefaultCoreConfig())
	b := rules.CoreRules(rules.DefaultCoreConfig())
	for i := range a {
		if a[i] == b[i] {
			t.Fatalf("rule %s shared between calls", a[i].ID())
		}
	}
}
