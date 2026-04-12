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

func TestLint_SelectStar(t *testing.T) {
	result, err := Lint("SELECT * FROM users")
	if err != nil {
		t.Fatalf("Lint returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Lint returned nil result")
	}

	// Should find at least L016 (SELECT *)
	found := false
	for _, v := range result.Violations {
		if v.Rule == "L016" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected L016 (SELECT *) violation, but none found")
	}
}

func TestLint_CleanSQL(t *testing.T) {
	// A well-formed query should still lint without error
	result, err := Lint("SELECT id, name FROM users WHERE active = TRUE")
	if err != nil {
		t.Fatalf("Lint returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Lint returned nil result")
	}
}

func TestLint_DeleteWithoutWhere(t *testing.T) {
	result, err := Lint("DELETE FROM users")
	if err != nil {
		t.Fatalf("Lint returned unexpected error: %v", err)
	}

	found := false
	for _, v := range result.Violations {
		if v.Rule == "L011" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected L011 (DELETE without WHERE) violation, but none found")
	}
}

func TestLint_AllRulesCreated(t *testing.T) {
	rules := allRules()
	if len(rules) != 30 {
		t.Errorf("expected 30 rules, got %d", len(rules))
	}
}
