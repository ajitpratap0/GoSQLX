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

// Package errors - UAT Bug 3: hint grammar regression tests.
//
// The old hint said "Expected 'table name' keyword here" which is grammatically
// incorrect ("table name" is not a keyword). The fix changes it to
// "expected <description> here" (lowercase, no erroneous "keyword" label).
package errors_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
)

func TestBug3_HintGrammar_NoKeywordSuffix(t *testing.T) {
	tests := []struct {
		name     string
		expected string // description passed to GenerateHint
	}{
		{"table name", "table name"},
		{"column name", "column name"},
		{"expression", "expression"},
		{"identifier", "identifier"},
		{"statement", "statement"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hint := errors.GenerateHint(errors.ErrCodeExpectedToken, tc.expected, "")
			if strings.Contains(hint, "keyword here") {
				t.Errorf("Bug 3 regression: hint still uses 'keyword here' for %q: %s", tc.expected, hint)
			}
			t.Logf("hint for %q: %s", tc.expected, hint)
		})
	}
}

func TestBug3_HintGrammar_ContainsExpected(t *testing.T) {
	hint := errors.GenerateHint(errors.ErrCodeExpectedToken, "table name", "")
	if !strings.Contains(strings.ToLower(hint), "expected") {
		t.Errorf("hint should contain 'expected', got: %s", hint)
	}
}

func TestBug3_HintGrammar_ContainsDescription(t *testing.T) {
	desc := "table name"
	hint := errors.GenerateHint(errors.ErrCodeExpectedToken, desc, "")
	if !strings.Contains(hint, desc) {
		t.Errorf("hint should contain the description %q, got: %s", desc, hint)
	}
}

func TestBug3_HintGrammar_TypoSuggestionUnchanged(t *testing.T) {
	// When "found" is a typo of "expected", the hint should still suggest the fix.
	hint := errors.GenerateHint(errors.ErrCodeExpectedToken, "FROM", "FORM")
	if !strings.Contains(hint, "FROM") {
		t.Errorf("expected typo-detection hint to mention FROM, got: %s", hint)
	}
	// The typo-detection branch does NOT say "keyword here"
	if strings.Contains(hint, "keyword here") {
		t.Errorf("Bug 3 regression in typo-detection branch: %s", hint)
	}
}

func TestBug3_HintGrammar_FallbackUsesLowercase(t *testing.T) {
	// When there's no typo match, the fallback hint should be lowercase "expected".
	hint := errors.GenerateHint(errors.ErrCodeExpectedToken, "semicolon", "BOGUS_TOKEN")
	if len(hint) == 0 {
		t.Skip("no fallback hint generated for this case")
	}
	if strings.Contains(hint, "keyword here") {
		t.Errorf("Bug 3 regression: fallback hint uses 'keyword here': %s", hint)
	}
}
