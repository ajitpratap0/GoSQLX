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
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// contractFixture is type-checked against the website's TypeScript mirror of
// the bridge types by website/src/components/playground/bridgeContract.check.ts.
var contractFixture = filepath.Join("..", "..", "..", "website", "src", "components", "playground", "bridgeContract.fixture.json")

// contractSample returns one response of each kind with every field set, so
// that no key is dropped by omitempty and the fixture lists the full contract.
func contractSample() any {
	sampleSpan := &ErrorSpan{
		Code: "E2002", Message: "message", Line: 1, Column: 14, EndLine: 1, EndColumn: 14,
	}
	return struct {
		Lint      LintResponse      `json:"lint"`
		Analyze   AnalyzeResponse   `json:"analyze"`
		Highlight HighlightResponse `json:"highlight"`
	}{
		Lint: LintResponse{
			ParseError:     "parse error",
			ParseErrorSpan: sampleSpan,
			Error:          "lint error",
			Violations: []LintViolation{{
				Rule: "L016", RuleName: "Select Star", Severity: "warning", Message: "message",
				Line: 1, Column: 1, Suggestion: "suggestion",
			}},
		},
		Analyze: AnalyzeResponse{
			ParseError:     "parse error",
			ParseErrorSpan: sampleSpan,
			Security: &SecurityReport{
				Findings: []SecurityFinding{{
					Severity: "high", Pattern: "TAUTOLOGY", Description: "description", Risk: "risk",
					Line: 1, Column: 1, SQL: "1=1", Suggestion: "suggestion",
				}},
				TotalCount: 1, CriticalCount: 0, HighCount: 1, MediumCount: 0, LowCount: 0,
			},
			Optimization: &OptimizationReport{
				Score: 90, Complexity: "simple",
				Suggestions: []OptimizationSuggestion{{
					RuleID: "OPT-001", Severity: "warning", Message: "message", Detail: "detail",
					Line: 1, Column: 1, OriginalSQL: "SELECT *", SuggestedSQL: "SELECT id",
				}},
			},
		},
		Highlight: HighlightResponse{
			Spans: []HighlightSpan{{Start: 0, End: 6, Category: "keyword"}},
		},
	}
}

// TestContractFixture keeps the JSON fixture the website type-checks in step
// with the Go response types. After changing a JSON tag, regenerate it with
//
//	UPDATE_CONTRACT_FIXTURE=1 go test ./wasm/internal/bridge -run TestContractFixture
//
// and update website/src/components/playground/bridgeTypes.ts until the
// website's `npm run typecheck` passes.
func TestContractFixture(t *testing.T) {
	want, err := json.MarshalIndent(contractSample(), "", "  ")
	if err != nil {
		t.Fatalf("marshal contract sample: %v", err)
	}
	want = append(want, '\n')

	if os.Getenv("UPDATE_CONTRACT_FIXTURE") == "1" {
		if err := os.WriteFile(contractFixture, want, 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		return
	}

	got, err := os.ReadFile(contractFixture)
	if err != nil {
		t.Fatalf("read fixture %s: %v", contractFixture, err)
	}
	got = bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is out of date with the Go response types; regenerate it with UPDATE_CONTRACT_FIXTURE=1 and update bridgeTypes.ts.\nwant:\n%s", contractFixture, want)
	}
}
