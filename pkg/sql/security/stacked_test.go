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

package security

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

var stackedOracle = [3]*regexp.Regexp{
	regexp.MustCompile(`;[\s\v]*(?i)(DROP|DELETE|TRUNCATE|UPDATE|INSERT|ALTER)\b`),
	regexp.MustCompile(`;[\s\v]*(?i)EXEC\b`),
	regexp.MustCompile(`;[\s\v]*(?i)EXECUTE\b`),
}

func BenchmarkScanSQLStackedScript(b *testing.B) {
	for _, size := range []int{4 << 10, 30 << 10, 1 << 20} {
		b.Run(fmt.Sprintf("%dKB", size>>10), func(b *testing.B) {
			sql := strings.Repeat("SELECT 1234567;\n", size/16)
			s := NewScanner()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				s.ScanSQL(sql)
			}
		})
	}
}

func BenchmarkStackedMatcher(b *testing.B) {
	for name, sql := range map[string]string{
		"clean":      strings.Repeat("SELECT 1; ", 256),
		"hit":        strings.Repeat("SELECT 1; ", 256) + "; DROP x; EXEC x; EXECUTE x",
		"semicolons": strings.Repeat(";", 4096),
		"whitespace": strings.Repeat("; \t\n", 1024),
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				stackedMatches([]string{sql})
			}
		})
	}
}

// stackedReference deliberately retains the original regexp decisions.
func stackedReference(s *Scanner, views []string, result *ScanResult) {
	patternsOnce.Do(initPatterns)
	group := regexGroups[PatternStackedQuery]
	for _, re := range stackedOracle {
		for _, view := range views {
			if m := re.FindString(view); m != "" {
				f := Finding{Severity: group.severity, Pattern: PatternStackedQuery,
					Description: "Pattern detected: " + m, Risk: group.risk, Suggestion: group.suggestion}
				if s.shouldInclude(f.Severity) {
					result.Findings = append(result.Findings, f)
				}
				break
			}
		}
	}
}

func TestStackedOracleBaseline(t *testing.T) {
	rng := rand.New(rand.NewSource(609))
	alphabet := []string{";", " ", "\t", "\v", "\f", "\r", "\n", "\u0085", "\u00a0", "DROP", "delete", "TRUNCATE", "update", "INſERT", "alter", "EXEC", "EXECUTE", "ı", "İ", "é", "_", "9", "\xff", "\xc5", "\xa0", "--", "/*", "*/", "'", "$$"}
	s := NewScanner()
	for i := 0; i < 10000; i++ {
		var b strings.Builder
		for n := rng.Intn(20); n > 0; n-- {
			b.WriteString(alphabet[rng.Intn(len(alphabet))])
		}
		views := []string{b.String(), "; EXEC x; DELETE y"}
		got, want := &ScanResult{}, &ScanResult{}
		detectStackedQueries(s, views, got)
		stackedReference(s, views, want)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("views %q: got %+v, want %+v", views, got, want)
		}
	}
}

func TestStackedMatcherCases(t *testing.T) {
	cases := [][]string{
		{"; DROPé; EXECUTE x; EXEC y"}, {";\v\fINſERT x; EXECUTE_; EXEC x"},
		{";\u00a0DROP x;\u0085DELETE x; INıERT x; INİERT x"},
		{"; DROP\xff; EXECUTE; EXEC"}, {"; DROP x; DROP y", "; DELETE z; EXEC x; EXECUTE x"},
		{";/**/DROP x", "; DROP x"}, {"; EXECUTE x; EXEC x; DELETE x"},
		{";\vDROP"}, {";\fDELETE"}, {"; INSERT"}, {"; INſERT"},
		{";\u0085DROP"}, {";\u00a0DROP"}, {"; ınsert"}, {"; İnsert"},
		{"; DROPé"}, {"; DROP_"}, {"; DROP"},
		{"; DROP x; DELETE y"}, {"; DROP x", "; DELETE y"},
		{"; EXECUTE"}, {"; EXECUTE x; EXEC x; DROP x"},
		{"; \tDROP"}, {"; DROP x; EXEC x; EXECUTE x"},
	}
	s := NewScanner()
	for _, views := range cases {
		got, want := &ScanResult{}, &ScanResult{}
		detectStackedQueries(s, views, got)
		stackedReference(s, views, want)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("views %q: got %+v, want %+v", views, got, want)
		}
	}
}

func TestStackedExplicitAlternatives(t *testing.T) {
	for _, verb := range []string{"DROP", "DELETE", "TRUNCATE", "UPDATE", "INSERT", "ALTER", "EXEC", "EXECUTE"} {
		input := ";" + verb
		slot := 0
		if verb == "EXEC" {
			slot = 1
		}
		if verb == "EXECUTE" {
			slot = 2
		}
		if got := stackedMatches([]string{input})[slot]; got != input {
			t.Errorf("%s: got %q, want %q", verb, got, input)
		}
	}
}

func TestStackedSeverityFilter(t *testing.T) {
	patternsOnce.Do(initPatterns)
	group := regexGroups[PatternStackedQuery]
	original := group.severity
	group.severity = SeverityHigh
	t.Cleanup(func() { group.severity = original })
	s := NewScanner()
	s.MinSeverity = SeverityCritical
	got := &ScanResult{}
	detectStackedQueries(s, []string{"; DROP"}, got)
	if len(got.Findings) != 0 {
		t.Fatalf("filtered finding: %+v", got.Findings)
	}
}

func TestStackedMatcherLinear(t *testing.T) {
	for name, unit := range map[string]string{"semicolons": ";", "whitespace": ";   \t\n"} {
		t.Run(name, func(t *testing.T) {
			makeInput := func(n int) string { return strings.Repeat(unit, n/len(unit)) }
			small, large := makeInput(1<<20), makeInput(2<<20)
			sample := func(s string) time.Duration {
				start := time.Now()
				for i := 0; i < 3; i++ {
					if got := stackedMatches([]string{s}); got != [3]string{} {
						t.Fatalf("unexpected match: %q", got)
					}
				}
				return time.Since(start)
			}
			var a, b time.Duration
			for i := 0; i < 5; i++ {
				x, y := sample(small), sample(large)
				if i == 0 || x < a {
					a = x
				}
				if i == 0 || y < b {
					b = y
				}
			}
			t.Logf("1 MiB %v, 2 MiB %v, ratio %.2f", a, b, float64(b)/float64(a))
			if b > 3*a {
				t.Fatalf("scaling exceeds linear allowance: %v vs %v", a, b)
			}
		})
	}
}

func FuzzStackedMatcher(f *testing.F) {
	for _, s := range stackedGoldenInputs {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		got := stackedMatches([]string{input})
		for i, re := range stackedOracle {
			if want := re.FindString(input); got[i] != want {
				t.Fatalf("pattern %d: got %q, want %q", i, got[i], want)
			}
		}
	})
}

var stackedGoldenInputs = []string{
	"SELECT 1; DROP TABLE users; EXEC x; EXECUTE y",
	"SELECT 1;\v\fInſert INTO t VALUES (1); EXECUTE x; EXEC y",
	"SELECT '; DROP x';/**/DELETE FROM t",
	"SELECT 1;-- comment\nUPDATE t SET x=1",
	"SELECT $$; DROP TABLE x$$; ALTER TABLE t ADD x int",
	"SELECT 1; DROPé; EXECUTE_foo; EXEC\xff",
	"SELECT 1;\u00a0DROP x;\u0085DELETE x; INıERT x",
	"SELECT 1; EXECUTE x; EXEC y; DELETE z; DROP w",
}

func TestStackedFindingsGolden(t *testing.T) {
	got := make([]*ScanResult, 0, len(stackedGoldenInputs))
	for _, input := range stackedGoldenInputs {
		got = append(got, NewScanner().ScanSQL(input))
	}
	const path = "testdata/stacked_findings.json"
	if os.Getenv("UPDATE_STACKED_GOLDEN") == "1" {
		data, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want []*ScanResult
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stacked findings differ from baseline golden\ngot: %+v\nwant: %+v", got, want)
	}
}
