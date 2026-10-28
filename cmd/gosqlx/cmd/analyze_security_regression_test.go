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

package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/security"
)

func TestAnalyzeSecurityRawSQLFindings(t *testing.T) {
	for _, sql := range []string{"SELECT 1; DROP TABLE users", "SELECT '$x$'; DROP TABLE users; SELECT '$x$'"} {
		t.Run(sql, func(t *testing.T) {
			var out, errOut bytes.Buffer
			analyzer := NewAnalyzer(&out, &errOut, CLIAnalyzerOptions{Security: true, Format: "json"})
			result, err := analyzer.Analyze(sql)
			if err != nil {
				t.Fatal(err)
			}
			if result.Report.CriticalIssues == 0 || result.Report.SecurityScore >= 100 {
				t.Fatalf("missing critical finding/score: %+v", result.Report)
			}
			if err := analyzer.DisplayReport(result.Report); err != nil {
				t.Fatal(err)
			}
			var report AnalysisReport
			if err := json.Unmarshal(out.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, issue := range report.Issues {
				if issue.ID == string(security.PatternStackedQuery) && issue.Severity == IssueSeverityCritical {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing stacked query in JSON: %s", out.String())
			}
			out.Reset()
			analyzer.Opts.Format = "table"
			if err := analyzer.DisplayReport(result.Report); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "CRITICAL") {
				t.Fatalf("missing critical finding in text: %s", out.String())
			}
		})
	}
	var out bytes.Buffer
	analyzer := NewAnalyzer(&out, &out, CLIAnalyzerOptions{Security: true})
	result, err := analyzer.Analyze("SELECT id FROM users WHERE id = 1")
	if err != nil {
		t.Fatal(err)
	}
	if issues := filterIssuesByCategory(result.Report.Issues, IssueCategorySecurity); len(issues) != 0 {
		t.Fatalf("clean SQL security issues: %+v", issues)
	}
	if _, err := analyzer.Analyze("SELECT 1 UNION/**/SELECT 2"); err != nil {
		t.Fatalf("inline SQL treated as path: %v", err)
	}
}

func TestLintSecurityRawSQLFindings(t *testing.T) {
	for _, sql := range []string{"SELECT 1; DROP TABLE users", "SELECT '$x$'; DROP TABLE users; SELECT '$x$'"} {
		var out bytes.Buffer
		if count := runSecurityScan(sql, "inline", &out); count == 0 || !strings.Contains(out.String(), "[CRITICAL]") || !strings.Contains(out.String(), string(security.PatternStackedQuery)) {
			t.Fatalf("missing critical finding: %d %s", count, out.String())
		}
	}
	var out bytes.Buffer
	if count := runSecurityScan("SELECT id FROM users WHERE id = 1", "inline", &out); count != 0 {
		t.Fatalf("clean SQL findings: %d %s", count, out.String())
	}
}

func TestMergeSecurityFindingsDeduplicatesAndCounts(t *testing.T) {
	critical := security.Finding{Pattern: security.PatternStackedQuery, Severity: security.SeverityCritical, Description: "stacked"}
	high := security.Finding{Pattern: security.PatternUnionGeneric, Severity: security.SeverityHigh, Description: "union"}
	result := mergeSecurityFindings(&security.ScanResult{Findings: []security.Finding{critical}}, &security.ScanResult{Findings: []security.Finding{critical, high}})
	if len(result.Findings) != 2 || result.TotalCount != 2 || result.CriticalCount != 1 || result.HighCount != 1 {
		t.Fatalf("incorrect merged summary: %+v", result)
	}
}

func TestAnalyzeSecurityExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "SELECT query.sql")
	if err := os.WriteFile(path, []byte("SELECT 1; DROP TABLE users"), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	analyzer := NewAnalyzer(&out, &out, CLIAnalyzerOptions{Security: true})
	result, err := analyzer.Analyze(path)
	if err != nil {
		t.Fatal(err)
	}
	if result.Report.CriticalIssues == 0 {
		t.Fatalf("file contents not scanned: %+v", result.Report)
	}
}
