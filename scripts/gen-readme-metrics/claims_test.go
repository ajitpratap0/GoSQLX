package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

var testMetrics = metrics{
	ParseNsPerOp: 318, Hardware: "Apple M4", GoVersion: "1.27",
	Dialects: 8, SQL99Estimate: "~80–85%", Stage: "parse",
}

func TestCheckMeasuredTag(t *testing.T) {
	cases := []struct {
		name, measured, version string
		wantBad                 bool
	}{
		{"matches", "v1.17.0", "1.17.0", false},
		{"older release", "v1.16.0", "1.17.0", true},
		{"empty", "", "1.17.0", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(checkMeasuredTag(tc.measured, tc.version)) > 0; got != tc.wantBad {
				t.Fatalf("bad=%v, want %v", got, tc.wantBad)
			}
		})
	}
}

func TestCheckCompareResults(t *testing.T) {
	const sha = "3655a37900cd391b7673e3e22a27699862cd3a28"
	cases := []struct {
		name, raw string
		wantBad   bool
		contains  string
	}{
		{"matching clean fresh", fmt.Sprintf(`{"commit":%q,"dirty":false,"generatedAt":"2026-10-31T13:55:00Z"}`, sha), false, ""},
		{"different commit", `{"commit":"e9c5db91a8eda4f98d697a53dbd997ebd5255c87","dirty":false,"generatedAt":"2026-10-31T13:55:00Z"}`, true, "3655a379"},
		{"dirty", fmt.Sprintf(`{"commit":%q,"dirty":true,"generatedAt":"2026-10-31T13:55:00Z"}`, sha), true, "dirty"},
		{"missing generatedAt", fmt.Sprintf(`{"commit":%q,"dirty":false}`, sha), true, "generatedAt"},
		{"old generatedAt", fmt.Sprintf(`{"commit":%q,"dirty":false,"generatedAt":"2026-10-30T13:55:00Z"}`, sha), true, "older"},
		{"invalid JSON", `{broken`, true, "JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := checkCompareResults([]byte(tc.raw), sha, "2026-10-31")
			if got := len(problems) > 0; got != tc.wantBad {
				t.Fatalf("problems=%v, want bad=%v", problems, tc.wantBad)
			}
			if tc.contains != "" && (len(problems) == 0 || !strings.Contains(strings.Join(problems, "\n"), tc.contains)) {
				t.Fatalf("problems %v do not contain %q", problems, tc.contains)
			}
		})
	}
}

// isolateGit removes the GIT_* variables a git hook exports (GIT_DIR,
// GIT_INDEX_FILE, ...) so the fixture repo never touches the caller's repo.
func isolateGit(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		name, value, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, "GIT_") {
			continue
		}
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Setenv(name, value) })
	}
}

func TestRunClaimsMissingCompareResults(t *testing.T) {
	isolateGit(t)
	original := originalWorkingDirectory(t)
	root := t.TempDir()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
	cmd := exec.Command("git", "init", "-q")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	if err := os.WriteFile("llms.txt", []byte(testMetrics.llmsPerformanceLine()+"\n- SQL dialects: 8\nSQL-99 compliance: ~80–85%\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"config", "user.email", "test@example.com"}, {"config", "user.name", "Test"}, {"config", "core.hooksPath", os.DevNull}, {"config", "commit.gpgsign", "false"}} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	if out, err := exec.Command("git", "add", "llms.txt").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}
	if out, err := exec.Command("git", "commit", "-qm", "fixture").CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v: %s", err, out)
	}
	if out, err := exec.Command("git", "tag", "v0.0.1").CombinedOutput(); err != nil {
		t.Fatalf("git tag: %v: %s", err, out)
	}
	problems, err := runClaims(testMetrics, "0.0.1", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(problems, "\n"), "latest.json") {
		t.Fatalf("missing compare results was not reported: %v", problems)
	}
	if err := os.MkdirAll("benchmarks/compare/results", 0o755); err != nil {
		t.Fatal(err)
	}
	tagDate, err := latestTagDate("0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	compare := fmt.Sprintf(`{"commit":"e9c5db91a8eda4f98d697a53dbd997ebd5255c87","dirty":false,"generatedAt":%q}`, tagDate+"T23:59:59Z")
	if err := os.WriteFile("benchmarks/compare/results/latest.json", []byte(compare), 0o644); err != nil {
		t.Fatal(err)
	}
	problems, err = runClaims(testMetrics, "0.0.1", "", false)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(problems, "\n")
	if !strings.Contains(joined, "e9c5db91") || !strings.Contains(joined, "task release:refresh-benchmarks TAG=v0.0.1") {
		t.Fatalf("wrong commit did not report both commit evidence and refresh hint: %v", problems)
	}
}

func originalWorkingDirectory(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

func TestCheckLLMS(t *testing.T) {
	ok := "- SQL dialects: 8\n- SQL-99 compliance: ~80–85% (estimated)\n- Performance: ~318 ns/op (~3.14M ops/sec) for a simple SELECT (parse stage) on Apple M4, Go 1.27. x"
	if p := checkLLMS(ok, testMetrics); len(p) != 0 {
		t.Fatalf("unexpected problems: %v", p)
	}
	seeded := strings.Replace(ok, "318 ns/op", "500 ns/op", 1)
	if p := checkLLMS(seeded, testMetrics); len(p) == 0 {
		t.Fatal("seeded llms.txt mismatch was not detected")
	}
}

func TestCheckAbout(t *testing.T) {
	cases := []struct {
		name, text string
		wantBad    bool
	}{
		{"no numbers", "High-performance SQL parser for Go", false},
		{"matching ops", "SQL parser, ~3.1M ops/sec", false},
		{"matching ns", "parses in 318 ns", false},
		{"stale ops", "SQL parser - 1.5M+ ops/sec, multi-dialect", true},
		{"stale ns", "parses in 500 ns", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(checkAbout(tc.text, testMetrics)) > 0; got != tc.wantBad {
				t.Fatalf("bad=%v, want %v", got, tc.wantBad)
			}
		})
	}
}

func TestCheckFresh(t *testing.T) {
	cases := []struct {
		name, measured, tag string
		wantBad             bool
	}{
		{"newer than tag", "2026-10-13", "2026-07-30", false},
		{"same day with timestamp", "2026-10-15T22:14:33Z", "2026-10-15", false},
		{"older than tag", "2026-07-01", "2026-07-30", true},
		{"missing date", "", "2026-07-30", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(checkFresh("x", tc.measured, tc.tag)) > 0; got != tc.wantBad {
				t.Fatalf("bad=%v, want %v", got, tc.wantBad)
			}
		})
	}
}
