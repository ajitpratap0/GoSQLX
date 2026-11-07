package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// This file implements the --claims mode used by the weekly claims-drift
// workflow (.github/workflows/claims-drift.yml). It checks that public claims
// outside the README blocks (llms.txt and the GitHub About text) agree with
// scripts/gen-readme-metrics/metrics.json, and that the measurements are not
// older than the latest release tag.

const dateLayout = "2006-01-02"

var (
	opsClaim = regexp.MustCompile(`(?i)(\d+(?:\.\d+)?)\s?M\+?\s*(?:ops|parses)/sec`)
	nsClaim  = regexp.MustCompile(`(?i)(\d[\d,]*)\s?ns\b`)
)

const refreshHint = "run task release:refresh-benchmarks TAG=v%s"

// ops returns the throughput figure with the given number of decimals.
func (m metrics) ops(decimals int) string {
	return fmt.Sprintf("%.*f", decimals, 1e9/float64(m.ParseNsPerOp)/1e6)
}

// llmsPerformanceLine is the exact claim llms.txt must carry.
func (m metrics) llmsPerformanceLine() string {
	return fmt.Sprintf("~%d ns/op (~%sM ops/sec) for a simple SELECT (parse stage) on %s, Go %s.",
		m.ParseNsPerOp, m.ops(2), m.Hardware, m.GoVersion)
}

// checkLLMS verifies the llms.txt key facts against metrics.json.
func checkLLMS(text string, m metrics) []string {
	var problems []string
	if !strings.Contains(text, m.llmsPerformanceLine()) {
		problems = append(problems, fmt.Sprintf("llms.txt: performance line does not contain %q", m.llmsPerformanceLine()))
	}
	if want := fmt.Sprintf("- SQL dialects: %d\n", m.Dialects); !strings.Contains(text, want) {
		problems = append(problems, fmt.Sprintf("llms.txt: missing %q", strings.TrimSpace(want)))
	}
	if want := "SQL-99 compliance: " + m.SQL99Estimate; !strings.Contains(text, want) {
		problems = append(problems, fmt.Sprintf("llms.txt: missing %q", want))
	}
	return problems
}

// checkAbout verifies the GitHub About (repository description) text. It may
// omit performance numbers, but any it states must match metrics.json.
func checkAbout(text string, m metrics) []string {
	var problems []string
	for _, mm := range opsClaim.FindAllStringSubmatch(text, -1) {
		if mm[1] != m.ops(1) && mm[1] != m.ops(2) {
			problems = append(problems, fmt.Sprintf("About text claims %sM ops/sec; metrics.json measures %sM (%s stage)", mm[1], m.ops(2), m.Stage))
		}
	}
	for _, mm := range nsClaim.FindAllStringSubmatch(text, -1) {
		if strings.ReplaceAll(mm[1], ",", "") != fmt.Sprint(m.ParseNsPerOp) {
			problems = append(problems, fmt.Sprintf("About text claims %s ns; metrics.json measures %d ns", mm[1], m.ParseNsPerOp))
		}
	}
	return problems
}

// checkFresh fails when a measurement date is older than the latest tag date.
func checkFresh(label, measured, tagDate string) []string {
	got, err := parseDate(measured)
	if err != nil {
		return []string{fmt.Sprintf("%s: cannot parse measurement date %q: %v", label, measured, err)}
	}
	tag, err := parseDate(tagDate)
	if err != nil {
		return []string{fmt.Sprintf("latest tag date %q: %v", tagDate, err)}
	}
	if got.Before(tag) {
		return []string{fmt.Sprintf("%s: measured %s is older than the latest tag (%s); re-run the benchmark", label, got.Format(dateLayout), tag.Format(dateLayout))}
	}
	return nil
}

func checkMeasuredTag(measuredTag, version string) []string {
	want := "v" + strings.TrimPrefix(version, "v")
	if measuredTag != want {
		return []string{fmt.Sprintf("scripts/gen-readme-metrics/metrics.json: measured at %s, not the latest release %s; "+refreshHint, measuredTag, want, strings.TrimPrefix(version, "v"))}
	}
	return nil
}

func tagCommit(version string) (string, error) {
	tag := "v" + strings.TrimPrefix(version, "v")
	out, err := exec.Command("git", "rev-parse", tag+"^{commit}").Output()
	if err != nil {
		return "", fmt.Errorf("resolving commit for tag %s: %w", tag, err)
	}
	sha := strings.TrimSpace(string(out))
	if sha == "" {
		return "", fmt.Errorf("resolving commit for tag %s: git returned an empty commit", tag)
	}
	return sha, nil
}

type compareResult struct {
	Commit      string `json:"commit"`
	Dirty       *bool  `json:"dirty"`
	GeneratedAt string `json:"generatedAt"`
}

func checkCompareResults(raw []byte, tagSHA, tagDate string) []string {
	const label = "benchmarks/compare/results/latest.json"
	var result compareResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return []string{fmt.Sprintf("%s: invalid JSON: %v", label, err)}
	}
	var problems []string
	if result.Commit != tagSHA {
		problems = append(problems, fmt.Sprintf("%s: commit %s does not match latest release tag commit %s", label, shortSHA(result.Commit), shortSHA(tagSHA)))
	}
	if result.Dirty == nil || *result.Dirty {
		problems = append(problems, fmt.Sprintf("%s: dirty must be false", label))
	}
	if result.GeneratedAt == "" {
		problems = append(problems, fmt.Sprintf("%s: generatedAt is missing", label))
	} else {
		problems = append(problems, checkFresh(label, result.GeneratedAt, tagDate)...)
	}
	return problems
}

func shortSHA(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}

func addRefreshHint(problems []string, version string) []string {
	hint := fmt.Sprintf(refreshHint, strings.TrimPrefix(version, "v"))
	for i := range problems {
		if !strings.Contains(problems[i], hint) {
			problems[i] += "; " + hint
		}
	}
	return problems
}

func parseDate(s string) (time.Time, error) {
	if len(s) >= len(dateLayout) {
		s = s[:len(dateLayout)]
	}
	return time.Parse(dateLayout, s)
}

func latestTagDate(version string) (string, error) {
	out, err := exec.Command("git", "log", "-1", "--format=%cs", "v"+version).Output()
	if err != nil {
		return "", fmt.Errorf("reading date of tag v%s: %w", version, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// runClaims executes every claims check and returns the problems found.
func runClaims(m metrics, version, aboutText string, aboutSet bool) ([]string, error) {
	var problems []string

	llms, err := os.ReadFile("llms.txt")
	if err != nil {
		return nil, fmt.Errorf("reading llms.txt (run from the repository root): %w", err)
	}
	problems = append(problems, checkLLMS(string(llms), m)...)

	if aboutSet {
		problems = append(problems, checkAbout(aboutText, m)...)
	}

	tagDate, err := latestTagDate(version)
	if err != nil {
		return nil, err
	}
	problems = append(problems, addRefreshHint(checkFresh("scripts/gen-readme-metrics/metrics.json", m.MeasuredAt, tagDate), version)...)
	problems = append(problems, addRefreshHint(checkMeasuredTag(m.MeasuredTag, version), version)...)

	tagSHA, err := tagCommit(version)
	if err != nil {
		return nil, err
	}
	cmp, err := os.ReadFile("benchmarks/compare/results/latest.json")
	if err != nil {
		if os.IsNotExist(err) {
			problems = append(problems, fmt.Sprintf("benchmarks/compare/results/latest.json: required results file is missing; "+refreshHint, strings.TrimPrefix(version, "v")))
		} else {
			return nil, fmt.Errorf("reading benchmarks/compare/results/latest.json: %w", err)
		}
	} else {
		problems = append(problems, addRefreshHint(checkCompareResults(cmp, tagSHA, tagDate), version)...)
	}
	return problems, nil
}
