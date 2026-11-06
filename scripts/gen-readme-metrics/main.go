// Command gen-readme-metrics generates the README metrics blocks from
// scripts/gen-readme-metrics/metrics.json and keeps documentation version
// banners in sync with the latest git release tag.
//
// Usage (from the repository root):
//
//	go run ./scripts/gen-readme-metrics           # rewrite README.md and docs banners
//	go run ./scripts/gen-readme-metrics --check   # exit 1 if anything has drifted
//	go run ./scripts/gen-readme-metrics --claims [--about "text"]
//	                                              # exit 1 if llms.txt, the About text
//	                                              # or benchmark dates disagree with metrics.json
//	go run ./scripts/gen-readme-metrics --record raw.txt --tag vX.Y.Z --hardware CPU --go-version 1.27
//	                                              # record tag-anchored parser benchmark output
//
// Metric blocks live between <!-- metrics:start --> / <!-- metrics:end -->
// (table + footnote) and <!-- metrics-inline:start --> / <!-- metrics-inline:end -->
// (inline prose). Version banners are rewritten in docs/*.md; the version
// history in doc.go is hand-written and only checked.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type metrics struct {
	Stage            string `json:"stage"`
	Query            string `json:"query"`
	ParseNsPerOp     int    `json:"parse_ns_per_op"`
	Hardware         string `json:"hardware"`
	GoVersion        string `json:"go_version"`
	Runs             int    `json:"runs"`
	Benchmark        string `json:"benchmark"`
	BenchmarkPackage string `json:"benchmark_package"`
	SQL99Estimate    string `json:"sql99_estimate"`
	Dialects         int    `json:"dialects"`
	RaceConditions   int    `json:"race_conditions"`
	MeasuredAt       string `json:"measured_at"`
	MeasuredTag      string `json:"measured_tag"`
}

func (m metrics) parsesPerSec() string {
	return fmt.Sprintf("~%.1fM", 1e9/float64(m.ParseNsPerOp)/1e6)
}

func (m metrics) table() string {
	return fmt.Sprintf("| **%s parses/sec†** | **%d ns parse latency†** | **%s SQL-99 (est.)** | **%d dialects** | **%d race conditions** |\n"+
		"|:---:|:---:|:---:|:---:|:---:|\n\n"+
		"<sub>† Parse stage only (pre-tokenized input to AST), `%s`, %s, Go %s, median of %d runs of `%s`. "+
		"Complex queries take longer (see `performance_baselines.json`). "+
		"Reproduce: `go test -run ^$ -bench %s -benchmem -count=%d %s`.</sub>",
		m.parsesPerSec(), m.ParseNsPerOp, m.SQL99Estimate, m.Dialects, m.RaceConditions,
		m.Query, m.Hardware, m.GoVersion, m.Runs, m.Benchmark,
		m.Benchmark, m.Runs, m.BenchmarkPackage)
}

func (m metrics) inline() string {
	return fmt.Sprintf("**%d ns (%s parses/sec)**", m.ParseNsPerOp, m.parsesPerSec())
}

// replaceBlock swaps the content between the named markers, preserving them.
func replaceBlock(src, name, body string) (string, error) {
	start, end := "<!-- "+name+":start -->", "<!-- "+name+":end -->"
	i := strings.Index(src, start)
	j := strings.Index(src, end)
	if i < 0 || j < 0 || j < i {
		return "", fmt.Errorf("markers %q / %q not found", start, end)
	}
	i += len(start)
	sep := "\n"
	if !strings.Contains(src[i:j], "\n") {
		sep = ""
	}
	return src[:i] + sep + body + sep + src[j:], nil
}

// bannerPatterns match version banners; group 2 is the version that gets
// replaced, groups 1 and 3 are preserved.
var bannerPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?m)^(# .*\(v)(\d+\.\d+\.\d+)(\)\s*)$`),
	regexp.MustCompile(`(?m)^(\*\*(?:Current )?Version(?::\*\*|\*\*:) v?)(\d+\.\d+\.\d+)()`),
	regexp.MustCompile(`(?m)^(\*\*(?:GoSQLX|Test Suite) Version(?::\*\*|\*\*:) v?)(\d+\.\d+\.\d+)(\s*)$`),
}

func syncBanners(src, version string) string {
	for _, re := range bannerPatterns {
		src = re.ReplaceAllString(src, "${1}"+version+"${3}")
	}
	return src
}

var baselineLine = regexp.MustCompile(`^BenchmarkPerformanceBaseline/([^\s/]+)-\d+(?:[ \t]|$).*?([0-9]+(?:\.[0-9]+)?) ns/op(?:[ \t]|$)`)

func parseBaseline(raw []byte, sub string) ([]float64, error) {
	var values []float64
	for _, line := range strings.Split(string(raw), "\n") {
		match := baselineLine.FindStringSubmatch(line)
		if len(match) != 3 || match[1] != sub {
			continue
		}
		value, err := strconv.ParseFloat(match[2], 64)
		if err != nil {
			return nil, fmt.Errorf("parsing %s ns/op from benchmark line %q: %w", sub, line, err)
		}
		values = append(values, value)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("no BenchmarkPerformanceBaseline/%s samples found", sub)
	}
	return values, nil
}

func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle]) / 2
}

// snapshotDocs are point-in-time analyses whose version banner records the
// release they were written against, so they are not kept in sync.
var snapshotDocs = map[string]bool{"sql99-compliance-analysis.md": true}

var docGoLatest = regexp.MustCompile(`(?m)^// v(\d+\.\d+\.\d+):`)

func latestTag() (string, error) {
	out, err := exec.Command("git", "tag", "--list", "v[0-9]*.[0-9]*.[0-9]*", "--sort=-v:refname").Output()
	if err != nil {
		return "", fmt.Errorf("listing git tags: %w", err)
	}
	for _, t := range strings.Fields(string(out)) {
		if !strings.Contains(t, "-") {
			return strings.TrimPrefix(t, "v"), nil
		}
	}
	return "", fmt.Errorf("no release tag found (CI needs fetch-depth: 0 / fetch-tags)")
}

func run() error { return runWithArgs(os.Args[1:]) }

func runWithArgs(args []string) error {
	flags := flag.NewFlagSet("gen-readme-metrics", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	check := flags.Bool("check", false, "fail if generated content differs from the files on disk")
	versionFlag := flags.String("version", "", "release version without leading v (default: latest git tag)")
	claims := flags.Bool("claims", false, "check llms.txt, the About text and benchmark freshness against metrics.json instead of the README blocks")
	about := flags.String("about", "", "with --claims: the GitHub About (repository description) text to verify")
	record := flags.String("record", "", "record parse benchmark output from a raw go test output file")
	tag := flags.String("tag", "", "with --record: release tag to measure (vX.Y.Z)")
	hardware := flags.String("hardware", "", "with --record: CPU model")
	goVersion := flags.String("go-version", "", "with --record: Go major.minor version")
	date := flags.String("date", "", "with --record: measurement date (YYYY-MM-DD, default UTC today)")
	if err := flags.Parse(args); err != nil {
		return err
	}

	version := strings.TrimPrefix(*versionFlag, "v")
	if version == "" {
		v, err := latestTag()
		if err != nil {
			return err
		}
		version = v
	}

	raw, err := os.ReadFile("scripts/gen-readme-metrics/metrics.json")
	if err != nil {
		return fmt.Errorf("reading metrics.json (run from the repository root): %w", err)
	}
	var m metrics
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("parsing metrics.json: %w", err)
	}
	if m.ParseNsPerOp <= 0 {
		return fmt.Errorf("metrics.json: parse_ns_per_op must be positive")
	}

	if *record != "" {
		if *claims || *check {
			return fmt.Errorf("--record cannot be combined with --claims or --check")
		}
		if !regexp.MustCompile(`^v\d+\.\d+\.\d+$`).MatchString(*tag) {
			return fmt.Errorf("--tag must match vX.Y.Z")
		}
		if version != strings.TrimPrefix(*tag, "v") {
			return fmt.Errorf("--tag %s does not match --version %s", *tag, version)
		}
		if strings.TrimSpace(*hardware) == "" {
			return fmt.Errorf("--hardware is required with --record")
		}
		if !regexp.MustCompile(`^\d+\.\d+$`).MatchString(*goVersion) {
			return fmt.Errorf("--go-version must be major.minor")
		}
		measuredAt := *date
		if measuredAt == "" {
			measuredAt = time.Now().UTC().Format(dateLayout)
		}
		if _, err := time.Parse(dateLayout, measuredAt); err != nil {
			return fmt.Errorf("invalid --date %q (expected YYYY-MM-DD): %w", measuredAt, err)
		}
		benchOutput, err := os.ReadFile(*record)
		if err != nil {
			return fmt.Errorf("reading benchmark output %s: %w", *record, err)
		}
		samples, err := parseBaseline(benchOutput, "SimpleSelect")
		if err != nil {
			return err
		}
		m.ParseNsPerOp = int(math.Round(median(samples)))
		m.Runs = len(samples)
		m.MeasuredAt = measuredAt
		m.MeasuredTag = *tag
		m.Hardware = strings.TrimSpace(*hardware)
		m.GoVersion = *goVersion
		encoded, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding metrics.json: %w", err)
		}
		encoded = append(encoded, '\n')
		if err := os.WriteFile("scripts/gen-readme-metrics/metrics.json", encoded, 0o644); err != nil {
			return fmt.Errorf("writing metrics.json: %w", err)
		}
		fmt.Println("Sub-benchmark\tMedian (ns/op)\tRuns")
		for _, sub := range []string{"SimpleSelect", "ComplexQuery", "WindowFunction", "CTE", "INSERT"} {
			values, err := parseBaseline(benchOutput, sub)
			if err == nil {
				fmt.Printf("%s\t%.0f\t%d\n", sub, median(values), len(values))
			}
		}
	}

	if *claims {
		aboutSet := false
		flags.Visit(func(f *flag.Flag) { aboutSet = aboutSet || f.Name == "about" })
		problems, err := runClaims(m, version, *about, aboutSet)
		if err != nil {
			return err
		}
		if len(problems) > 0 {
			return fmt.Errorf("claims drifted from metrics.json:\n  - %s", strings.Join(problems, "\n  - "))
		}
		fmt.Printf("ok: claims match metrics.json at v%s (About text checked: %t)\n", version, aboutSet)
		return nil
	}

	var drift []string
	update := func(path string, fn func(string) (string, error)) error {
		cur, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		next, err := fn(string(cur))
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if next == string(cur) {
			return nil
		}
		drift = append(drift, path)
		if *check {
			return nil
		}
		return os.WriteFile(path, []byte(next), 0o644)
	}

	if err := update("README.md", func(s string) (string, error) {
		s, err := replaceBlock(s, "metrics", m.table())
		if err != nil {
			return "", err
		}
		return replaceBlock(s, "metrics-inline", m.inline())
	}); err != nil {
		return err
	}

	docs, err := filepath.Glob("docs/*.md")
	if err != nil {
		return err
	}
	for _, p := range docs {
		if snapshotDocs[filepath.Base(p)] {
			continue
		}
		if err := update(p, func(s string) (string, error) { return syncBanners(s, version), nil }); err != nil {
			return err
		}
	}

	// doc.go carries a hand-written version history; its newest entry must
	// match the tag, so it is checked but never rewritten.
	docGo, err := os.ReadFile("doc.go")
	if err != nil {
		return err
	}
	if mm := docGoLatest.FindSubmatch(docGo); mm == nil || string(mm[1]) != version {
		got := "none"
		if mm != nil {
			got = string(mm[1])
		}
		return fmt.Errorf("doc.go: newest version-history entry is %s, latest tag is %s (edit doc.go by hand)", got, version)
	}
	if b, err := os.ReadFile("pkg/gosqlx/doc.go"); err == nil {
		re := regexp.MustCompile(`(?mi)^//\s*(?:current )?version:?\s*v?(\d+\.\d+\.\d+)`)
		for _, mm := range re.FindAllSubmatch(b, -1) {
			if string(mm[1]) != version {
				return fmt.Errorf("pkg/gosqlx/doc.go: version banner %s does not match latest tag %s (edit by hand)", mm[1], version)
			}
		}
	}

	if len(drift) > 0 {
		if *check {
			return fmt.Errorf("drift against v%s in: %s\nfix with: go run ./scripts/gen-readme-metrics", version, strings.Join(drift, ", "))
		}
		fmt.Printf("updated %d file(s): %s\n", len(drift), strings.Join(drift, ", "))
		return nil
	}
	fmt.Printf("ok: README metrics and version banners match v%s\n", version)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen-readme-metrics:", err)
		os.Exit(1)
	}
}
