// Command publish runs the competitor benchmark harness and writes the
// results JSON that the website reads (issue #673).
//
// Run it from the benchmarks/compare module directory, usually through
// `task bench:publish`:
//
//	go run ./cmd/publish                 # -count=10, writes results/latest.json and results/latest.txt
//	go run ./cmd/publish -count=3 -out /tmp/r.json -raw /tmp/r.txt
//
// The raw `go test -bench` output is kept next to the JSON so anyone can
// summarise the same samples with benchstat.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ajitpratap0/GoSQLX/benchmarks/compare"
)

const schemaVersion = 1

const caveat = "The libraries implement different SQL dialects and build different ASTs " +
	"(pg_query_go wraps the real PostgreSQL parser through CGo and converts its tree to Go structs; " +
	"Vitess, TiDB and xwb1989 implement MySQL grammars). Each figure is the end-to-end cost of " +
	"turning the same SQL text into that library's AST on the stated hardware, not identical work."

// Report is the published results document.
type Report struct {
	SchemaVersion int       `json:"schemaVersion"`
	GeneratedAt   string    `json:"generatedAt"`
	Commit        string    `json:"commit"`
	Dirty         bool      `json:"dirty"`
	GoVersion     string    `json:"goVersion"`
	Hardware      Hardware  `json:"hardware"`
	Stage         string    `json:"stage"`
	Method        Method    `json:"method"`
	Caveat        string    `json:"caveat"`
	Parsers       []ParserV `json:"parsers"`
	Queries       []QueryV  `json:"queries"`
	Results       []ResultV `json:"results"`
}

// Hardware describes the machine the run happened on.
type Hardware struct {
	CPU    string `json:"cpu"`
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
	NumCPU int    `json:"numCPU"`
}

// Method records how the numbers were produced.
type Method struct {
	Command   string `json:"command"`
	Count     int    `json:"count"`
	Statistic string `json:"statistic"`
	RawOutput string `json:"rawOutput"`
}

// ParserV is a library under test with its pinned version.
type ParserV struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Module  string `json:"module"`
	Version string `json:"version"`
	Dialect string `json:"dialect"`
	CGo     bool   `json:"cgo"`
}

// QueryV is one corpus entry.
type QueryV struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	SQL  string `json:"sql"`
}

// ResultV is the median of all samples for one (query, parser) pair.
// Measurement fields are null when the parser rejects the query.
type ResultV struct {
	Query       string   `json:"query"`
	Parser      string   `json:"parser"`
	Supported   bool     `json:"supported"`
	Samples     int      `json:"samples"`
	NsPerOp     *float64 `json:"nsPerOp"`
	BytesPerOp  *float64 `json:"bytesPerOp"`
	AllocsPerOp *float64 `json:"allocsPerOp"`
}

type samples struct {
	ns, bytes, allocs []float64
}

var benchLine = regexp.MustCompile(
	`^BenchmarkParse/([A-Za-z0-9_]+)/([A-Za-z0-9_]+)(?:-\d+)?\s+\d+\s+([\d.]+) ns/op(?:\s+[\d.]+ MB/s)?\s+([\d.]+) B/op\s+([\d.]+) allocs/op`)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "publish:", err)
		os.Exit(1)
	}
}

func run() error {
	count := flag.Int("count", 10, "benchmark repetitions per (query, parser) pair")
	benchtime := flag.String("benchtime", "", "optional -benchtime passed to go test (default: go test's own)")
	out := flag.String("out", filepath.Join("results", "latest.json"), "results JSON path")
	raw := flag.String("raw", filepath.Join("results", "latest.txt"), "raw go test -bench output path (benchstat input)")
	flag.Parse()

	if *count < 1 {
		return fmt.Errorf("-count must be at least 1, got %d", *count)
	}

	commit, dirty, err := gitState()
	if err != nil {
		return err
	}
	goVersion, err := commandOutput("go", "env", "GOVERSION")
	if err != nil {
		return err
	}

	args := []string{"test", "-run=^$", "-bench=^BenchmarkParse$", "-benchmem", "-count=" + strconv.Itoa(*count)}
	if *benchtime != "" {
		args = append(args, "-benchtime="+*benchtime)
	}
	args = append(args, ".")

	fmt.Fprintf(os.Stderr, "running: go %s\n", strings.Join(args, " "))
	var buf bytes.Buffer
	cmd := exec.Command("go", args...)
	cmd.Stdout = io.MultiWriter(&buf, os.Stderr)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go test -bench: %w", err)
	}

	cpu, data, err := parseBench(buf.Bytes())
	if err != nil {
		return err
	}

	report := Report{
		SchemaVersion: schemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Commit:        commit,
		Dirty:         dirty,
		GoVersion:     goVersion,
		Hardware:      Hardware{CPU: cpu, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, NumCPU: runtime.NumCPU()},
		Stage:         "e2e",
		Method: Method{
			Command:   "go " + strings.Join(args, " "),
			Count:     *count,
			Statistic: "median",
			RawOutput: filepath.ToSlash(*raw),
		},
		Caveat:  caveat,
		Parsers: parserVersions(commit),
	}
	for _, q := range compare.Corpus {
		report.Queries = append(report.Queries, QueryV{ID: q.ID, Name: q.Name, SQL: q.SQL})
	}
	for _, q := range compare.Corpus {
		for _, p := range compare.Parsers {
			r := ResultV{Query: q.ID, Parser: p.ID, Supported: compare.Supports(p, q) == nil}
			if s, ok := data[q.ID+"/"+p.ID]; ok && r.Supported {
				r.Samples = len(s.ns)
				r.NsPerOp = ptr(round(median(s.ns), 1))
				r.BytesPerOp = ptr(median(s.bytes))
				r.AllocsPerOp = ptr(median(s.allocs))
			} else if r.Supported {
				return fmt.Errorf("no benchmark samples for supported pair %s/%s", q.ID, p.ID)
			}
			report.Results = append(report.Results, r)
		}
	}

	if err := writeFile(*raw, buf.Bytes()); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	if err := writeFile(*out, append(encoded, '\n')); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s and %s\n", *out, *raw)
	return nil
}

// parseBench extracts the cpu line and per-pair samples from go test output.
func parseBench(output []byte) (string, map[string]*samples, error) {
	cpu := "unknown"
	data := map[string]*samples{}
	sc := bufio.NewScanner(bytes.NewReader(output))
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "cpu: "); ok {
			cpu = strings.TrimSpace(v)
			continue
		}
		m := benchLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := m[1] + "/" + m[2]
		s, ok := data[key]
		if !ok {
			s = &samples{}
			data[key] = s
		}
		for i, dst := range []*[]float64{&s.ns, &s.bytes, &s.allocs} {
			v, err := strconv.ParseFloat(m[3+i], 64)
			if err != nil {
				return "", nil, fmt.Errorf("parse %q: %w", line, err)
			}
			*dst = append(*dst, v)
		}
	}
	if err := sc.Err(); err != nil {
		return "", nil, fmt.Errorf("scan benchmark output: %w", err)
	}
	if len(data) == 0 {
		return "", nil, fmt.Errorf("no BenchmarkParse results found in go test output")
	}
	return cpu, data, nil
}

// parserVersions resolves each library's pinned version from the build info,
// which reflects this module's go.mod. GoSQLX is replaced by the enclosing
// repository, so its version is the commit being measured.
func parserVersions(commit string) []ParserV {
	versions := map[string]string{}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, d := range info.Deps {
			versions[d.Path] = d.Version
		}
	}
	out := make([]ParserV, 0, len(compare.Parsers))
	for _, p := range compare.Parsers {
		v := versions[p.Module]
		if p.ID == "gosqlx" {
			v = "commit " + shortCommit(commit)
		}
		out = append(out, ParserV{ID: p.ID, Name: p.Name, Module: p.Module, Version: v, Dialect: p.Dialect, CGo: p.CGo})
	}
	return out
}

func gitState() (string, bool, error) {
	if sha := os.Getenv("GITHUB_SHA"); sha != "" {
		return sha, false, nil
	}
	commit, err := commandOutput("git", "rev-parse", "HEAD")
	if err != nil {
		return "", false, err
	}
	status, err := commandOutput("git", "status", "--porcelain", "--untracked-files=no")
	if err != nil {
		return "", false, err
	}
	return commit, status != "", nil
}

func commandOutput(name string, args ...string) (string, error) {
	b, err := exec.Command(name, args...).Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(b)), nil
}

func writeFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func median(v []float64) float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

func round(v float64, places int) float64 {
	p := 1.0
	for range places {
		p *= 10
	}
	return float64(int64(v*p+0.5)) / p
}

func shortCommit(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

func ptr(v float64) *float64 { return &v }
