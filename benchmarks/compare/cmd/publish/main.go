// Command publish runs the competitor benchmark harness and writes the
// results JSON that the website reads (issue #673).
//
// Run it from the benchmarks/compare module directory, usually through
// `task bench:publish`:
//
//	go run ./cmd/publish                 # -count=10, -cpu 4, GOGC default, all families
//	go run ./cmd/publish -families=Parse # cheap v1-only publish (about the v1 cost)
//	go run ./cmd/publish -count=3 -out /tmp/r.json -raw /tmp/r.txt
//	go run ./cmd/publish -cpus=4,1 -gogc=default,off   # the CI matrix
//	go run ./cmd/publish -cpus=1,4,10,32               # scaling run on a 32+ vCPU box
//
// The primary configuration (the first -cpus value with the first -gogc
// value, cpu4-gogc-default unless overridden) feeds the v1 fields, so the
// published v1 numbers do not depend on who runs the publish.
//
// The results document is schema v2 (see ../../SCHEMA.md). Every v1 field is
// still written, from the first configuration of the matrix, because the
// website reads results/latest.json.
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
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ajitpratap0/GoSQLX/benchmarks/compare"
)

const schemaVersion = 2

// defaultGOMEMLIMIT is the GOMEMLIMIT of the GOGC=off configurations. Without
// a limit a GOGC=off heap only grows, so every allocation lands on a fresh
// page and its first-touch fault is timed with the parser; the limit lets the
// collector run rarely and reuse pages. scripts/perf/lib.sh uses the same
// default (a root-module test keeps them equal) and explains the value.
const defaultGOMEMLIMIT = "64MiB"

// gosqlxModule is the module path of the library under test; every variant
// of it (gosqlx, gosqlx_norelease) reports the commit being measured.
const gosqlxModule = "github.com/ajitpratap0/GoSQLX"

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

	// Schema v2 additions. Everything above is the v1 view and is derived
	// from the first entry of Configs.
	Peers        []ParserV           `json:"peers"`
	ORMQueries   []ORMQueryV         `json:"ormQueries"`
	Configs      []ConfigV           `json:"configs"`
	Cells        []CellV             `json:"cells"`
	Acceptance   []compare.AcceptRow `json:"acceptance"`
	CommonAccept []CommonAcceptV     `json:"commonAccept"`
}

// ConfigV is one point of the run matrix.
type ConfigV struct {
	ID   string `json:"id"`
	CPU  int    `json:"cpu"`  // -cpu value; 0 means go test's default (GOMAXPROCS)
	GOGC string `json:"gogc"` // "default" or "off"
	// GOMEMLIMIT is the memory limit of a GOGC=off configuration (empty for
	// default GC, and when -gomemlimit=off).
	GOMEMLIMIT string `json:"gomemlimit,omitempty"`
	Command    string `json:"command"`
	RawOutput  string `json:"rawOutput"`
}

// CellV is the median of all samples of one benchmark cell under one
// configuration. Cell is the benchmark family without the Benchmark prefix
// (Parse, Lex, Normalize, Render, ParseFresh, ParseParallel, ParseDialect,
// ParseORM), Group is the query or dialect, Parser the library or
// implementation ID.
type CellV struct {
	Cell        string  `json:"cell"`
	Group       string  `json:"group"`
	Parser      string  `json:"parser"`
	Config      string  `json:"config"`
	Samples     int     `json:"samples"`
	NsPerOp     float64 `json:"nsPerOp"`
	BytesPerOp  float64 `json:"bytesPerOp"`
	AllocsPerOp float64 `json:"allocsPerOp"`
}

// ORMQueryV is one ORM-style corpus entry.
type ORMQueryV struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Shape string `json:"shape"`
	SQL   string `json:"sql"`
}

// CommonAcceptV summarises one checked-in common-accept set.
type CommonAcceptV struct {
	Dialect   string   `json:"dialect"`
	Parsers   []string `json:"parsers"`
	Total     int      `json:"total"`
	Accepted  int      `json:"accepted"`
	SetSHA256 string   `json:"setSha256"`
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
	// License is read from the library's LICENSE file at the pinned version.
	License      string   `json:"license"`
	Legacy       bool     `json:"legacy"`
	PeerDialects []string `json:"peerDialects,omitempty"`
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

// benchLine matches any benchmark result line with -benchmem columns:
// Benchmark<Cell>/<group>[/<more>]/<parser>[-<procs>].
var benchLine = regexp.MustCompile(
	`^Benchmark([A-Za-z0-9_]+)((?:/[A-Za-z0-9_]+)+?)(?:-(\d+))?\s+\d+\s+([\d.]+) ns/op(?:\s+[\d.]+ MB/s)?\s+([\d.]+) B/op\s+([\d.]+) allocs/op`)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "publish:", err)
		os.Exit(1)
	}
}

func run() error {
	count := flag.Int("count", 10, "benchmark repetitions per benchmark")
	benchtime := flag.String("benchtime", "", "optional -benchtime passed to go test (default: go test's own)")
	cpus := flag.String("cpus", "4", "comma-separated -cpu values, one run per value; the first is the primary configuration that feeds the v1 fields (empty: go test's default GOMAXPROCS)")
	gogcs := flag.String("gogc", "default", "comma-separated GOGC settings, default and/or off; the first is the primary configuration")
	families := flag.String("families", "all", "comma-separated benchmark families to run ("+strings.Join(allFamilies, ",")+"), or all; the v1 fields need Parse, so Parse alone gives a cheap v1-only publish")
	out := flag.String("out", filepath.Join("results", "latest.json"), "results JSON path")
	raw := flag.String("raw", filepath.Join("results", "latest.txt"), "raw go test -bench output path of the first configuration (benchstat input)")
	memlimit := flag.String("gomemlimit", defaultGOMEMLIMIT, "GOMEMLIMIT of the GOGC=off configurations, or off to leave it unset")
	ratios := flag.String("ratios", "", "also write a Markdown table of GoSQLX/peer time ratios per cell and configuration here")
	flag.Parse()

	if *count < 1 {
		return fmt.Errorf("-count must be at least 1, got %d", *count)
	}
	configs, err := parseMatrix(*cpus, *gogcs)
	if err != nil {
		return err
	}
	benchRe, err := benchRegexFor(*families)
	if err != nil {
		return err
	}

	commit, dirty, err := gitState()
	if err != nil {
		return err
	}
	goVersion, err := commandOutput("go", "env", "GOVERSION")
	if err != nil {
		return err
	}

	report := Report{
		SchemaVersion: schemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Commit:        commit,
		Dirty:         dirty,
		GoVersion:     goVersion,
		Stage:         "e2e",
		Caveat:        caveat,
		Parsers:       parserVersions(commit, true),
		Peers:         parserVersions(commit, false),
	}

	type rawFile struct {
		path string
		data []byte
	}
	var raws []rawFile
	var primary map[cellKey]*samples
	for i, c := range configs {
		rawPath := rawPathFor(*raw, i, c)
		args := benchArgs(benchRe, *count, c.CPU, *benchtime)

		if c.GOGC == "off" && *memlimit != "off" {
			c.GOMEMLIMIT = *memlimit
		}
		fmt.Fprintf(os.Stderr, "running [%s]: %s\n", c.ID, shellCommand(c.GOGC, *memlimit, args))
		var buf bytes.Buffer
		cmd := exec.Command("go", args...)
		cmd.Env = envForGOGC(os.Environ(), c.GOGC, *memlimit)
		cmd.Stdout = io.MultiWriter(&buf, os.Stderr)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("go test -bench (%s): %w", c.ID, err)
		}
		cpu, data, err := parseCells(buf.Bytes())
		if err != nil {
			return fmt.Errorf("%s: %w", c.ID, err)
		}
		c.Command = shellCommand(c.GOGC, *memlimit, args)
		c.RawOutput = filepath.ToSlash(rawPath)
		report.Configs = append(report.Configs, c)
		report.Cells = append(report.Cells, cellResults(data, c.ID)...)
		raws = append(raws, rawFile{rawPath, buf.Bytes()})
		if i == 0 {
			primary = data
			report.Hardware = Hardware{CPU: cpu, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, NumCPU: runtime.NumCPU()}
			report.Method = Method{
				Command:   shellCommand(c.GOGC, *memlimit, benchArgs(v1BenchRegex, *count, c.CPU, *benchtime)),
				Count:     *count,
				Statistic: "median",
				RawOutput: c.RawOutput,
			}
		}
	}

	for _, q := range compare.Corpus {
		report.Queries = append(report.Queries, QueryV{ID: q.ID, Name: q.Name, SQL: q.SQL})
	}
	for _, q := range compare.ORMCorpus {
		report.ORMQueries = append(report.ORMQueries, ORMQueryV{ID: q.ID, Name: q.Name, Shape: q.Shape, SQL: q.SQL})
	}
	v1, err := v1Results(primary)
	if err != nil {
		return err
	}
	report.Results = v1

	acc, err := compare.AcceptanceTable()
	if err != nil {
		return fmt.Errorf("acceptance table: %w", err)
	}
	report.Acceptance = acc
	for _, d := range compare.Dialects {
		c, err := compare.ComputeCommonAccept(d)
		if err != nil {
			return fmt.Errorf("common-accept %s: %w", d, err)
		}
		// BenchmarkParseDialect times the checked-in set, so the JSON must
		// describe that set, not a freshly computed one.
		checked, err := os.ReadFile(filepath.Join(compare.CommonAcceptDir, d+".txt"))
		if err != nil {
			return fmt.Errorf("common-accept %s: %w", d, err)
		}
		if string(checked) != c.Encode() {
			return fmt.Errorf("common-accept %s: checked-in %s/%s.txt is stale against the pinned parsers and corpus; run `go test -run TestCommonAcceptSets -update` and commit it", d, compare.CommonAcceptDir, d)
		}
		report.CommonAccept = append(report.CommonAccept, CommonAcceptV{
			Dialect: d, Parsers: c.Parsers, Total: c.Total, Accepted: len(c.Statements), SetSHA256: c.SetHash(),
		})
	}

	for _, r := range raws {
		if err := writeFile(r.path, r.data); err != nil {
			return err
		}
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	if err := writeFile(*out, append(encoded, '\n')); err != nil {
		return err
	}
	if *ratios != "" {
		if err := writeFile(*ratios, []byte(ratioMarkdown(report.Cells, report.Configs, report.Hardware.CPU))); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "wrote %s and %d raw file(s)\n", *out, len(raws))
	return nil
}

// allFamilies lists the benchmark families of the harness.
var allFamilies = []string{"Parse", "ParseORM", "ParseFresh", "ParseParallel", "ParseDialect", "Lex", "Normalize", "Render"}

// v1BenchRegex selects BenchmarkParse alone, the family the v1 results[] are
// derived from.
const v1BenchRegex = "^BenchmarkParse$"

// benchRegexFor builds the -bench regexp for a comma-separated family list.
func benchRegexFor(families string) (string, error) {
	families = strings.TrimSpace(families)
	if families == "" || families == "all" {
		families = strings.Join(allFamilies, ",")
	}
	var picked []string
	hasParse := false
	for _, f := range strings.Split(families, ",") {
		f = strings.TrimSpace(f)
		if !slices.Contains(allFamilies, f) {
			return "", fmt.Errorf("-families: unknown family %q (known: %s)", f, strings.Join(allFamilies, ", "))
		}
		hasParse = hasParse || f == "Parse"
		picked = append(picked, f)
	}
	if !hasParse {
		return "", fmt.Errorf("-families must include Parse: the v1 results[] are derived from it")
	}
	return "^Benchmark(" + strings.Join(picked, "|") + ")$", nil
}

// benchArgs builds the go test arguments of one run.
func benchArgs(benchRe string, count, cpu int, benchtime string) []string {
	args := []string{"test", "-run=^$", "-bench=" + benchRe, "-benchmem", "-count=" + strconv.Itoa(count)}
	if cpu > 0 {
		args = append(args, "-cpu="+strconv.Itoa(cpu))
	}
	if benchtime != "" {
		args = append(args, "-benchtime="+benchtime)
	}
	return append(args, ".")
}

// shellCommand renders a copy-pasteable command line (to be run in
// benchmarks/compare). Values with shell metacharacters are single-quoted,
// and GOGC=off (with its GOMEMLIMIT unless that is "off") is spelled out only
// for the configuration that sets it.
func shellCommand(gogc, memlimit string, args []string) string {
	parts := make([]string, 0, len(args)+3)
	if gogc == "off" {
		parts = append(parts, "GOGC=off")
		if memlimit != "off" {
			parts = append(parts, "GOMEMLIMIT="+quoteArg(memlimit))
		}
	}
	parts = append(parts, "go")
	for _, a := range args {
		parts = append(parts, quoteArg(a))
	}
	return strings.Join(parts, " ")
}

var safeShell = regexp.MustCompile(`^[A-Za-z0-9_@%+:,./-]*$`)

// quoteArg single-quotes the value of a -flag=value argument (or a bare
// argument) when it holds anything the shell would interpret.
func quoteArg(a string) string {
	flagPart, val := "", a
	if strings.HasPrefix(a, "-") {
		if i := strings.Index(a, "="); i >= 0 {
			flagPart, val = a[:i+1], a[i+1:]
		}
	}
	if safeShell.MatchString(val) {
		return a
	}
	return flagPart + "'" + strings.ReplaceAll(val, "'", `'\''`) + "'"
}

// cellKey identifies one benchmark cell: family, group, parser.
type cellKey struct{ cell, group, parser string }

// parseMatrix expands the -cpus and -gogc flags into the run matrix, cpu
// varying slowest. The first entry is the primary configuration.
func parseMatrix(cpus, gogcs string) ([]ConfigV, error) {
	cpuList := []int{0}
	if strings.TrimSpace(cpus) != "" {
		cpuList = nil
		for _, f := range strings.Split(cpus, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(f))
			if err != nil || n < 1 {
				return nil, fmt.Errorf("-cpus: %q is not a positive integer", f)
			}
			cpuList = append(cpuList, n)
		}
	}
	gcList := []string{"default"}
	if strings.TrimSpace(gogcs) != "" {
		gcList = nil
		for _, f := range strings.Split(gogcs, ",") {
			f = strings.TrimSpace(f)
			if f != "default" && f != "off" {
				return nil, fmt.Errorf("-gogc: %q must be default or off", f)
			}
			gcList = append(gcList, f)
		}
	}
	var out []ConfigV
	for _, c := range cpuList {
		for _, g := range gcList {
			id := "gogc-" + g
			if c > 0 {
				id = "cpu" + strconv.Itoa(c) + "-" + id
			}
			out = append(out, ConfigV{ID: id, CPU: c, GOGC: g})
		}
	}
	return out, nil
}

// rawPathFor returns the raw output path of configuration i: the -raw path
// itself for the first, a suffixed sibling for the others.
func rawPathFor(raw string, i int, c ConfigV) string {
	if i == 0 {
		return raw
	}
	ext := filepath.Ext(raw)
	return strings.TrimSuffix(raw, ext) + "-" + c.ID + ext
}

// envForGOGC returns env with GOGC and GOMEMLIMIT set for the configuration:
// both removed for "default"; GOGC=off plus GOMEMLIMIT=memlimit (unless
// memlimit is "off") for "off". Inherited values never leak through.
func envForGOGC(env []string, gogc, memlimit string) []string {
	out := make([]string, 0, len(env)+2)
	for _, kv := range env {
		if !strings.HasPrefix(kv, "GOGC=") && !strings.HasPrefix(kv, "GOMEMLIMIT=") {
			out = append(out, kv)
		}
	}
	if gogc == "off" {
		out = append(out, "GOGC=off")
		if memlimit != "off" {
			out = append(out, "GOMEMLIMIT="+memlimit)
		}
	}
	return out
}

// ratioMarkdown renders the in-job comparison for the job summary: for every
// benchmark family, GoSQLX implementation (parser IDs starting with
// "gosqlx") and peer, the geometric mean over the groups (queries or
// dialects) both ran of GoSQLX ns/op divided by peer ns/op, one column per
// configuration, plus the group count and the worst group of the primary
// configuration. Absolute times are left out on purpose: hosted runners
// differ in CPU model from job to job, so only same-job ratios carry over.
func ratioMarkdown(cells []CellV, configs []ConfigV, cpu string) string {
	type key struct{ cell, group, parser, config string }
	ns := map[key]float64{}
	type pair struct{ cell, gosqlx, peer string }
	groups := map[pair]map[string]bool{}
	byCell := map[string]map[string]bool{} // cell -> parser IDs
	for _, c := range cells {
		if c.NsPerOp <= 0 {
			continue
		}
		ns[key{c.Cell, c.Group, c.Parser, c.Config}] = c.NsPerOp
		if byCell[c.Cell] == nil {
			byCell[c.Cell] = map[string]bool{}
		}
		byCell[c.Cell][c.Parser] = true
	}
	for _, c := range cells {
		if !strings.HasPrefix(c.Parser, "gosqlx") {
			continue
		}
		for peer := range byCell[c.Cell] {
			if strings.HasPrefix(peer, "gosqlx") {
				continue
			}
			p := pair{c.Cell, c.Parser, peer}
			if groups[p] == nil {
				groups[p] = map[string]bool{}
			}
			groups[p][c.Group] = true
		}
	}
	pairs := make([]pair, 0, len(groups))
	for p := range groups {
		pairs = append(pairs, p)
	}
	family := func(c string) int {
		if i := slices.Index(allFamilies, c); i >= 0 {
			return i
		}
		return len(allFamilies)
	}
	sort.Slice(pairs, func(i, j int) bool {
		a, b := pairs[i], pairs[j]
		if fa, fb := family(a.cell), family(b.cell); fa != fb {
			return fa < fb
		}
		if a.cell != b.cell {
			return a.cell < b.cell
		}
		if a.gosqlx != b.gosqlx {
			return a.gosqlx < b.gosqlx
		}
		return a.peer < b.peer
	})

	var b strings.Builder
	b.WriteString("### Ratios: GoSQLX time / peer time (< 1 means GoSQLX is faster)\n\n")
	fmt.Fprintf(&b, "Runner CPU: `%s`. Every cell ran in this job on this CPU, so the ratios compare across runs; "+
		"the absolute ns/op in the JSON and raw files hold for this CPU and this job only. "+
		"Each value is the geometric mean over the groups (queries or dialects) both sides ran.\n\n", cpu)
	b.WriteString("| cell | GoSQLX | peer |")
	for _, c := range configs {
		fmt.Fprintf(&b, " %s |", c.ID)
	}
	b.WriteString(" groups | worst group |\n|---|---|---|")
	for range configs {
		b.WriteString("---:|")
	}
	b.WriteString("---:|---|\n")
	for _, p := range pairs {
		gs := make([]string, 0, len(groups[p]))
		for g := range groups[p] {
			gs = append(gs, g)
		}
		sort.Strings(gs)
		fmt.Fprintf(&b, "| %s | %s | %s |", p.cell, p.gosqlx, p.peer)
		n, worst, worstG := 0, 0.0, ""
		for i, c := range configs {
			sum, k := 0.0, 0
			for _, g := range gs {
				a, okA := ns[key{p.cell, g, p.gosqlx, c.ID}]
				z, okZ := ns[key{p.cell, g, p.peer, c.ID}]
				if !okA || !okZ {
					continue
				}
				r := a / z
				sum += math.Log(r)
				k++
				if i == 0 && r > worst {
					worst, worstG = r, g
				}
			}
			if i == 0 {
				n = k
			}
			if k == 0 {
				b.WriteString("  |")
				continue
			}
			fmt.Fprintf(&b, " %.2f |", math.Exp(sum/float64(k)))
		}
		if worstG != "" {
			fmt.Fprintf(&b, " %d | %s %.2f |\n", n, worstG, worst)
		} else {
			fmt.Fprintf(&b, " %d |  |\n", n)
		}
	}
	return b.String()
}

// cellResults reduces samples to medians, in a stable order.
func cellResults(data map[cellKey]*samples, config string) []CellV {
	keys := make([]cellKey, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.cell != b.cell {
			return a.cell < b.cell
		}
		if a.group != b.group {
			return a.group < b.group
		}
		return a.parser < b.parser
	})
	out := make([]CellV, 0, len(keys))
	for _, k := range keys {
		s := data[k]
		out = append(out, CellV{
			Cell: k.cell, Group: k.group, Parser: k.parser, Config: config,
			Samples: len(s.ns), NsPerOp: round(median(s.ns), 1),
			BytesPerOp: median(s.bytes), AllocsPerOp: median(s.allocs),
		})
	}
	return out
}

// v1Results builds the schema v1 results array: BenchmarkParse over the
// portable corpus for the parsers the v1 fields describe.
func v1Results(data map[cellKey]*samples) ([]ResultV, error) {
	var out []ResultV
	for _, q := range compare.Corpus {
		for _, p := range compare.Parsers {
			if !p.Schema1 {
				continue
			}
			r := ResultV{Query: q.ID, Parser: p.ID, Supported: compare.Supports(p, q) == nil}
			if s, ok := data[cellKey{"Parse", q.ID, p.ID}]; ok && r.Supported {
				r.Samples = len(s.ns)
				r.NsPerOp = ptr(round(median(s.ns), 1))
				r.BytesPerOp = ptr(median(s.bytes))
				r.AllocsPerOp = ptr(median(s.allocs))
			} else if r.Supported {
				return nil, fmt.Errorf("no benchmark samples for supported pair %s/%s", q.ID, p.ID)
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// parseCells extracts the cpu line and per-cell samples from go test output.
func parseCells(output []byte) (string, map[cellKey]*samples, error) {
	cpu := "unknown"
	data := map[cellKey]*samples{}
	sc := bufio.NewScanner(bytes.NewReader(output))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
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
		parts := strings.Split(strings.TrimPrefix(m[2], "/"), "/")
		key := cellKey{cell: m[1], group: strings.Join(parts[:len(parts)-1], "/"), parser: parts[len(parts)-1]}
		if key.group == "" {
			continue
		}
		s, ok := data[key]
		if !ok {
			s = &samples{}
			data[key] = s
		}
		for i, dst := range []*[]float64{&s.ns, &s.bytes, &s.allocs} {
			v, err := strconv.ParseFloat(m[4+i], 64)
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
		return "", nil, fmt.Errorf("no benchmark results found in go test output")
	}
	return cpu, data, nil
}

// parseBench is the v1 view of parseCells: BenchmarkParse samples keyed
// "<query>/<parser>".
func parseBench(output []byte) (string, map[string]*samples, error) {
	cpu, cells, err := parseCells(output)
	if err != nil {
		return "", nil, err
	}
	data := map[string]*samples{}
	for k, s := range cells {
		if k.cell == "Parse" {
			data[k.group+"/"+k.parser] = s
		}
	}
	if len(data) == 0 {
		return "", nil, fmt.Errorf("no BenchmarkParse results found in go test output")
	}
	return cpu, data, nil
}

// parserVersions resolves each library's pinned version from the build info,
// which reflects this module's go.mod. GoSQLX is replaced by the enclosing
// repository, so its version is the commit being measured.
func parserVersions(commit string, v1Only bool) []ParserV {
	versions := map[string]string{}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, d := range info.Deps {
			versions[d.Path] = d.Version
		}
	}
	out := make([]ParserV, 0, len(compare.Parsers))
	for _, p := range compare.Parsers {
		if v1Only && !p.Schema1 {
			continue
		}
		v := versions[p.Module]
		if p.Module == gosqlxModule {
			v = "commit " + shortCommit(commit)
		}
		out = append(out, ParserV{ID: p.ID, Name: p.Name, Module: p.Module, Version: v, Dialect: p.Dialect, CGo: p.CGo,
			License: p.License, Legacy: p.Legacy, PeerDialects: p.PeerDialects})
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
