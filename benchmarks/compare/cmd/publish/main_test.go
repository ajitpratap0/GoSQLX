package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/benchmarks/compare"
)

func TestParseBench(t *testing.T) {
	out := []byte(`goos: linux
goarch: amd64
cpu: AMD EPYC 7763 64-Core Processor
BenchmarkParse/simple_select/gosqlx-4         	  800000	      1450 ns/op	  17.93 MB/s	    2230 B/op	       7 allocs/op
BenchmarkParse/simple_select/gosqlx-4         	  800000	      1350.5 ns/op	  17.93 MB/s	    2230 B/op	       7 allocs/op
BenchmarkParse/simple_select/gosqlx-4         	  800000	      1500 ns/op	  17.93 MB/s	    2232 B/op	       7 allocs/op
BenchmarkParse/cte/xwb1989-4                  	--- SKIP: does not accept this query
BenchmarkParse/delete/pg_query_go             	   20000	      5705 ns/op	    1416 B/op	      30 allocs/op
PASS
`)
	cpu, data, err := parseBench(out)
	if err != nil {
		t.Fatal(err)
	}
	if cpu != "AMD EPYC 7763 64-Core Processor" {
		t.Errorf("cpu = %q", cpu)
	}
	tests := []struct {
		key               string
		n                 int
		ns, bytes, allocs float64
	}{
		{"simple_select/gosqlx", 3, 1450, 2230, 7},
		{"delete/pg_query_go", 1, 5705, 1416, 30},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			s, ok := data[tt.key]
			if !ok {
				t.Fatalf("missing %s", tt.key)
			}
			if len(s.ns) != tt.n {
				t.Fatalf("samples = %d, want %d", len(s.ns), tt.n)
			}
			if got := median(s.ns); got != tt.ns {
				t.Errorf("median ns = %v, want %v", got, tt.ns)
			}
			if got := median(s.bytes); got != tt.bytes {
				t.Errorf("median bytes = %v, want %v", got, tt.bytes)
			}
			if got := median(s.allocs); got != tt.allocs {
				t.Errorf("median allocs = %v, want %v", got, tt.allocs)
			}
		})
	}
	if _, ok := data["cte/xwb1989"]; ok {
		t.Error("skipped benchmark must not produce samples")
	}
}

func TestParseBenchEmpty(t *testing.T) {
	if _, _, err := parseBench([]byte("PASS\n")); err == nil {
		t.Fatal("expected an error when no benchmark lines are present")
	}
}

func TestMedianEven(t *testing.T) {
	if got := median([]float64{4, 1, 3, 2}); got != 2.5 {
		t.Fatalf("median = %v, want 2.5", got)
	}
}

func TestParseCellsAllFamilies(t *testing.T) {
	out := []byte(`cpu: Test CPU
BenchmarkLex/simple_select/gosqlx_scratch-4   	  100	   400 ns/op	  60.00 MB/s	   72 B/op	   0 allocs/op
BenchmarkLex/simple_select/gosqlx_scratch-4   	  100	   500 ns/op	  60.00 MB/s	   72 B/op	   0 allocs/op
BenchmarkParseDialect/mysql/dolthub_vitess    	   10	  9000 ns/op	   1.00 MB/s	  100 B/op	   3 allocs/op
BenchmarkParseParallel/join/gosqlx_norelease-4	  100	   300 ns/op	  5.00 MB/s	   10 B/op	   1 allocs/op
BenchmarkParse/cte/xwb1989-4                  	--- SKIP: does not accept this query
BenchmarkParseFresh/join/vitess               	  100	  7000 ns/op	   4.00 MB/s	   50 B/op	   2 allocs/op
`)
	cpu, cells, err := parseCells(out)
	if err != nil {
		t.Fatal(err)
	}
	if cpu != "Test CPU" {
		t.Errorf("cpu = %q", cpu)
	}
	want := map[cellKey]float64{
		{"Lex", "simple_select", "gosqlx_scratch"}:    450,
		{"ParseDialect", "mysql", "dolthub_vitess"}:   9000,
		{"ParseParallel", "join", "gosqlx_norelease"}: 300,
		{"ParseFresh", "join", "vitess"}:              7000,
	}
	if len(cells) != len(want) {
		t.Fatalf("got %d cells, want %d: %v", len(cells), len(want), cells)
	}
	for k, ns := range want {
		s, ok := cells[k]
		if !ok {
			t.Errorf("missing cell %+v", k)
			continue
		}
		if got := median(s.ns); got != ns {
			t.Errorf("%+v median = %v, want %v", k, got, ns)
		}
	}
}

func TestParseBenchIgnoresOtherFamilies(t *testing.T) {
	out := []byte(`BenchmarkLex/q/a-4   100  1 ns/op  1 B/op  1 allocs/op
BenchmarkParse/q/gosqlx-4  100  2 ns/op  1 B/op  1 allocs/op
`)
	_, data, err := parseBench(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 1 || data["q/gosqlx"] == nil {
		t.Fatalf("parseBench must expose only BenchmarkParse samples, got %v", data)
	}
}

func TestParseMatrix(t *testing.T) {
	got, err := parseMatrix("1,4", "default,off")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range got {
		ids = append(ids, c.ID)
	}
	want := []string{"cpu1-gogc-default", "cpu1-gogc-off", "cpu4-gogc-default", "cpu4-gogc-off"}
	if !slices.Equal(ids, want) {
		t.Errorf("ids = %v, want %v", ids, want)
	}
	if got[0].CPU != 1 || got[3].GOGC != "off" {
		t.Errorf("unexpected configs: %+v", got)
	}

	def, err := parseMatrix("", "")
	if err != nil || len(def) != 1 || def[0].CPU != 0 || def[0].GOGC != "default" {
		t.Errorf("empty flags must give the single v1 run, got %+v, %v", def, err)
	}
	for _, bad := range [][2]string{{"0", ""}, {"x", ""}, {"", "100"}} {
		if _, err := parseMatrix(bad[0], bad[1]); err == nil {
			t.Errorf("parseMatrix(%q, %q) must fail", bad[0], bad[1])
		}
	}
}

func TestEnvForGOGC(t *testing.T) {
	base := []string{"PATH=/bin", "GOGC=50", "GOMEMLIMIT=9GiB"}
	isGC := func(s string) bool { return strings.HasPrefix(s, "GOGC=") || strings.HasPrefix(s, "GOMEMLIMIT=") }
	if got := envForGOGC(base, "default", defaultGOMEMLIMIT); slices.ContainsFunc(got, isGC) {
		t.Errorf("default must drop an inherited GOGC and GOMEMLIMIT, got %v", got)
	}
	// GOGC=off always comes with a memory limit, so the heap stops growing
	// onto fresh pages whose first-touch faults would be timed (W0-15).
	got := envForGOGC(base, "off", defaultGOMEMLIMIT)
	if !slices.Contains(got, "GOGC=off") || slices.Contains(got, "GOGC=50") {
		t.Errorf("off must replace GOGC, got %v", got)
	}
	if !slices.Contains(got, "GOMEMLIMIT="+defaultGOMEMLIMIT) || slices.Contains(got, "GOMEMLIMIT=9GiB") {
		t.Errorf("off must set GOMEMLIMIT=%s in place of the inherited one, got %v", defaultGOMEMLIMIT, got)
	}
	if got := envForGOGC(base, "off", "off"); slices.ContainsFunc(got, func(s string) bool { return strings.HasPrefix(s, "GOMEMLIMIT=") }) {
		t.Errorf("-gomemlimit=off must leave GOMEMLIMIT unset, got %v", got)
	}
	if len(base) != 3 || base[1] != "GOGC=50" {
		t.Error("envForGOGC must not modify its input")
	}
}

func TestRawPathFor(t *testing.T) {
	if got := rawPathFor("results/latest.txt", 0, ConfigV{ID: "x"}); got != "results/latest.txt" {
		t.Errorf("primary raw path = %q", got)
	}
	if got := rawPathFor("results/latest.txt", 2, ConfigV{ID: "cpu4-gogc-off"}); got != "results/latest-cpu4-gogc-off.txt" {
		t.Errorf("secondary raw path = %q", got)
	}
}

// TestV1ViewKeepsWebsiteContract checks the compatibility rule of schema v2:
// the v1 results cover exactly the v1 parsers, so the website never sees a
// peer it has no copy for, while the v2 peers list has them all.
func TestV1ViewKeepsWebsiteContract(t *testing.T) {
	data := map[cellKey]*samples{}
	for _, q := range compare.Corpus {
		for _, p := range compare.Parsers {
			data[cellKey{"Parse", q.ID, p.ID}] = &samples{ns: []float64{1}, bytes: []float64{2}, allocs: []float64{3}}
		}
	}
	res, err := v1Results(data)
	if err != nil {
		t.Fatal(err)
	}
	v1 := map[string]bool{}
	for _, p := range compare.Parsers {
		if p.Schema1 {
			v1[p.ID] = true
		}
	}
	for _, r := range res {
		if !v1[r.Parser] {
			t.Errorf("v1 results contain non-v1 parser %s", r.Parser)
		}
	}
	if len(res) != len(v1)*len(compare.Corpus) {
		t.Errorf("v1 results = %d rows, want %d", len(res), len(v1)*len(compare.Corpus))
	}
	for _, id := range []string{"gosqlx", "pg_query_go", "vitess", "tidb", "xwb1989"} {
		if !v1[id] {
			t.Errorf("%s dropped from the v1 view", id)
		}
	}
	if len(parserVersions("abc", true)) != len(v1) {
		t.Error("parserVersions(v1Only) must list exactly the v1 parsers")
	}
	if len(parserVersions("abc", false)) != len(compare.Parsers) {
		t.Error("parserVersions(all) must list every parser")
	}
}

func TestV1ResultsFailsOnMissingSamples(t *testing.T) {
	if _, err := v1Results(map[cellKey]*samples{}); err == nil {
		t.Fatal("a supported pair without samples must be an error")
	}
}

// TestReportKeepsV1Fields marshals a Report and checks every top-level key
// the website's CompetitorRun type reads is still present.
func TestReportKeepsV1Fields(t *testing.T) {
	b, err := json.Marshal(Report{SchemaVersion: schemaVersion})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schemaVersion", "generatedAt", "commit", "dirty", "goVersion", "hardware",
		"stage", "method", "caveat", "parsers", "queries", "results"} {
		if _, ok := m[k]; !ok {
			t.Errorf("v1 key %q missing from the report", k)
		}
	}
	for _, k := range []string{"peers", "ormQueries", "configs", "cells", "acceptance", "commonAccept"} {
		if _, ok := m[k]; !ok {
			t.Errorf("v2 key %q missing from the report", k)
		}
	}
	if schemaVersion != 2 {
		t.Errorf("schemaVersion = %d, want 2", schemaVersion)
	}
}

// TestPublishedJSONStillDecodes decodes the committed results/latest.json
// (written by an earlier schema) into the current Report: the website copy
// and every v1 consumer must keep working until it is regenerated.
func TestPublishedJSONStillDecodes(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "results", "latest.json"))
	if err != nil {
		t.Skipf("no committed results: %v", err)
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.SchemaVersion < 1 || len(r.Results) == 0 || len(r.Parsers) == 0 {
		t.Errorf("committed results look empty: %+v", r.SchemaVersion)
	}
	if r.SchemaVersion == 1 && len(r.Cells) != 0 {
		t.Error("a v1 document must not carry v2 cells")
	}
}

func TestCellResultsMedianAndOrder(t *testing.T) {
	data := map[cellKey]*samples{
		{"Render", "q", "b"}: {ns: []float64{4, 2}, bytes: []float64{1, 1}, allocs: []float64{1, 1}},
		{"Lex", "q", "a"}:    {ns: []float64{10}, bytes: []float64{0}, allocs: []float64{0}},
	}
	got := cellResults(data, "cfg")
	if len(got) != 2 || got[0].Cell != "Lex" || got[1].Cell != "Render" {
		t.Fatalf("unexpected order: %+v", got)
	}
	if got[1].NsPerOp != 3 || got[1].Samples != 2 || got[1].Config != "cfg" {
		t.Errorf("render cell = %+v", got[1])
	}
}

// unquotedMeta returns the shell metacharacters of cmd outside single quotes.
func unquotedMeta(cmd string) string {
	var out []rune
	inQuote := false
	for _, r := range cmd {
		if r == '\'' {
			inQuote = !inQuote
			continue
		}
		if !inQuote && strings.ContainsRune("()|&;<>$*?[]{}!^`\"\\#~", r) {
			out = append(out, r)
		}
	}
	return string(out)
}

// TestMethodCommandIsCopyPasteable keeps method.command (shown by the
// website as a reproduce command) free of unquoted shell metacharacters, and
// restricted to the family the v1 results come from.
func TestMethodCommandIsCopyPasteable(t *testing.T) {
	cfgs, err := parseMatrix("1,4", "default,off")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cfgs {
		for _, re := range []string{v1BenchRegex, "^Benchmark(Parse|ParseORM|Lex)$"} {
			cmd := shellCommand(c.GOGC, defaultGOMEMLIMIT, benchArgs(re, 10, c.CPU, "200ms"))
			if bad := unquotedMeta(cmd); bad != "" {
				t.Errorf("%q has unquoted shell metacharacters %q", cmd, bad)
			}
			if strings.Contains(cmd, "GOGC=default") {
				t.Errorf("%q uses GOGC=default, which is not a GOGC value", cmd)
			}
			if (c.GOGC == "off") != strings.HasPrefix(cmd, "GOGC=off GOMEMLIMIT="+defaultGOMEMLIMIT+" ") {
				t.Errorf("%q: the GOGC=off GOMEMLIMIT prefix must appear exactly for the off configuration", cmd)
			}
		}
	}
	want := "go test -run='^$' -bench='^BenchmarkParse$' -benchmem -count=10 -cpu=1 -benchtime=200ms ."
	if got := shellCommand("default", defaultGOMEMLIMIT, benchArgs(v1BenchRegex, 10, 1, "200ms")); got != want {
		t.Errorf("v1 command = %q, want %q", got, want)
	}
}

func TestBenchRegexFor(t *testing.T) {
	all, err := benchRegexFor("all")
	if err != nil || !strings.Contains(all, "ParseParallel") || !strings.Contains(all, "Render") {
		t.Errorf("all = %q, %v", all, err)
	}
	if re, err := benchRegexFor("Parse"); err != nil || re != "^Benchmark(Parse)$" {
		t.Errorf("Parse = %q, %v", re, err)
	}
	for _, bad := range []string{"Lex", "Parse,Nope"} {
		if _, err := benchRegexFor(bad); err == nil {
			t.Errorf("benchRegexFor(%q) must fail", bad)
		}
	}
}

// TestNoReleaseVariantGetsCommitVersion covers every GoSQLX variant, not just
// the one with ID "gosqlx".
func TestNoReleaseVariantGetsCommitVersion(t *testing.T) {
	for _, p := range parserVersions("0123456789abcdef", false) {
		if p.Module == gosqlxModule && p.Version != "commit 0123456789ab" {
			t.Errorf("%s version = %q, want the measured commit", p.ID, p.Version)
		}
	}
}

// TestRatioMarkdown: the job summary compares GoSQLX with each peer by the
// ratio of their times in the same job, geomean over the groups both ran,
// and names the runner CPU; it never prints absolute ns/op, which do not
// carry across jobs (hosted runners differ in CPU model).
func TestRatioMarkdown(t *testing.T) {
	cfgs := []ConfigV{{ID: "cpu4-gogc-default"}, {ID: "cpu1-gogc-off"}}
	cell := func(c, g, p, cfg string, ns float64) CellV {
		return CellV{Cell: c, Group: g, Parser: p, Config: cfg, NsPerOp: ns, Samples: 10}
	}
	cells := []CellV{
		cell("Parse", "join", "gosqlx", "cpu4-gogc-default", 12345),
		cell("Parse", "join", "vitess", "cpu4-gogc-default", 10288),
		cell("Parse", "aggregate", "gosqlx", "cpu4-gogc-default", 13000),
		cell("Parse", "aggregate", "vitess", "cpu4-gogc-default", 10000),
		cell("Parse", "join", "tidb", "cpu4-gogc-default", 24690),
		cell("Parse", "join", "gosqlx", "cpu1-gogc-off", 900),
		cell("Parse", "join", "vitess", "cpu1-gogc-off", 1000),
		cell("Lex", "join", "gosqlx_scratch", "cpu4-gogc-default", 3700),
		cell("Lex", "join", "vitess", "cpu4-gogc-default", 1000),
	}
	md := ratioMarkdown(cells, cfgs, "AMD EPYC 7763 64-Core Processor")
	for _, want := range []string{
		"Runner CPU: `AMD EPYC 7763 64-Core Processor`",
		"| Parse | gosqlx | vitess | 1.25 | 0.90 | 2 | aggregate 1.30 |",
		"| Parse | gosqlx | tidb | 0.50 |  | 1 | join 0.50 |",
		"| Lex | gosqlx_scratch | vitess | 3.70 |  | 1 | join 3.70 |",
		"| cell | GoSQLX | peer | cpu4-gogc-default | cpu1-gogc-off |",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("ratio table lacks %q:\n%s", want, md)
		}
	}
	for _, abs := range []string{"12345", "10288", "24690"} {
		if strings.Contains(md, abs) {
			t.Errorf("ratio table prints the absolute time %s:\n%s", abs, md)
		}
	}
	if i, j := strings.Index(md, "| Parse |"), strings.Index(md, "| Lex |"); i < 0 || j < 0 || i > j {
		t.Errorf("rows must follow the family order (Parse before Lex):\n%s", md)
	}
}
