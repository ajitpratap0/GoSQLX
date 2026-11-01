// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bench describes one synthetic benchmark of an arm.
type bench struct {
	name   string
	ns     float64 // centre of the time distribution
	noise  float64 // relative half-width of the time jitter (0.01 = +-1%)
	bytes  float64
	allocs float64
}

// lcg is a tiny deterministic generator so the synthetic samples are the same
// on every run.
type lcg uint64

func (l *lcg) next() float64 {
	*l = *l*6364136223846793005 + 1442695040888963407
	return float64(uint64(*l)>>11) / float64(1<<53) // [0, 1)
}

// arm renders rounds of Go benchmark output for the given benchmarks, one
// line per benchmark per round, as `go test -bench -count 1` repeated would.
func arm(seed uint64, rounds int, benches []bench) string {
	r := lcg(seed)
	var b strings.Builder
	b.WriteString("goos: linux\ngoarch: amd64\npkg: github.com/ajitpratap0/GoSQLX/pkg/gosqlx\n")
	for i := 0; i < rounds; i++ {
		for _, bn := range benches {
			ns := bn.ns * (1 + bn.noise*(2*r.next()-1))
			fmt.Fprintf(&b, "%s \t  100000\t%10.1f ns/op\t%8.2f MB/s\t%g B/op\t%g allocs/op\n", bn.name, ns, 123.4, bn.bytes, bn.allocs)
		}
	}
	b.WriteString("PASS\n")
	return b.String()
}

func mustParse(t *testing.T, s string) *Run {
	t.Helper()
	r, err := parseBench(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// suite is a stand-in for the gated suite: 20 benchmarks so that the A/A
// fraction rule (more than 10%) needs at least 3 noisy ones.
func suite() []bench {
	var out []bench
	for i := 0; i < 20; i++ {
		out = append(out, bench{
			name:   fmt.Sprintf("BenchmarkParseE2E/q%02d", i),
			ns:     1000 + 100*float64(i),
			noise:  0.01,
			bytes:  800 + 16*float64(i),
			allocs: float64(5 + i),
		})
	}
	return out
}

func modify(in []bench, f func(i int, b *bench)) []bench {
	out := append([]bench(nil), in...)
	for i := range out {
		f(i, &out[i])
	}
	return out
}

const rounds = 10

func evaluate(t *testing.T, base, head, aa []bench, cfg Config) Result {
	t.Helper()
	in := Inputs{Base: mustParse(t, arm(1, rounds, base)), Head: mustParse(t, arm(2, rounds, head))}
	if aa != nil {
		in.AA = mustParse(t, arm(3, rounds, aa))
	}
	return Evaluate(in, cfg)
}

func TestNoOpChangePasses(t *testing.T) {
	s := suite()
	res := evaluate(t, s, s, s, DefaultConfig())
	if res.Verdict != Pass {
		t.Fatalf("verdict = %s, reasons %v", res.Verdict, res.Reasons)
	}
	if res.AACompared != len(s) || res.AANoisy != 0 {
		t.Fatalf("A/A: %d noisy of %d, want 0 of %d", res.AANoisy, res.AACompared, len(s))
	}
}

func TestTenPercentSlowdownIsARegression(t *testing.T) {
	s := suite()
	slow := modify(s, func(_ int, b *bench) { b.ns *= 1.10 })
	res := evaluate(t, s, slow, s, DefaultConfig())
	if res.Verdict != Regression {
		t.Fatalf("verdict = %s, want regression", res.Verdict)
	}
	if res.TimeRegressed != len(s) {
		t.Fatalf("time regressions = %d, want %d", res.TimeRegressed, len(s))
	}
	if g := (res.Geomean - 1) * 100; math.Abs(g-10) > 1 {
		t.Fatalf("geomean = %+.2f%%, want about +10%%", g)
	}
	if res.HardRegressed != 0 {
		t.Fatalf("hard regressions = %d, want 0 (only time moved)", res.HardRegressed)
	}
}

func TestSlowdownOnOneBenchmarkIsCaught(t *testing.T) {
	s := suite()
	slow := modify(s, func(i int, b *bench) {
		if i == 7 {
			b.ns *= 1.10
		}
	})
	res := evaluate(t, s, slow, s, DefaultConfig())
	if res.Verdict != Regression || res.TimeRegressed != 1 || !res.Rows[7].Regress {
		t.Fatalf("verdict %s, %d time regressions, row 7 regress=%v", res.Verdict, res.TimeRegressed, res.Rows[7].Regress)
	}
}

func TestSmallUniformSlowdownTripsTheGeomean(t *testing.T) {
	// +2% everywhere: under the 3% per-benchmark bar, over the 1.5% geomean bar.
	s := modify(suite(), func(_ int, b *bench) { b.noise = 0.002 })
	slow := modify(s, func(_ int, b *bench) { b.ns *= 1.02 })
	res := evaluate(t, s, slow, s, DefaultConfig())
	if res.Verdict != Regression || res.TimeRegressed != 0 {
		t.Fatalf("verdict %s with %d per-benchmark regressions, want a geomean-only regression", res.Verdict, res.TimeRegressed)
	}
	if !strings.Contains(strings.Join(res.Reasons, "\n"), "geomean") {
		t.Fatalf("reasons %v do not mention the geomean", res.Reasons)
	}
}

func TestOneExtraAllocationIsARegression(t *testing.T) {
	s := suite()
	more := modify(s, func(i int, b *bench) {
		if i == 3 {
			b.allocs++
			b.bytes += 16
		}
	})
	res := evaluate(t, s, more, s, DefaultConfig())
	if res.Verdict != Regression {
		t.Fatalf("verdict = %s, want regression", res.Verdict)
	}
	r := res.Rows[3]
	if !r.Regress || !strings.Contains(strings.Join(r.Status, ","), "+allocs") {
		t.Fatalf("row 3 status %v, want +allocs", r.Status)
	}
	if res.TimeRegressed != 0 {
		t.Fatalf("time regressions = %d, want 0", res.TimeRegressed)
	}
}

func TestExtraAllocationIsCaughtEvenWithFewRounds(t *testing.T) {
	// Two samples per arm can never reach p < 0.01; complete separation of a
	// deterministic metric still counts.
	s := suite()[:1]
	more := modify(s, func(_ int, b *bench) { b.allocs++ })
	in := Inputs{Base: mustParse(t, arm(1, 2, s)), Head: mustParse(t, arm(2, 2, more))}
	if res := Evaluate(in, DefaultConfig()); res.Verdict != Regression {
		t.Fatalf("verdict = %s, want regression", res.Verdict)
	}
}

func TestFewerAllocationsPass(t *testing.T) {
	s := suite()
	fewer := modify(s, func(_ int, b *bench) { b.allocs--; b.bytes -= 64 })
	if res := evaluate(t, s, fewer, s, DefaultConfig()); res.Verdict != Pass {
		t.Fatalf("verdict = %s, reasons %v", res.Verdict, res.Reasons)
	}
}

func TestBytesThreshold(t *testing.T) {
	s := suite()
	for _, tc := range []struct {
		grow float64
		want Verdict
	}{{1.01, Pass}, {1.05, Regression}} {
		grown := modify(s, func(_ int, b *bench) { b.bytes = math.Round(b.bytes * tc.grow) })
		if res := evaluate(t, s, grown, s, DefaultConfig()); res.Verdict != tc.want {
			t.Errorf("B/op x%.2f: verdict %s, want %s (%v)", tc.grow, res.Verdict, tc.want, res.Reasons)
		}
	}
}

func noisyAA(s []bench) []bench {
	// A third of the benchmarks wander by 8% in the A/A arm.
	return modify(s, func(i int, b *bench) {
		if i%3 == 0 {
			b.ns *= 1.08
		}
	})
}

func TestNoisyAAAsksForARerunThenIsInconclusive(t *testing.T) {
	s := suite()
	slow := modify(s, func(_ int, b *bench) { b.ns *= 1.10 })

	res := evaluate(t, s, slow, noisyAA(s), DefaultConfig())
	if res.Verdict != Noisy || !res.TimingDisabled {
		t.Fatalf("first attempt: verdict %s, timing disabled %v; want noisy", res.Verdict, res.TimingDisabled)
	}
	if res.TimeRegressed != 0 {
		t.Fatalf("a noisy run must not judge timings, got %d regressions", res.TimeRegressed)
	}

	cfg := DefaultConfig()
	cfg.FinalAttempt = true
	if res := evaluate(t, s, slow, noisyAA(s), cfg); res.Verdict != Inconclusive {
		t.Fatalf("re-run: verdict %s, want inconclusive", res.Verdict)
	}
}

func TestNoisyAAStillReportsAllocationRegressions(t *testing.T) {
	s := suite()
	more := modify(s, func(_ int, b *bench) { b.allocs++ })
	if res := evaluate(t, s, more, noisyAA(s), DefaultConfig()); res.Verdict != Regression {
		t.Fatalf("verdict = %s, want regression: allocation counts are not timing noise", res.Verdict)
	}
}

func TestAANoiseAtTheThresholdIsNotNoisy(t *testing.T) {
	// Exactly 10% of benchmarks noisy (2 of 20) is allowed; the rule is "more than".
	s := suite()
	aa := modify(s, func(i int, b *bench) {
		if i < 2 {
			b.ns *= 1.08
		}
	})
	res := evaluate(t, s, s, aa, DefaultConfig())
	if res.AANoisy != 2 || res.Verdict != Pass {
		t.Fatalf("A/A noisy %d, verdict %s; want 2 and pass", res.AANoisy, res.Verdict)
	}
}

func irArm(vals map[string]float64) string {
	var b strings.Builder
	for _, name := range []string{"BenchmarkPerfdriver/e2e/join", "BenchmarkPerfdriver/e2e/insert"} {
		fmt.Fprintf(&b, "%s 1 %g instructions/op\n", name, vals[name])
	}
	return b.String()
}

func TestInstructionCountThreshold(t *testing.T) {
	s := suite()
	base := map[string]float64{"BenchmarkPerfdriver/e2e/join": 100000, "BenchmarkPerfdriver/e2e/insert": 50000}
	for _, tc := range []struct {
		grow float64
		want Verdict
	}{{1.01, Pass}, {1.02, Regression}} {
		head := map[string]float64{}
		for k, v := range base {
			head[k] = v
		}
		head["BenchmarkPerfdriver/e2e/join"] *= tc.grow
		in := Inputs{
			Base: mustParse(t, arm(1, rounds, s)), Head: mustParse(t, arm(2, rounds, s)),
			IrBase: mustParse(t, irArm(base)), IrHead: mustParse(t, irArm(head)),
		}
		res := Evaluate(in, DefaultConfig())
		if res.Verdict != tc.want || len(res.IrRows) != 2 {
			t.Errorf("Ir x%.2f: verdict %s with %d rows, want %s", tc.grow, res.Verdict, len(res.IrRows), tc.want)
		}
	}
}

func TestMissingAndNewBenchmarksAreReportedNotJudged(t *testing.T) {
	s := suite()
	head := append(append([]bench(nil), s[1:]...), bench{name: "BenchmarkNew/x", ns: 5000, noise: 0.01, bytes: 1, allocs: 99})
	res := evaluate(t, s, head, nil, DefaultConfig())
	if res.Verdict != Pass {
		t.Fatalf("verdict = %s (%v)", res.Verdict, res.Reasons)
	}
	if len(res.MissingInHead) != 1 || res.MissingInHead[0] != s[0].name {
		t.Fatalf("missing = %v", res.MissingInHead)
	}
	if len(res.NewInHead) != 1 || res.NewInHead[0] != "BenchmarkNew/x" {
		t.Fatalf("new = %v", res.NewInHead)
	}
}

// writeArms writes base/head/aa files and returns their paths.
func writeArms(t *testing.T, base, head []bench) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "base.txt"), filepath.Join(dir, "head.txt"), filepath.Join(dir, "aa.txt")}
	for i, content := range []string{arm(1, rounds, base), arm(2, rounds, head), arm(3, rounds, base)} {
		if err := os.WriteFile(paths[i], []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return paths[0], paths[1], paths[2]
}

func TestShadowModeNeverFails(t *testing.T) {
	s := suite()
	base, head, aa := writeArms(t, s, modify(s, func(_ int, b *bench) { b.ns *= 1.10; b.allocs++ }))
	status := filepath.Join(t.TempDir(), "status")
	var out bytes.Buffer
	code, err := realMain([]string{"-base", base, "-head", head, "-aa", aa, "-status", status}, &out)
	if err != nil || code != 0 {
		t.Fatalf("shadow mode: code %d, err %v; want 0, nil", code, err)
	}
	if got, _ := os.ReadFile(status); strings.TrimSpace(string(got)) != "regression" {
		t.Fatalf("status file = %q, want regression", got)
	}
	md := out.String()
	for _, want := range []string{ReportMarker, "Perf gate: REGRESSION", "shadow mode", "+allocs", "slower"} {
		if !strings.Contains(md, want) {
			t.Errorf("report lacks %q", want)
		}
	}
}

func TestEnforceModeFailsUnlessAccepted(t *testing.T) {
	s := suite()
	base, head, aa := writeArms(t, s, modify(s, func(_ int, b *bench) { b.allocs++ }))
	args := []string{"-base", base, "-head", head, "-aa", aa, "-enforce"}
	if code, err := realMain(args, &bytes.Buffer{}); err != nil || code != 1 {
		t.Fatalf("enforce: code %d, err %v; want 1", code, err)
	}
	if code, err := realMain(append(args, "-accepted"), &bytes.Buffer{}); err != nil || code != 0 {
		t.Fatalf("enforce + accepted: code %d, err %v; want 0", code, err)
	}
	// A clean change passes in enforce mode too.
	base, head, aa = writeArms(t, s, s)
	if code, err := realMain([]string{"-base", base, "-head", head, "-aa", aa, "-enforce"}, &bytes.Buffer{}); err != nil || code != 0 {
		t.Fatalf("enforce, no change: code %d, err %v; want 0", code, err)
	}
}

func TestUsageErrors(t *testing.T) {
	s := suite()
	base, head, _ := writeArms(t, s, s)
	empty := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(empty, []byte("PASS\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-base", base},
		{"-base", base, "-head", head, "-sec-base", base},
		{"-base", base, "-head", head, "-ir-head", head},
		{"-base", base, "-head", filepath.Join(t.TempDir(), "absent.txt")},
		{"-base", empty, "-head", head},
	} {
		if _, err := realMain(args, &bytes.Buffer{}); err == nil {
			t.Errorf("realMain(%q) succeeded, want an error", args)
		}
	}
}

func TestFewRoundsNeverJudgeTimings(t *testing.T) {
	// Two samples per arm cannot reach p < 0.01, and separated timings alone
	// are not evidence: a 10% slowdown over two rounds is not reported.
	s := suite()[:1]
	slow := modify(s, func(_ int, b *bench) { b.ns *= 1.10 })
	in := Inputs{Base: mustParse(t, arm(1, 2, s)), Head: mustParse(t, arm(2, 2, slow))}
	if res := Evaluate(in, DefaultConfig()); res.TimeRegressed != 0 {
		t.Fatalf("%d time regressions from 2 rounds, want 0", res.TimeRegressed)
	}
}
