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

// layoutArm renders `rounds` rounds of benchmark output from `k` code
// layouts, as ab.sh writes it: round r runs layout r mod k, preceded by a
// "layout: <seed>" line. Layout j of the arm shifts every benchmark by its
// own factor 1 + spread*(2u-1), u uniform from `layoutSeed`, mimicking the
// placement effect of one -randlayout binary; samples within a layout jitter
// by the benchmark's own noise. Seeds of one arm are firstSeed..firstSeed+k-1.
func layoutArm(sampleSeed, layoutSeed uint64, firstSeed, rounds, k int, spread float64, benches []bench) string {
	lr := lcg(layoutSeed)
	effect := make([][]float64, k)
	for j := range effect {
		effect[j] = make([]float64, len(benches))
		for i := range benches {
			effect[j][i] = 1 + spread*(2*lr.next()-1)
		}
	}
	r := lcg(sampleSeed)
	var b strings.Builder
	for round := 0; round < rounds; round++ {
		j := round % k
		fmt.Fprintf(&b, "layout: %d\n", firstSeed+j)
		b.WriteString("goos: linux\ngoarch: amd64\npkg: github.com/ajitpratap0/GoSQLX/pkg/gosqlx\n")
		for i, bn := range benches {
			ns := bn.ns * effect[j][i] * (1 + bn.noise*(2*r.next()-1))
			fmt.Fprintf(&b, "%s \t  100000\t%10.1f ns/op\t%g B/op\t%g allocs/op\n", bn.name, ns, bn.bytes, bn.allocs)
		}
	}
	b.WriteString("PASS\n")
	return b.String()
}

// quiet is the synthetic suite with 0.5% sample noise: the layout effect,
// not sampling, dominates, as on the CI runners.
func quiet() []bench {
	return modify(suite(), func(_ int, b *bench) { b.noise = 0.005 })
}

func TestParseLayoutLabels(t *testing.T) {
	run := mustParse(t, "layout: 11\nBenchmarkA 1 10 ns/op 4 allocs/op\nBenchmarkA 1 12 ns/op 4 allocs/op\n"+
		"goos: linux\nlayout: 12\nBenchmarkA 1 20 ns/op 4 allocs/op\nlayout: 11\nBenchmarkA 1 11 ns/op 4 allocs/op\n")
	labels, groups := run.ByLayout("BenchmarkA", unitTime)
	if fmt.Sprint(labels) != "[11 12]" || fmt.Sprint(groups) != "[[10 12 11] [20]]" {
		t.Fatalf("ByLayout = %v %v, want [11 12] [[10 12 11] [20]]", labels, groups)
	}
	if got := run.Get("BenchmarkA", unitAllocs); len(got) != 4 {
		t.Fatalf("allocs samples = %v, want 4 (labels must not change Get)", got)
	}
	plain := mustParse(t, "BenchmarkA 1 10 ns/op\nBenchmarkA 1 11 ns/op\n")
	if labels, groups := plain.ByLayout("BenchmarkA", unitTime); len(labels) != 1 || labels[0] != "" || len(groups[0]) != 2 {
		t.Fatalf("unlabelled ByLayout = %q %v, want one unlabelled group of 2", labels, groups)
	}
}

func TestCompareLayoutsUsesTheLayoutAsTheUnit(t *testing.T) {
	// Three layouts per arm, many samples each: the pooled test would see
	// 30 vs 30 samples, the layout test sees 3 vs 3 medians.
	base := [][]float64{{100, 101, 100, 99, 100, 101, 100, 99, 100, 100}, {104, 104, 105, 103, 104, 104, 105, 104, 104, 104}, {98, 98, 97, 98, 99, 98, 98, 98, 97, 98}}
	head := [][]float64{{106, 106, 107, 105, 106, 106, 106, 107, 106, 106}, {103, 103, 102, 103, 104, 103, 103, 103, 102, 103}, {105, 105, 105, 104, 106, 105, 105, 105, 105, 106}}
	c := compareLayouts(base, head)
	if !c.ByLayout || c.NBase != 3 || c.NHead != 3 {
		t.Fatalf("cmp = %+v, want ByLayout with 3 layouts per arm", c)
	}
	if want := mean([]float64{100, 104, 98}); math.Abs(c.Base-want) > 1e-9 {
		t.Fatalf("Base = %g, want the mean of the layout medians %g", c.Base, want)
	}
	if math.Abs(c.P-mannWhitney([]float64{100, 104, 98}, []float64{106, 103, 105})) > 1e-12 {
		t.Fatalf("P = %g is not the Mann-Whitney p of the layout medians", c.P)
	}
	if c.P < 0.05 {
		t.Fatalf("P = %g: three layouts per arm cannot be significant", c.P)
	}
	if math.IsNaN(c.SpreadPct) || c.SpreadPct < 2 || c.SpreadPct > 5 {
		t.Fatalf("SpreadPct = %g, want the relative sd of 100, 104, 98 (about 3%%)", c.SpreadPct)
	}
	pooled := compare(flatten(base), flatten(head))
	if pooled.P >= 0.01 {
		t.Fatalf("pooled p = %g: the fixture should fool a sample-level test", pooled.P)
	}
}

func flatten(groups [][]float64) []float64 {
	var out []float64
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

func TestCompareArmsFallsBackWithoutLayouts(t *testing.T) {
	s := suite()[:1]
	base, head := mustParse(t, arm(1, rounds, s)), mustParse(t, arm(2, rounds, s))
	c := compareArms(base, head, s[0].name, unitTime)
	if c.ByLayout || c.NBase != rounds || !math.IsNaN(c.SpreadPct) {
		t.Fatalf("unlabelled runs: %+v, want the sample-level comparison", c)
	}
	// One layout per arm is no layout replication either.
	one := mustParse(t, layoutArm(1, 7, 1, rounds, 1, 0.04, s))
	if c := compareArms(one, one, s[0].name, unitTime); c.ByLayout {
		t.Fatal("a single layout per arm must use the sample-level comparison")
	}
}

// TestLayoutShiftIsNotARegression reproduces the false alarm of runs
// 41543555385, 41545141354 and 41545145216: a change that adds no work moves
// the code, and in one fixed layout a benchmark ends up 4% slower. Judged by
// samples of one binary per arm it is a "significant" regression; judged by
// layouts, where head's layouts come from the same distribution as base's,
// it is not.
func TestLayoutShiftIsNotARegression(t *testing.T) {
	s := quiet()
	shifted := modify(s, func(i int, b *bench) {
		if i == 4 {
			b.ns *= 1.04
		}
	})
	fixed := evaluate(t, s, shifted, s, DefaultConfig())
	if fixed.Verdict != Regression {
		t.Fatalf("one fixed layout per arm: verdict %s, want the (false) regression the old gate reported", fixed.Verdict)
	}

	const k, rounds = 10, 20
	in := Inputs{
		Base: mustParse(t, layoutArm(1, 100, 1, rounds, k, 0.04, s)),
		Head: mustParse(t, layoutArm(2, 200, 1, rounds, k, 0.04, s)),
		AA:   mustParse(t, layoutArm(3, 300, 11, rounds, k, 0.04, s)),
	}
	res := Evaluate(in, DefaultConfig())
	if !res.ByLayout || res.Layouts != k {
		t.Fatalf("ByLayout %v with %d layouts, want true and %d", res.ByLayout, res.Layouts, k)
	}
	if res.Verdict != Pass || res.TimeRegressed != 0 {
		t.Fatalf("verdict %s with %d time regressions (%v), want pass", res.Verdict, res.TimeRegressed, res.Reasons)
	}
}

// TestLayoutNoiseFalseAlarmRate runs many no-op comparisons whose only
// difference is the draw of code layouts (+-5% per layout, independent per
// benchmark) and counts REGRESSION verdicts. With the layout as the unit the
// rate stays near the nominal level; pooling the samples of one binary per
// arm flags most of them.
func TestLayoutNoiseFalseAlarmRate(t *testing.T) {
	s := quiet()
	const trials, k, rounds = 200, 10, 20
	var layoutFalse, pooledFalse int
	for i := uint64(0); i < trials; i++ {
		base := mustParse(t, layoutArm(10*i+1, 10*i+2, 1, rounds, k, 0.05, s))
		head := mustParse(t, layoutArm(10*i+3, 10*i+4, 1, rounds, k, 0.05, s))
		if Evaluate(Inputs{Base: base, Head: head}, DefaultConfig()).Verdict == Regression {
			layoutFalse++
		}
		b1 := mustParse(t, layoutArm(10*i+1, 10*i+2, 1, rounds, 1, 0.05, s))
		h1 := mustParse(t, layoutArm(10*i+3, 10*i+4, 1, rounds, 1, 0.05, s))
		if Evaluate(Inputs{Base: b1, Head: h1}, DefaultConfig()).Verdict == Regression {
			pooledFalse++
		}
	}
	// The false discovery rate is held at alpha = 1% over the suite, which
	// for a no-op change is the chance of any false regression: allow 2%.
	if layoutFalse > trials/50 {
		t.Errorf("layout-level gate: %d of %d no-op trials were regressions, want at most %d", layoutFalse, trials, trials/50)
	}
	if pooledFalse < trials/2 {
		t.Errorf("single-layout gate: only %d of %d no-op trials were regressions; the fixture no longer shows the problem", pooledFalse, trials)
	}
	t.Logf("no-op trials judged REGRESSION: %d/%d by layout, %d/%d with one layout per arm", layoutFalse, trials, pooledFalse, trials)
}

func TestRealRegressionIsCaughtAcrossLayouts(t *testing.T) {
	s := quiet()
	const k, rounds = 10, 20
	for _, tc := range []struct {
		name  string
		which func(i int) bool
		rows  int
	}{
		{"one benchmark +10%", func(i int) bool { return i == 6 }, 1},
		{"every benchmark +10%", func(int) bool { return true }, len(s)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			slow := modify(s, func(i int, b *bench) {
				if tc.which(i) {
					b.ns *= 1.10
				}
			})
			in := Inputs{
				Base: mustParse(t, layoutArm(1, 100, 1, rounds, k, 0.04, s)),
				Head: mustParse(t, layoutArm(2, 200, 1, rounds, k, 0.04, slow)),
			}
			res := Evaluate(in, DefaultConfig())
			if res.Verdict != Regression || res.TimeRegressed != tc.rows {
				t.Fatalf("verdict %s with %d time regressions, want regression with %d (%v)", res.Verdict, res.TimeRegressed, tc.rows, res.Reasons)
			}
		})
	}
}

func TestUniformSlowdownTripsTheLayoutGeomean(t *testing.T) {
	// +2% everywhere hides under each benchmark's +-4% layout spread, but the
	// suite geomean of a layout averages 20 independent placement effects,
	// so the per-layout suite geomeans separate.
	s := quiet()
	slow := modify(s, func(_ int, b *bench) { b.ns *= 1.02 })
	const k, rounds = 10, 20
	in := Inputs{
		Base: mustParse(t, layoutArm(1, 100, 1, rounds, k, 0.04, s)),
		Head: mustParse(t, layoutArm(2, 200, 1, rounds, k, 0.04, slow)),
	}
	res := Evaluate(in, DefaultConfig())
	if res.Verdict != Regression || res.TimeRegressed != 0 || !(res.GeomeanP < 0.01) {
		t.Fatalf("verdict %s, %d per-benchmark regressions, geomean p %g; want a geomean-only regression", res.Verdict, res.TimeRegressed, res.GeomeanP)
	}
}

func TestLayoutSuiteGeomeansNeedEveryLayout(t *testing.T) {
	text := "layout: 1\nBenchmarkA 1 10 ns/op\nBenchmarkB 1 20 ns/op\nlayout: 2\nBenchmarkA 1 30 ns/op\nBenchmarkB 1 40 ns/op\n"
	run := mustParse(t, text)
	got, ok := layoutSuiteGeomeans(run, []string{"BenchmarkA", "BenchmarkB"})
	if !ok || len(got) != 2 || math.Abs(got[0]-math.Sqrt(200)) > 1e-9 || math.Abs(got[1]-math.Sqrt(1200)) > 1e-9 {
		t.Fatalf("layoutSuiteGeomeans = %v, %v; want [sqrt(200) sqrt(1200)]", got, ok)
	}
	partial := mustParse(t, text+"layout: 3\nBenchmarkA 1 50 ns/op\n")
	if _, ok := layoutSuiteGeomeans(partial, []string{"BenchmarkA", "BenchmarkB"}); ok {
		t.Fatal("a layout missing from one benchmark must make the suite geomeans unusable")
	}
}

func TestExtraAllocationIsCaughtWithLayouts(t *testing.T) {
	// allocs/op do not depend on code layout; they stay judged over the
	// pooled samples, and an extra allocation is a regression even when
	// the timings are inside layout noise.
	s := quiet()
	more := modify(s, func(i int, b *bench) {
		if i == 2 {
			b.allocs++
		}
	})
	in := Inputs{
		Base: mustParse(t, layoutArm(1, 100, 1, 20, 10, 0.04, s)),
		Head: mustParse(t, layoutArm(2, 200, 1, 20, 10, 0.04, more)),
	}
	res := Evaluate(in, DefaultConfig())
	if res.Verdict != Regression || res.HardRegressed != 1 || !res.Rows[2].Regress {
		t.Fatalf("verdict %s, %d hard regressions, row 2 regress %v; want the +allocs regression", res.Verdict, res.HardRegressed, res.Rows[2].Regress)
	}
	if res.Rows[2].Allocs.ByLayout {
		t.Fatal("allocs/op must be compared over pooled samples, not by layout")
	}
}

func TestAAPrimeCountsWhatTheTimeRuleWouldFlag(t *testing.T) {
	// The A/A' arm (base revision, disjoint seeds) is 10% slower on two
	// benchmarks in every layout: the time rule would flag both.
	s := quiet()
	aa := modify(s, func(i int, b *bench) {
		if i < 2 {
			b.ns *= 1.10
		}
	})
	in := Inputs{
		Base: mustParse(t, layoutArm(1, 100, 1, 20, 10, 0.02, s)),
		Head: mustParse(t, layoutArm(2, 200, 1, 20, 10, 0.02, s)),
		AA:   mustParse(t, layoutArm(3, 300, 11, 20, 10, 0.02, aa)),
	}
	res := Evaluate(in, DefaultConfig())
	if res.AAFlagged != 2 || res.AANoisy != 2 {
		t.Fatalf("A/A': %d flagged, %d noisy; want 2 and 2", res.AAFlagged, res.AANoisy)
	}
	if math.IsNaN(res.AAGeomeanP) {
		t.Fatal("A/A' suite geomean p-value missing")
	}
	md := Markdown(res, DefaultConfig(), Meta{})
	if !strings.Contains(md, "A/A' control (base revision, disjoint layout seeds): 2 of 20 benchmarks moved more than 3%; 2 would have been flagged") {
		t.Fatalf("report lacks the A/A' summary:\n%s", md)
	}
}

func TestMinMWP(t *testing.T) {
	for _, tc := range []struct {
		n1, n2 int
		want   float64
	}{
		{3, 3, 0.1},              // 2 / C(6,3)
		{4, 4, 2.0 / 70},         // above 0.01: four layouts can never be significant
		{5, 5, 2.0 / 252},        // just below 0.01
		{10, 10, 2.0 / 184756.0}, // C(20,10)
		{0, 4, 1},
	} {
		if got := minMWP(tc.n1, tc.n2); math.Abs(got-tc.want) > 1e-12 {
			t.Errorf("minMWP(%d, %d) = %g, want %g", tc.n1, tc.n2, got, tc.want)
		}
	}
	// It is the p-value of complete separation.
	if p := mannWhitney([]float64{1, 2, 3, 4, 5}, []float64{6, 7, 8, 9, 10}); math.Abs(p-minMWP(5, 5)) > 1e-12 {
		t.Errorf("complete separation p = %g, minMWP = %g", p, minMWP(5, 5))
	}
}

func TestMeanAndRelSD(t *testing.T) {
	if m := mean([]float64{1, 2, 3, 6}); m != 3 {
		t.Errorf("mean = %g, want 3", m)
	}
	if !math.IsNaN(mean(nil)) || !math.IsNaN(relSD([]float64{5})) || !math.IsNaN(relSD([]float64{0, 0})) {
		t.Error("mean(nil), relSD of one value and relSD of a zero mean must be NaN")
	}
	// sd of {98, 100, 102} is 2, mean 100.
	if r := relSD([]float64{98, 100, 102}); math.Abs(r-2) > 1e-9 {
		t.Errorf("relSD = %g, want 2", r)
	}
	if g := groupMedians([][]float64{{3, 1, 2}, nil, {5}}); fmt.Sprint(g) != "[2 5]" {
		t.Errorf("groupMedians = %v, want [2 5] (empty groups skipped)", g)
	}
}

func TestReportShowsRunnerCPUAndLayouts(t *testing.T) {
	s := quiet()
	dir := t.TempDir()
	files := map[string]string{
		"base.txt": layoutArm(1, 100, 1, 20, 10, 0.03, s),
		"head.txt": layoutArm(2, 200, 1, 20, 10, 0.03, s),
		"aa.txt":   layoutArm(3, 300, 11, 20, 10, 0.03, s),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	code, err := realMain([]string{
		"-base", filepath.Join(dir, "base.txt"), "-head", filepath.Join(dir, "head.txt"), "-aa", filepath.Join(dir, "aa.txt"),
		"-cpu-model", "AMD EPYC 7763 64-Core Processor",
	}, &out)
	if err != nil || code != 0 {
		t.Fatalf("realMain: code %d, err %v", code, err)
	}
	md := out.String()
	for _, want := range []string{
		"Runner CPU: **AMD EPYC 7763 64-Core Processor**.",
		"each arm runs 10 randomized code layouts",
		"| benchmark | time | p | A/A' | layout sd |",
		"A/A' control (base revision, disjoint layout seeds)",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if strings.Contains(md, "Warning:") {
		t.Error("ten layouts per arm can reach p < 0.01; the report must not warn")
	}
}

func TestReportWarnsWhenLayoutsCannotReachAlpha(t *testing.T) {
	s := quiet()
	in := Inputs{
		Base: mustParse(t, layoutArm(1, 100, 1, 8, 4, 0.03, s)),
		Head: mustParse(t, layoutArm(2, 200, 1, 8, 4, 0.03, modify(s, func(_ int, b *bench) { b.ns *= 1.5 }))),
	}
	res := Evaluate(in, DefaultConfig())
	if res.TimeRegressed != 0 {
		t.Fatalf("%d time regressions from 4 layouts per arm; p cannot go below %g", res.TimeRegressed, minMWP(4, 4))
	}
	if md := Markdown(res, DefaultConfig(), Meta{}); !strings.Contains(md, "**Warning:** with 4 layouts per arm") {
		t.Fatal("report does not warn that 4 layouts per arm cannot reach alpha")
	}
}
