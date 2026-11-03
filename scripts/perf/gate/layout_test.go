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
		for i, bn := range benches {
			sp := spread
			if bn.layoutSpread != 0 {
				sp = bn.layoutSpread
			}
			effect[j][i] = 1 + sp*(2*lr.next()-1)
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
	if c.Base != 100 || c.Head != 105 {
		t.Fatalf("Base, Head = %g, %g; want the medians of the layout medians, 100 and 105", c.Base, c.Head)
	}
	if want := hodgesLehmannRatio([]float64{100, 104, 98}, []float64{106, 103, 105}); math.Abs(c.Ratio-want) > 1e-12 || math.Abs(c.DeltaPct-(want-1)*100) > 1e-9 {
		t.Fatalf("Ratio %g, DeltaPct %g; want the Hodges-Lehmann ratio %g", c.Ratio, c.DeltaPct, want)
	}
	if math.Abs(c.P-mannWhitney([]float64{100, 104, 98}, []float64{106, 103, 105})) > 1e-12 {
		t.Fatalf("P = %g is not the Mann-Whitney p of the layout medians", c.P)
	}
	if c.P < 0.05 {
		t.Fatalf("P = %g: three layouts per arm cannot be significant", c.P)
	}
	if want := 1.4826 * 2; math.Abs(c.SpreadPct-want) > 1e-9 {
		t.Fatalf("SpreadPct = %g, want 1.4826 x MAD(100, 104, 98) / 100 = %g%%", c.SpreadPct, want)
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

func TestRobustSpreadAndHodgesLehmann(t *testing.T) {
	if !math.IsNaN(robustRelSD([]float64{5})) || !math.IsNaN(robustRelSD([]float64{0, 0, 0})) {
		t.Error("robustRelSD of one value or of a zero median must be NaN")
	}
	// median 100, |deviations| {2, 0, 2, 50}: MAD 2. The +50% outlier does not count.
	if r := robustRelSD([]float64{98, 100, 102, 150}); math.Abs(r-1.4826*2/101*100) > 1e-9 {
		t.Errorf("robustRelSD = %g, want %g", r, 1.4826*2/101*100)
	}
	// Every head value is 10% above its base counterpart: the shift is 1.1
	// exactly, and one wild head run does not move it.
	base := []float64{100, 102, 98, 101, 99}
	head := []float64{110, 112.2, 107.8, 111.1, 108.9}
	if r := hodgesLehmannRatio(base, head); math.Abs(r-1.1) > 0.005 {
		t.Errorf("hodgesLehmannRatio = %g, want about 1.1", r)
	}
	wild := append([]float64(nil), head...)
	wild[0] = 300
	if r := hodgesLehmannRatio(base, wild); math.Abs(r-1.1) > 0.02 {
		t.Errorf("hodgesLehmannRatio with one wild head value = %g, want still about 1.1", r)
	}
	if !math.IsNaN(hodgesLehmannRatio(nil, head)) || !math.IsNaN(hodgesLehmannRatio([]float64{0}, head)) {
		t.Error("hodgesLehmannRatio of an empty or non-positive sample must be NaN")
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
		"env.txt":  "cpu model:   AMD EPYC 7763 64-Core Processor (x86_64)\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	code, err := realMain([]string{
		"-base", filepath.Join(dir, "base.txt"), "-head", filepath.Join(dir, "head.txt"), "-aa", filepath.Join(dir, "aa.txt"),
		"-env", filepath.Join(dir, "env.txt"),
	}, &out)
	if err != nil || code != 0 {
		t.Fatalf("realMain: code %d, err %v", code, err)
	}
	md := out.String()
	for _, want := range []string{
		"Runner CPU: `AMD EPYC 7763 64-Core Processor (x86_64)`.",
		"each arm runs 10 randomized code layouts",
		"| benchmark | time | p | A/A' | spread |",
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

// TestFivePercentWithTwentyLayouts: a +5% slowdown of one benchmark among
// 20, with per-layout effects of +-3% (a reported spread of about 2.2%,
// typical of the EPYC 7763 runs), is flagged on its own.
func TestFivePercentWithTwentyLayouts(t *testing.T) {
	s := quiet()
	slow := modify(s, func(i int, b *bench) {
		if i == 9 {
			b.ns *= 1.05
		}
	})
	in := Inputs{
		Base: mustParse(t, layoutArm(1, 100, 1, 20, 20, 0.03, s)),
		Head: mustParse(t, layoutArm(2, 200, 1, 20, 20, 0.03, slow)),
	}
	res := Evaluate(in, DefaultConfig())
	if res.TimeRegressed != 1 || !res.Rows[9].Regress {
		t.Fatalf("%d time regressions, row 9 regress %v (delta %+.2f%%, p %g); want the +5%% row flagged",
			res.TimeRegressed, res.Rows[9].Regress, res.Rows[9].Time.DeltaPct, res.Rows[9].Time.P)
	}
	if lp := LowPower(res, DefaultConfig()); len(lp) != 0 {
		t.Fatalf("low-power list %v, want empty at a +-3%% layout spread", lp)
	}
}

func TestLowPowerListsWideBenchmarks(t *testing.T) {
	s := modify(quiet(), func(i int, b *bench) {
		if i == 3 {
			b.layoutSpread = 0.12 // reported spread about 9%
		}
	})
	in := Inputs{
		Base: mustParse(t, layoutArm(1, 100, 1, 20, 20, 0.02, s)),
		Head: mustParse(t, layoutArm(2, 200, 1, 20, 20, 0.02, s)),
	}
	res := Evaluate(in, DefaultConfig())
	lp := LowPower(res, DefaultConfig())
	if len(lp) != 1 || lp[0].Name != s[3].name {
		t.Fatalf("low-power list %+v, want only %s", lp, s[3].name)
	}
	if lp[0].Power >= 0.8 || !(lp[0].MinShift > 5) {
		t.Fatalf("low-power row %+v: want power < 80%% and an 80%% shift above 5%%", lp[0])
	}
	md := Markdown(res, DefaultConfig(), Meta{})
	for _, want := range []string{"### Low power", "1 benchmark(s) have under 80% estimated power", "`" + strings.TrimPrefix(s[3].name, "Benchmark") + "`"} {
		if !strings.Contains(md, want) {
			t.Errorf("report lacks %q", want)
		}
	}
}

func TestLayoutPowerMatchesSimulation(t *testing.T) {
	// k = 20 layouts, m = 50 benchmarks: Benjamini-Hochberg's single-
	// discovery level is 0.01/50. The simulation (reported spread, uniform
	// layout effects) caught a +5% slowdown 93%, 47% and 6% of the time.
	level := 0.01 / 50
	for _, tc := range []struct{ spread, lo, hi float64 }{
		{2.97, 0.85, 0.97},
		{4.45, 0.30, 0.55},
		{7.41, 0.02, 0.10},
	} {
		if p := layoutPower(tc.spread, 20, level, 5); p < tc.lo || p > tc.hi {
			t.Errorf("layoutPower(spread %.2f%%) = %.3f, want in [%.2f, %.2f]", tc.spread, p, tc.lo, tc.hi)
		}
	}
	// layoutMinShift inverts layoutPower.
	shift := layoutMinShift(4, 20, level, 0.8)
	if p := layoutPower(4, 20, level, shift); math.Abs(p-0.8) > 1e-6 {
		t.Errorf("layoutPower at layoutMinShift = %g, want 0.8", p)
	}
	if !math.IsNaN(layoutPower(0, 20, level, 5)) || !math.IsNaN(layoutPower(3, 1, level, 5)) {
		t.Error("layoutPower must be NaN for a zero spread or a single layout")
	}
}

func TestCompareArmsWithLayoutsOnOneSideOnly(t *testing.T) {
	// A head built without randomization (one unlabelled binary) against a
	// randomized base cannot be compared by layout: the gate falls back to
	// the sample-level test and the report says layouts were not used.
	s := quiet()
	base := mustParse(t, layoutArm(1, 100, 1, 20, 20, 0.03, s))
	head := mustParse(t, arm(2, 20, s))
	c := compareArms(base, head, s[0].name, unitTime)
	if c.ByLayout || c.NBase != 20 || c.NHead != 20 {
		t.Fatalf("one-sided layouts: %+v, want the sample-level comparison of 20 vs 20 samples", c)
	}
	res := Evaluate(Inputs{Base: base, Head: head}, DefaultConfig())
	if res.ByLayout {
		t.Fatal("ByLayout with an unrandomized head")
	}
	if md := Markdown(res, DefaultConfig(), Meta{}); !strings.Contains(md, "Code layouts were not randomized") {
		t.Fatal("report does not say the layouts were not randomized")
	}
}

func TestUnevenSamplesPerLayout(t *testing.T) {
	// 30 rounds over 20 layouts: layouts 1-10 get two samples, 11-20 one.
	// Every layout still counts once, through its median.
	s := quiet()
	base := mustParse(t, layoutArm(1, 100, 1, 30, 20, 0.03, s))
	labels, groups := base.ByLayout(s[0].name, unitTime)
	if len(labels) != 20 || len(groups[0]) != 2 || len(groups[19]) != 1 {
		t.Fatalf("%d layouts, %d and %d samples in the first and last; want 20, 2, 1", len(labels), len(groups[0]), len(groups[19]))
	}
	head := mustParse(t, layoutArm(2, 200, 1, 30, 20, 0.03, s))
	res := Evaluate(Inputs{Base: base, Head: head}, DefaultConfig())
	if !res.ByLayout || res.Layouts != 20 || res.Rows[0].Time.NBase != 20 {
		t.Fatalf("ByLayout %v, %d layouts, NBase %d; want true, 20, 20", res.ByLayout, res.Layouts, res.Rows[0].Time.NBase)
	}
	if math.IsNaN(res.GeomeanP) || res.Verdict != Pass {
		t.Fatalf("geomean p %g, verdict %s; want a p-value and pass", res.GeomeanP, res.Verdict)
	}
}

func TestBHAwareReachWarning(t *testing.T) {
	// 5 layouts per arm (the matrix default): the smallest p, 2/252, is
	// below alpha but far above alpha/m, so no single benchmark can be
	// flagged; the report must say so and show both limits.
	s := quiet()
	in := Inputs{
		Base: mustParse(t, layoutArm(1, 100, 1, 5, 5, 0.02, s)),
		Head: mustParse(t, layoutArm(2, 200, 1, 5, 5, 0.02, s)),
	}
	res := Evaluate(in, DefaultConfig())
	if res.TimeTests != len(s) || res.MinUnits != 5 {
		t.Fatalf("m %d, units %d; want %d and 5", res.TimeTests, res.MinUnits, len(s))
	}
	md := Markdown(res, DefaultConfig(), Meta{})
	for _, want := range []string{
		"**Warning:** with 5 layouts per arm the smallest attainable p-value is 0.00794",
		"below alpha = 0.01 but above alpha/m = 0.0005",
		"a single benchmark's slowdown can never be flagged on its own",
		"None of the 20 benchmarks can be flagged on its own",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	// 20 layouts reach alpha/m easily: no warning.
	in = Inputs{
		Base: mustParse(t, layoutArm(1, 100, 1, 20, 20, 0.02, s)),
		Head: mustParse(t, layoutArm(2, 200, 1, 20, 20, 0.02, s)),
	}
	if md := Markdown(Evaluate(in, DefaultConfig()), DefaultConfig(), Meta{}); strings.Contains(md, "**Warning:**") {
		t.Error("20 layouts per arm: unexpected warning")
	}
}

func TestMissingLayoutIsReportedNotSilent(t *testing.T) {
	// The head arm lost one benchmark's run in one layout: per-layout suite
	// geomeans cannot be formed, and the report says the geomean rule was
	// not judged.
	s := quiet()
	headText := layoutArm(2, 200, 1, 20, 20, 0.03, s)
	i := strings.Index(headText, "layout: 5\n")
	if i < 0 {
		t.Fatal("no layout 5 in the head arm")
	}
	j := strings.Index(headText[i:], s[0].name+" ")
	k := strings.IndexByte(headText[i+j:], '\n')
	headText = headText[:i+j] + headText[i+j+k+1:]
	in := Inputs{Base: mustParse(t, layoutArm(1, 100, 1, 20, 20, 0.03, s)), Head: mustParse(t, headText)}
	res := Evaluate(in, DefaultConfig())
	if !math.IsNaN(res.GeomeanP) || res.GeomeanNote == "" {
		t.Fatalf("geomean p %g, note %q; want NaN and a note", res.GeomeanP, res.GeomeanNote)
	}
	if md := Markdown(res, DefaultConfig(), Meta{}); !strings.Contains(md, "**Note:** the time geomean rule was not judged") {
		t.Fatal("report does not say the geomean rule was skipped")
	}
}

func TestNonPositiveTimesFallBackToTheMedianRatio(t *testing.T) {
	if !math.IsNaN(hodgesLehmannRatio([]float64{1, -2}, []float64{3, 4})) || !math.IsNaN(hodgesLehmannRatio([]float64{1, 2}, []float64{0, 4})) {
		t.Fatal("hodgesLehmannRatio must be NaN with a zero or negative value")
	}
	// compareLayouts then keeps the ratio of the medians of layout medians.
	c := compareLayouts([][]float64{{0}, {10}, {20}}, [][]float64{{20}, {30}, {40}})
	if !c.OK || c.Ratio != 3 || math.Abs(c.DeltaPct-200) > 1e-9 {
		t.Fatalf("cmp %+v, want Ratio 30/10 = 3", c)
	}
}
