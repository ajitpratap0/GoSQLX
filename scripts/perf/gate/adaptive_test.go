// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseSuiteLineLabels(t *testing.T) {
	r := mustParse(t, "layout: 7\nsuite-line: 1\nBenchmarkA 1 10 ns/op\nBenchmarkB 1 12 ns/op\nsuite-line: 2\nBenchmarkC 1 14 ns/op\n")
	if r.Line["BenchmarkB"] != 1 || r.LineFirst[1] != "BenchmarkA" || r.LineFirst[2] != "BenchmarkC" {
		t.Fatalf("line metadata = %v %v", r.Line, r.LineFirst)
	}
	if _, err := parseBench(strings.NewReader("suite-line: nope\n")); err == nil {
		t.Fatal("invalid suite-line accepted")
	}
}

func TestMergeRuns(t *testing.T) {
	a := mustParse(t, "layout: 1\nsuite-line: 1\nBenchmarkA 1 10 ns/op\n")
	b := mustParse(t, "layout: 2\nsuite-line: 9\nBenchmarkA 1 20 ns/op\nsuite-line: 2\nBenchmarkB 1 30 ns/op\n")
	if mergeRuns(a, nil) != a {
		t.Fatal("nil extension must return original")
	}
	c := mergeRuns(a, b)
	if c == a || fmt.Sprint(c.Names) != "[BenchmarkA BenchmarkB]" || fmt.Sprint(c.Get("BenchmarkA", unitTime)) != "[10 20]" || c.Line["BenchmarkA"] != 1 || c.LineFirst[1] != "BenchmarkA" {
		t.Fatalf("merge = %+v", c)
	}
	labs, _ := c.ByLayout("BenchmarkA", unitTime)
	if fmt.Sprint(labs) != "[1 2]" || len(a.Get("BenchmarkA", unitTime)) != 1 {
		t.Fatal("merge lost labels or mutated original")
	}
}

func distArm(sampleSeed, layoutSeed uint64, firstSeed, k int, draw func(*lcg) float64, benches []bench, line int) string {
	lr, sr := lcg(layoutSeed), lcg(sampleSeed)
	var out strings.Builder
	for j := 0; j < k; j++ {
		fmt.Fprintf(&out, "layout: %d\nsuite-line: %d\n", firstSeed+j, line)
		for _, bn := range benches {
			factor := draw(&lr)
			fmt.Fprintf(&out, "%s 1 %.9f ns/op %g B/op %g allocs/op\n", bn.name, bn.ns*factor*(1+bn.noise*(2*sr.next()-1)), bn.bytes, bn.allocs)
		}
	}
	return out.String()
}
func normalDraw(r *lcg) float64 {
	return math.Sqrt(-2*math.Log(math.Max(r.next(), 1e-15))) * math.Cos(2*math.Pi*r.next())
}
func tailDraw(r *lcg) float64 {
	if r.next() < 0.75 {
		return 1 + 0.007*normalDraw(r)
	}
	return 1.04 + 0.21*r.next()
}

// lowPowerTailDraw increases the disturbed-layout share from 25% to one third.
// This models a low-power benchmark at alpha/10 without changing the +5%
// slowdown or choosing a favourable sample seed.
func lowPowerTailDraw(r *lcg) float64 {
	if r.next() < 2.0/3 {
		return 1 + 0.007*normalDraw(r)
	}
	return 1.04 + 0.21*r.next()
}
func powerShapes() []struct {
	name string
	draw func(*lcg) float64
} {
	out := []struct {
		name string
		draw func(*lcg) float64
	}{}
	for _, sp := range []float64{.04, .06, .10} {
		spread := sp
		out = append(out, struct {
			name string
			draw func(*lcg) float64
		}{fmt.Sprintf("uniform%.0f", 100*sp), func(r *lcg) float64 { return 1 + spread*(2*r.next()-1) }})
	}
	return append(out, struct {
		name string
		draw func(*lcg) float64
	}{"tail", tailDraw}, struct {
		name string
		draw func(*lcg) float64
	}{"clusters", func(r *lcg) float64 {
		v := 1.
		if r.next() < .5 {
			v += .08
		}
		return v + .004*normalDraw(r)
	}})
}
func shapeResiduals(draw func(*lcg) float64) []float64 {
	r := lcg(173)
	out := make([]float64, 2000)
	for i := range out {
		out[i] = math.Log(draw(&r))
	}
	return out
}

func TestAUCPowerMatchesMonteCarlo(t *testing.T) {
	const level = .01 / 50
	for _, shape := range powerShapes() {
		for _, k := range []int{20, 60} {
			t.Run(fmt.Sprintf("%s/K%d", shape.name, k), func(t *testing.T) {
				residuals := shapeResiduals(shape.draw)
				p := aucPower(residuals, k, k, level, 5)
				r := lcg(871)
				hits := 0
				for trial := 0; trial < 300; trial++ {
					x, y := make([]float64, k), make([]float64, k)
					for i := range x {
						x[i] = shape.draw(&r)
						y[i] = 1.05 * shape.draw(&r)
					}
					if mannWhitney(x, y) <= level {
						hits++
					}
				}
				mc := float64(hits) / 300
				if p > mc+.06 || p < mc-.25 {
					t.Errorf("estimate %.3f, MC %.3f", p, mc)
				}
				if k == 20 && shape.name == "uniform6" && (p < .30 || p > .55) {
					t.Errorf("old uniform6 band: %.3f", p)
				}
				if k == 20 && shape.name == "uniform10" && (p < .02 || p > .10) {
					t.Errorf("old uniform10 band: %.3f", p)
				}
				t.Logf("power %.3f MC %.3f", p, mc)
			})
		}
	}
	// Ordered self-pairs must be excluded and ties count half.
	if p := aucShift([]float64{0, 0, math.Log(1.05), math.Log(1.05)}, 0); math.Abs(p-.5) > 1e-12 {
		t.Errorf("tie AUC %g", p)
	}
	if p := aucShift([]float64{0, 100}, 5); p != .5 {
		t.Errorf("self-pairs were counted: AUC %g", p)
	}
}
func TestRequiredLayoutsIsMinimal(t *testing.T) {
	const level = .01 / 50
	for _, shape := range powerShapes() {
		r := shapeResiduals(shape.draw)
		k := requiredLayouts(r, level, 5, .8, 200)
		if k > 200 || aucPower(r, k, k, level, 5) < .8 || aucPower(r, k-1, k-1, level, 5) >= .8 {
			t.Errorf("%s nonminimal K=%d", shape.name, k)
		}
		if requiredLayouts(r, level, 5, .9, 200) < k {
			t.Error("target monotonicity")
		}
		if requiredLayouts(r, level, 5, .8, 2) != 3 {
			t.Error("cap sentinel")
		}
		shift := aucMinShift(r, 20, 20, level, .8)
		if math.Abs(aucPower(r, 20, 20, level, shift)-.8) > 1e-3 {
			t.Errorf("inverse at %g", shift)
		}
	}
	if requiredLayouts([]float64{0, 100, 200, 300}, level, 0, .8, 20) != 21 {
		t.Error("AUC <= half sentinel")
	}
	for _, tc := range []struct {
		r      []float64
		n1, n2 int
	}{{nil, 20, 20}, {[]float64{0, 1, 2}, 20, 20}, {[]float64{0, 1, 2, 3}, 1, 20}} {
		if !math.IsNaN(aucPower(tc.r, tc.n1, tc.n2, level, 5)) {
			t.Error("invalid power must be NaN")
		}
	}
	if !math.IsInf(aucMinShift([]float64{0, 100, 200, 300}, 20, 20, level, .8), 1) {
		t.Error("unreachable inverse must be +Inf")
	}
}
func planFixture(t *testing.T) Inputs {
	s := quiet()[:4]
	s[2].name = "BenchmarkWide/a+b/(x).#01"
	build := func(seed uint64) *Run {
		a := distArm(seed, seed, 1, 20, func(r *lcg) float64 { return 1 + .01*(2*r.next()-1) }, s[:2], 1)
		a += distArm(seed+1, seed+1, 1, 20, tailDraw, s[2:3], 1)
		a += distArm(seed+2, seed+2, 1, 20, func(r *lcg) float64 { return 1 + .01*(2*r.next()-1) }, s[3:], 2)
		return mustParse(t, a)
	}
	return Inputs{Base: build(19), Head: build(51)}
}
func TestPlanListsUnderpoweredWithLineAndWarmup(t *testing.T) {
	cfg := DefaultConfig()
	res := Evaluate(planFixture(t), cfg)
	p := Plan(res, cfg)
	if len(p) != 1 {
		t.Fatalf("needs %+v", p)
	}
	n := p[0]
	if n.Line != 1 || n.Name != "BenchmarkWide/a+b/(x).#01" || n.Regex != `^BenchmarkWide$/^a\+b$/^\(x\)\.#01$` || n.More != n.Target-20 || n.More <= 0 || n.Have != 20 {
		t.Fatalf("need %+v", n)
	}
	var out strings.Builder
	if err := WritePlan(&out, p, map[int]string{1: "BenchmarkParseE2E/q00", 2: "BenchmarkOther"}, cfg.Alpha/float64(res.TimeTests), res.TimeTests, cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "warmup\t1\t^BenchmarkParseE2E$/^q00$\n") || strings.Count(out.String(), "warmup\t") != 1 {
		t.Fatalf("warmups:\n%s", out.String())
	}
}
func TestPlanIgnoresARealShift(t *testing.T) {
	s := quiet()[:1]
	draw := powerShapes()[2].draw
	base := mustParse(t, distArm(1, 100, 1, 100, draw, s, 1))
	head := mustParse(t, distArm(2, 200, 1, 100, draw, s, 1))
	slow := modify(s, func(_ int, b *bench) { b.ns *= .8 })
	shift := mustParse(t, distArm(2, 200, 1, 100, draw, slow, 1))
	a, b := Evaluate(Inputs{Base: base, Head: head}, DefaultConfig()), Evaluate(Inputs{Base: base, Head: shift}, DefaultConfig())
	if math.Abs(float64(a.Rows[0].NeedK-b.Rows[0].NeedK)) > .15*float64(a.Rows[0].NeedK) {
		t.Fatalf("real shift changed needed K: %d -> %d", a.Rows[0].NeedK, b.Rows[0].NeedK)
	}
}

// adaptiveTrial follows the production planner with fresh layout seeds,
// collecting only requested benchmarks before re-planning.
func adaptiveTrial(t *testing.T, trial int, slow bool) (Result, Result, int) {
	t.Helper()
	cfg := DefaultConfig()
	s := modify(quiet()[:10], func(_ int, b *bench) { b.noise = 0 })
	h := modify(s, func(i int, b *bench) {
		if slow && i == 4 {
			b.ns *= 1.05
		}
	})
	build := func(seed uint64, first, k int, bs []bench) *Run {
		var text strings.Builder
		for i, b := range bs {
			draw := powerShapes()[0].draw
			if i%2 == 0 {
				draw = tailDraw
			}
			if i == 4 {
				draw = lowPowerTailDraw
			}
			text.WriteString(distArm(seed+uint64(i), seed+uint64(13*i), first, k, draw, []bench{b}, 1))
		}
		return mustParse(t, text.String())
	}
	seed := uint64(1000 + trial*10000)
	in := Inputs{Base: build(seed, 1, 20, s), Head: build(seed+1234, 1, 20, h)}
	initial := Evaluate(in, cfg)
	res := initial
	last := 20
	stages := 0
	for stage := 0; stage < 3; stage++ {
		needs := Plan(res, cfg)
		if len(needs) == 0 {
			break
		}
		stages++
		maxmore := 0
		for _, n := range needs {
			if n.More > maxmore {
				maxmore = n.More
			}
			var bs, hs []bench
			draw := powerShapes()[0].draw
			for i, b := range s {
				if b.name == n.Name {
					bs = []bench{b}
					hs = []bench{h[i]}
					if i%2 == 0 {
						draw = tailDraw
					}
					if i == 4 {
						draw = lowPowerTailDraw
					}
				}
			}
			in.BaseExt = mergeRuns(in.BaseExt, mustParse(t, distArm(seed+uint64(stage*101+41), seed+uint64(stage*151+43+n.Have), last+1, n.More, draw, bs, 1)))
			in.HeadExt = mergeRuns(in.HeadExt, mustParse(t, distArm(seed+uint64(stage*101+61), seed+uint64(stage*151+67+n.Have), last+1, n.More, draw, hs, 1)))
		}
		last += maxmore
		res = Evaluate(in, cfg)
	}
	return initial, res, stages
}
func TestAdaptiveLayoutsCatchAFivePercentSlowdown(t *testing.T) {
	fixed, adaptive := 0, 0
	under := 0
	maxStages, maxK := 0, 0
	minCaughtPower := math.Inf(1)
	for trial := 0; trial < 60; trial++ {
		a, b, stages := adaptiveTrial(t, trial, true)
		maxStages = max(maxStages, stages)
		maxK = max(maxK, b.Rows[4].K)
		if a.Rows[4].TimeSig && a.Rows[4].Regress {
			fixed++
		}
		if b.Rows[4].TimeSig && b.Rows[4].Regress {
			adaptive++
			minCaughtPower = math.Min(minCaughtPower, b.Rows[4].Power)
			if !(b.Rows[4].Power >= .8) {
				under++
				t.Logf("caught trial %d: K=%d final power=%.6f need=%d", trial, b.Rows[4].K, b.Rows[4].Power, b.Rows[4].NeedK)
			}
		}
	}
	if fixed > 30 || adaptive < 42 {
		t.Errorf("fixed catches %d/60 adaptive %d/60; want <=30 and >=42", fixed, adaptive)
	}
	if under > 0 {
		t.Errorf("%d caught trials finished below estimated 80%% power", under)
	}
	if maxStages > 3 || maxK > DefaultConfig().ExtMax {
		t.Errorf("extension exceeded cap: stages=%d K=%d", maxStages, maxK)
	}
	t.Logf("fixed %d/60 adaptive %d/60; minimum caught power %.4f, max stages %d, max K %d", fixed, adaptive, minCaughtPower, maxStages, maxK)
}
func TestAdaptiveNoOpFalseAlarmRate(t *testing.T) {
	alarms := 0
	for trial := 0; trial < 150; trial++ {
		_, res, _ := adaptiveTrial(t, 1000+trial, false)
		if res.Verdict == Regression {
			alarms++
		}
	}
	if alarms > 3 {
		t.Errorf("%d/150 no-op regressions; want <=3", alarms)
	}
	t.Logf("no-op regressions %d/150", alarms)
}
func TestExtensionLeavesStageOneRulesAlone(t *testing.T) {
	s := quiet()[:10]
	in := Inputs{Base: mustParse(t, distArm(1, 101, 1, 20, tailDraw, s, 1)), Head: mustParse(t, distArm(2, 202, 1, 20, tailDraw, s, 1)), AA: mustParse(t, distArm(3, 303, 21, 20, tailDraw, s, 1))}
	a := Evaluate(in, DefaultConfig())
	ext := modify(s[2:3], func(_ int, b *bench) { b.ns *= 1.3; b.bytes *= 2; b.allocs += 10 })
	in.BaseExt = mustParse(t, distArm(4, 404, 41, 60, tailDraw, s[2:3], 1))
	in.HeadExt = mustParse(t, distArm(5, 505, 41, 60, tailDraw, ext, 1))
	b := Evaluate(in, DefaultConfig())
	if a.GeomeanP != b.GeomeanP || a.AAGeomeanP != b.AAGeomeanP || a.AANoisy != b.AANoisy || a.AAFlagged != b.AAFlagged || a.Geomean != b.Geomean || b.GeomeanNote != "" {
		t.Fatalf("stage-one suite rules changed:\n%+v\n%+v", a, b)
	}
	for i := range a.Rows {
		if !sameCmp(a.Rows[i].AA, b.Rows[i].AA) || !sameCmp(a.Rows[i].Bytes, b.Rows[i].Bytes) || !sameCmp(a.Rows[i].Allocs, b.Rows[i].Allocs) {
			t.Errorf("stage-one row %d changed", i)
		}
	}
}
func sameCmp(a, b Cmp) bool {
	return reflect.DeepEqual(a, b) || (a.OK == b.OK && a.Base == b.Base && a.Head == b.Head && a.Ratio == b.Ratio && a.DeltaPct == b.DeltaPct && a.P == b.P && a.Separated == b.Separated && a.NBase == b.NBase && a.NHead == b.NHead && a.ByLayout == b.ByLayout && ((math.IsNaN(a.SpreadPct) && math.IsNaN(b.SpreadPct)) || a.SpreadPct == b.SpreadPct))
}
func TestNoExtensionIsEquivalent(t *testing.T) {
	for _, k := range []int{3, 10, 20} {
		s := quiet()
		in := Inputs{Base: mustParse(t, layoutArm(1, 100, 1, 20, k, .04, s)), Head: mustParse(t, layoutArm(2, 200, 1, 20, k, .04, s)), AA: mustParse(t, layoutArm(3, 300, 21, 20, k, .04, s))}
		a := Evaluate(in, DefaultConfig())
		in.BaseExt = newRun()
		in.HeadExt = newRun()
		b := Evaluate(in, DefaultConfig())
		if a.Verdict != b.Verdict || !reflect.DeepEqual(a.Reasons, b.Reasons) {
			t.Fatalf("K=%d nil/empty differ", k)
		}
		for i := range a.Rows {
			if !sameCmp(a.Rows[i].Time, b.Rows[i].Time) || a.Rows[i].TimeSig != b.Rows[i].TimeSig {
				t.Errorf("K=%d row %d changed", k, i)
			}
		}
	}
}
func TestLowPowerReasons(t *testing.T) {
	for _, tc := range []struct {
		status, reason string
		extended       bool
	}{
		{"off", "adaptive layouts off", false},
		{"budget", "not planned (time budget ran out)", false},
		{"stages", "not planned (still short after the last extension stage)", false},
		{"done", "not planned (no extension samples)", false},
		{"skipped", "not planned (timings not judged)", false},
		{"budget", "time budget ran out", true},
		{"stages", "still short after the last extension stage", true},
		{"done", "estimate rose after the last extension", true},
	} {
		t.Run(tc.status+fmt.Sprint(tc.extended), func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.ExtStatus = tc.status
			in := planFixture(t)
			if tc.extended {
				// A real extra layout, rather than altered Row metadata.
				s := quiet()[2:3]
				s[0].name = "BenchmarkWide/a+b/(x).#01"
				in.BaseExt = mustParse(t, "adaptive-planned: "+s[0].name+"\n"+distArm(91, 91, 21, 1, tailDraw, s, 1))
				in.HeadExt = mustParse(t, "adaptive-planned: "+s[0].name+"\n"+distArm(92, 92, 21, 1, tailDraw, s, 1))
			}
			res := Evaluate(in, cfg)
			lp := LowPower(res, cfg)
			if len(lp) != 1 || lp[0].Reason != tc.reason {
				t.Fatalf("low power: %+v, want %q", lp, tc.reason)
			}
			md := Markdown(res, cfg, Meta{})
			if !strings.Contains(md, "Adaptive layouts:") || !strings.Contains(md, "| reason |") || !strings.Contains(md, tc.reason) {
				t.Errorf("missing adaptive report/reason")
			}
			cfg.ExtMax = 2
			res = Evaluate(in, cfg)
			lp = LowPower(res, cfg)
			if len(lp) != 1 || lp[0].Reason != "needs more than 2 layouts per arm (cap)" {
				t.Fatalf("cap precedence: %+v", lp)
			}
		})
	}
}

// A partial first extension leaves this benchmark underpowered, so the next
// plan must subtract the measured merged count rather than the initial 20.
func TestPlanUsesMergedLayoutsAfterExtension(t *testing.T) {
	cfg := DefaultConfig()
	in := planFixture(t)
	first := Plan(Evaluate(in, cfg), cfg)
	if len(first) != 1 || first[0].Have != 20 || first[0].More < 2 {
		t.Fatalf("first plan: %+v", first)
	}
	s := quiet()[2:3]
	s[0].name = first[0].Name
	in.BaseExt = mustParse(t, distArm(91, 91, 21, 1, tailDraw, s, 1))
	in.HeadExt = mustParse(t, distArm(92, 92, 21, 1, tailDraw, s, 1))
	merged := Evaluate(in, cfg)
	second := Plan(merged, cfg)
	if len(second) != 1 {
		t.Fatalf("second plan: %+v", second)
	}
	mergedK := 0
	for _, row := range merged.Rows {
		if row.Name == first[0].Name {
			mergedK = row.K
		}
	}
	if mergedK != 21 || second[0].Have != mergedK || second[0].More != second[0].Target-mergedK {
		t.Fatalf("merged K=%d, second plan %+v", mergedK, second[0])
	}
}

func TestAdaptiveReportUsesConfigAndUnknownPower(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LowPowerShiftPct, cfg.LowPowerTarget, cfg.ExtMax = 7, .7, 123
	res := Evaluate(planFixture(t), cfg)
	var plan strings.Builder
	if err := WritePlan(&plan, Plan(res, cfg), nil, cfg.Alpha/float64(res.TimeTests), res.TimeTests, cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.String(), "shift 7 target 0.7 sizing-target 0.85 kmax 123") {
		t.Fatalf("plan header does not use config: %s", plan.String())
	}
	md := Markdown(res, cfg, Meta{})
	for _, want := range []string{"under 70% estimated power", "lone +7% slowdown", "power at +7%", "slowdown caught 70% of the time", "under a +7% shift", "85%"} {
		if !strings.Contains(md, want) {
			t.Errorf("custom report missing %q", want)
		}
	}
	if !strings.Contains(Markdown(Evaluate(planFixture(t), DefaultConfig()), DefaultConfig(), Meta{}), "90%") {
		t.Error("default report omits 90% plan sizing target")
	}
	res.Rows[0].Power = math.NaN()
	md = Markdown(res, cfg, Meta{})
	if strings.Contains(md, "NaN%") || !strings.Contains(md, "| n/a |") {
		t.Fatalf("unknown power must render n/a:\n%s", md)
	}
}

func TestAdaptiveReportSeparatesPlannedBenchmarksFromWarmups(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ExtStatus = "done"
	in := planFixture(t)
	s := quiet()[:3]
	s[2].name = "BenchmarkWide/a+b/(x).#01"
	for _, arm := range []struct {
		seed uint64
		dst  **Run
	}{{91, &in.BaseExt}, {92, &in.HeadExt}} {
		text := "adaptive-planned: " + s[2].name + "\n"
		text += distArm(arm.seed, arm.seed, 21, 1, tailDraw, []bench{s[0], s[2]}, 1)
		*arm.dst = mustParse(t, text)
	}
	md := Markdown(Evaluate(in, cfg), cfg, Meta{})
	for _, want := range []string{"Adaptive layouts: 1 benchmark(s) extended", "1 warm-up benchmark(s)"} {
		if !strings.Contains(md, want) {
			t.Errorf("report missing %q:\n%s", want, md)
		}
	}
}

func TestExactRegexRunsOnlyTheNamedBenchmarks(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles temporary benchmark module")
	}
	dir := t.TempDir()
	files := map[string]string{"go.mod": "module regexfixture\n\ngo 1.26\n", "bench_test.go": `package regexfixture
import ("testing"; "time")

// Sleep so a 1x run never measures 0 ns, which go test prints without an ns/op field.
func spin() { time.Sleep(time.Microsecond) }
func BenchmarkWarm(b *testing.B) { for i:=0;i<b.N;i++ { spin() } }
func BenchmarkNested(b *testing.B) { for _,name:=range []string{"a+b", "a.b", "(x)", "dup", "dup", "other"} { b.Run(name,func(b *testing.B){ for _,leaf:=range []string{"p", "q"} { b.Run(leaf,func(b *testing.B){ for i:=0;i<b.N;i++ { spin() } }) } }) } }
func BenchmarkOther(b *testing.B) { for i:=0;i<b.N;i++ { spin() } }
`}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0600); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"BenchmarkWarm", "BenchmarkNested/a+b/p", "BenchmarkNested/a.b/q", "BenchmarkNested/(x)/p", "BenchmarkNested/dup#01/q"}
	var needs []PlanNeed
	for _, n := range want[1:] {
		needs = append(needs, PlanNeed{Line: 1, Name: n, Regex: exactBenchRegex(n), More: 1, Have: 20, Target: 21})
	}
	var plan strings.Builder
	if err := WritePlan(&plan, needs, map[int]string{1: want[0]}, .001, 4, DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "plan.tsv")
	if err := os.WriteFile(path, []byte(plan.String()), 0600); err != nil {
		t.Fatal(err)
	}
	regex := strings.TrimSpace(bashLib(t, []string{"PLAN=" + path}, `perf_plan_regex "$PLAN" 1 0`))
	cmd := exec.Command("go", "test", "-run", "^$", "-bench", regex, "-benchtime", "1x", "-cpu", "1")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go test: %v\n%s", err, out)
	}
	run := mustParse(t, string(out))
	if !reflect.DeepEqual(run.Names, want) {
		t.Fatalf("regex %q ran %v, want %v:\n%s", regex, run.Names, want, out)
	}
}
func TestUDistributionCacheIsEquivalent(t *testing.T) {
	for n1 := 1; n1 <= 12; n1++ {
		for n2 := 1; n2 <= 12; n2++ {
			a, b := uDistribution(n1, n2), uDistributionFresh(n1, n2)
			if !reflect.DeepEqual(a, b) {
				t.Fatalf("distribution differs (%d,%d)", n1, n2)
			}
			again := uDistribution(n1, n2)
			if &a[0] != &again[0] {
				t.Fatalf("cache misses (%d,%d)", n1, n2)
			}
		}
	}
}
