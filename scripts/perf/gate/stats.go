// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"math"
	"sort"
	"sync"
)

// median returns the median of xs, or NaN for an empty slice. xs is not
// modified.
func median(xs []float64) float64 {
	if len(xs) == 0 {
		return math.NaN()
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	m := len(s) / 2
	if len(s)%2 == 1 {
		return s[m]
	}
	return (s[m-1] + s[m]) / 2
}

// groupMedians returns the median of every non-empty group.
func groupMedians(groups [][]float64) []float64 {
	out := make([]float64, 0, len(groups))
	for _, g := range groups {
		if len(g) > 0 {
			out = append(out, median(g))
		}
	}
	return out
}

// robustRelSD returns a robust standard deviation of xs relative to their
// median, in percent: 1.4826 x the median absolute deviation, which equals
// the standard deviation for normal data and ignores a few wild values. NaN
// for fewer than two values or a zero median.
func robustRelSD(xs []float64) float64 {
	m := median(xs)
	if len(xs) < 2 || m == 0 || math.IsNaN(m) {
		return math.NaN()
	}
	dev := make([]float64, len(xs))
	for i, x := range xs {
		dev[i] = math.Abs(x - m)
	}
	return 1.4826 * median(dev) / math.Abs(m) * 100
}

// hodgesLehmannRatio is the Hodges-Lehmann estimate of how much larger y is
// than x, as a ratio: exp of the median of log(y_j) - log(x_i) over all
// pairs. It is the estimator that goes with the Mann-Whitney U test. NaN
// when a value is not positive or a sample is empty.
func hodgesLehmannRatio(x, y []float64) float64 {
	if len(x) == 0 || len(y) == 0 {
		return math.NaN()
	}
	d := make([]float64, 0, len(x)*len(y))
	for _, a := range x {
		for _, b := range y {
			if !(a > 0) || !(b > 0) {
				return math.NaN()
			}
			d = append(d, math.Log(b)-math.Log(a))
		}
	}
	return math.Exp(median(d))
}

// minMWP is the smallest two-sided p-value an exact Mann-Whitney U test can
// produce for samples of n1 and n2 distinct values: complete separation,
// 2 / C(n1+n2, n1). With few layouts it can exceed alpha, so no difference
// could ever be significant.
func minMWP(n1, n2 int) float64 {
	if n1 < 1 || n2 < 1 {
		return 1
	}
	c := 1.0
	for i := 1; i <= n1; i++ {
		c = c * float64(n2+i) / float64(i)
	}
	return math.Min(1, 2/c)
}

// benjaminiHochberg returns which of the p-values are rejected when the false
// discovery rate is controlled at q (Benjamini and Hochberg, 1995): sort the
// m p-values, find the largest rank i with p_(i) <= i*q/m, and reject the i
// smallest. When no hypothesis is false (a change that adds no work) the
// false discovery rate equals the family-wise error rate, so the chance that
// any benchmark is flagged stays at q instead of growing with the suite. The
// procedure is valid for independent and positively dependent tests; the
// benchmarks of one binary share code, which makes their layout effects
// positively dependent if anything. NaN p-values are never rejected.
func benjaminiHochberg(ps []float64, q float64) []bool {
	type entry struct {
		p float64
		i int
	}
	es := make([]entry, 0, len(ps))
	for i, p := range ps {
		if !math.IsNaN(p) {
			es = append(es, entry{p, i})
		}
	}
	sort.SliceStable(es, func(a, b int) bool { return es[a].p < es[b].p })
	m := float64(len(es))
	k := -1
	for r, e := range es {
		if e.p <= float64(r+1)*q/m {
			k = r
		}
	}
	out := make([]bool, len(ps))
	for r := 0; r <= k; r++ {
		out[es[r].i] = true
	}
	return out
}

// powerResiduals pools log per-layout medians after centring each arm by
// its own median, removing real head shifts from the sizing distribution.
// E1's runner evidence has long tails and layout clusters that MAD misses.
func powerResiduals(name string, arms ...*Run) []float64 {
	var residuals []float64
	for _, arm := range arms {
		labels, groups := arm.ByLayout(name, "ns/op")
		if len(labels) < 2 || labels[0] == "" {
			continue
		}
		values := groupMedians(groups)
		center := median(values)
		if !(center > 0) {
			continue
		}
		for _, value := range values {
			if !(value > 0) {
				return nil
			}
			residuals = append(residuals, math.Log(value/center))
		}
	}
	return residuals
}

// aucShift measures P(r_j + log(1+shift) > r_i), counting ties by halves
// and excluding self-pairs, using sorting and binary search. E1 shows this
// empirical effect size captures runner tails and clusters missed by MAD.
func aucShift(resid []float64, shiftPct float64) float64 {
	if len(resid) < 2 || !(shiftPct > -100) {
		return math.NaN()
	}
	values := append([]float64(nil), resid...)
	sort.Float64s(values)
	shift := math.Log1p(shiftPct / 100)
	var wins float64
	for _, value := range values {
		shifted := value + shift
		lower := sort.Search(len(values), func(i int) bool { return values[i] >= shifted })
		upper := sort.Search(len(values), func(i int) bool { return values[i] > shifted })
		wins += float64(lower) + float64(upper-lower)/2
		if shifted > value {
			wins--
		} else if shifted == value {
			wins -= 0.5
		}
	}
	return wins / (float64(len(values)) * float64(len(values)-1))
}

// aucPower uses Noether's normal approximation with an empirical AUC
// effect size from pooled within-arm residuals. In E1 it overestimates
// Monte-Carlo power by at most 0.06, unlike the optimistic MAD model.
func aucPower(resid []float64, n1, n2 int, level, shiftPct float64) float64 {
	if len(resid) < 4 || n1 < 2 || n2 < 2 || !(level > 0 && level < 1) {
		return math.NaN()
	}
	return aucPowerAt(aucShift(resid, shiftPct), n1, n2, level)
}

func aucPowerAt(auc float64, n1, n2 int, level float64) float64 {
	return normalCDF((auc-0.5)*math.Sqrt(12*float64(n1)*float64(n2)/float64(n1+n2+1)) - normalQuantile(1-level/2))
}

// requiredLayouts finds the smallest balanced K reaching target under the
// empirical-AUC Noether model, or kmax+1 if none does. E1 supports this
// conservative sizing for the runner's long tails and discrete clusters.
func requiredLayouts(resid []float64, level, shiftPct, target float64, kmax int) int {
	if len(resid) < 4 || !(level > 0 && level < 1) {
		return kmax + 1
	}
	auc := aucShift(resid, shiftPct)
	if !(auc > 0.5) {
		return kmax + 1
	}
	for k := 2; k <= kmax; k++ {
		if aucPowerAt(auc, k, k, level) >= target {
			return k
		}
	}
	return kmax + 1
}

// aucMinShift bisects the empirical-AUC Noether power curve to 0.01
// percentage points, returning +Inf when even +100% is insufficient.
// E1 supports this conservative model over the former MAD normal model.
func aucMinShift(resid []float64, n1, n2 int, level, target float64) float64 {
	if len(resid) < 4 || n1 < 2 || n2 < 2 || !(level > 0 && level < 1) {
		return math.NaN()
	}
	if !(aucPower(resid, n1, n2, level, 100) >= target) {
		return math.Inf(1)
	}
	lo, hi := 0.0, 100.0
	for hi-lo > 0.00001 {
		mid := (lo + hi) / 2
		if aucPower(resid, n1, n2, level, mid) >= target {
			hi = mid
		} else {
			lo = mid
		}
	}
	return hi
}

func normalCDF(x float64) float64 { return 0.5 * math.Erfc(-x/math.Sqrt2) }

// normalQuantile is the inverse of normalCDF for 0 < p < 1.
func normalQuantile(p float64) float64 { return math.Sqrt2 * math.Erfinv(2*p-1) }

func minMax(xs []float64) (lo, hi float64) {
	lo, hi = math.Inf(1), math.Inf(-1)
	for _, x := range xs {
		lo = math.Min(lo, x)
		hi = math.Max(hi, x)
	}
	return lo, hi
}

// exactLimit bounds the sample sizes for which mannWhitney enumerates the
// exact null distribution; larger samples use the normal approximation.
const exactLimit = 50

// mannWhitney returns the two-sided p-value of the Mann-Whitney U test that x
// and y come from the same distribution, the test benchstat uses. Without
// ties, and for samples of at most exactLimit, the p-value is exact;
// otherwise it uses the normal approximation with tie and continuity
// correction. Identical constant samples (zero variance) give p = 1.
func mannWhitney(x, y []float64) float64 {
	n1, n2 := len(x), len(y)
	if n1 == 0 || n2 == 0 {
		return 1
	}
	// Rank the pooled sample, giving tied values their average rank.
	type obs struct {
		v     float64
		fromX bool
	}
	all := make([]obs, 0, n1+n2)
	for _, v := range x {
		all = append(all, obs{v, true})
	}
	for _, v := range y {
		all = append(all, obs{v, false})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v < all[j].v })
	var rankX, tieTerm float64
	ties := false
	for i := 0; i < len(all); {
		j := i
		for j < len(all) && all[j].v == all[i].v {
			j++
		}
		t := float64(j - i)
		if t > 1 {
			ties = true
			tieTerm += t*t*t - t
		}
		avg := float64(i+j+1) / 2 // ranks i+1..j
		for k := i; k < j; k++ {
			if all[k].fromX {
				rankX += avg
			}
		}
		i = j
	}
	u := rankX - float64(n1*(n1+1))/2

	if !ties && n1 <= exactLimit && n2 <= exactLimit {
		return exactP(n1, n2, int(math.Round(u)))
	}
	n := float64(n1 + n2)
	mean := float64(n1*n2) / 2
	variance := float64(n1*n2) / 12 * ((n + 1) - tieTerm/(n*(n-1)))
	if variance <= 0 {
		return 1
	}
	z := (math.Abs(u-mean) - 0.5) / math.Sqrt(variance)
	if z < 0 {
		return 1
	}
	return math.Min(1, math.Erfc(z/math.Sqrt2))
}

// exactP is the exact two-sided p-value of U = u for samples of n1 and n2
// distinct values: 2 * min(P(U <= u), P(U >= u)), capped at 1.
func exactP(n1, n2, u int) float64 {
	dist := uDistribution(n1, n2)
	var total, le, ge float64
	for k, c := range dist {
		total += c
		if k <= u {
			le += c
		}
		if k >= u {
			ge += c
		}
	}
	return math.Min(1, 2*math.Min(le, ge)/total)
}

// uDistribution returns, for each U in 0..n1*n2, the number of orderings of
// n1 x-values and n2 y-values that produce it. It uses the recurrence
// f(i, j)[u] = f(i-1, j)[u-j] + f(i, j-1)[u], keeping one row of i at a time;
// cached slices are shared and must never be mutated by callers.
func uDistribution(n1, n2 int) []float64 {
	key := [2]int{n1, n2}
	if cached, ok := uDistributionCache.Load(key); ok {
		if dist, ok := cached.([]float64); ok {
			return dist
		}
	}
	dist := uDistributionFresh(n1, n2)
	cached, _ := uDistributionCache.LoadOrStore(key, dist)
	if stored, ok := cached.([]float64); ok {
		return stored
	}
	return dist
}

var uDistributionCache sync.Map

// uDistributionFresh computes the recurrence without consulting the cache.
func uDistributionFresh(n1, n2 int) []float64 {
	prev := make([][]float64, n2+1) // f(i-1, j) for j = 0..n2
	for j := range prev {
		prev[j] = []float64{1} // f(0, j): only U = 0
	}
	for i := 1; i <= n1; i++ {
		cur := make([][]float64, n2+1)
		cur[0] = []float64{1} // f(i, 0): only U = 0
		for j := 1; j <= n2; j++ {
			row := make([]float64, i*j+1)
			for k, c := range cur[j-1] { // last value is a y: U unchanged
				row[k] += c
			}
			for k, c := range prev[j] { // last value is an x: it beats all j y's
				row[k+j] += c
			}
			cur[j] = row
		}
		prev = cur
	}
	return prev[n2]
}

// geomean returns the geometric mean of positive ratios, or NaN if there are
// none.
func geomean(ratios []float64) float64 {
	if len(ratios) == 0 {
		return math.NaN()
	}
	var s float64
	for _, r := range ratios {
		s += math.Log(r)
	}
	return math.Exp(s / float64(len(ratios)))
}
