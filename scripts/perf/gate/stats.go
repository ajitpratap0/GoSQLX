// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"math"
	"sort"
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
// f(i, j)[u] = f(i-1, j)[u-j] + f(i, j-1)[u], keeping one row of i at a time.
func uDistribution(n1, n2 int) []float64 {
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
