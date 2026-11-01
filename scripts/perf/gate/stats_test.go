// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"math"
	"strings"
	"testing"
)

func TestMedian(t *testing.T) {
	for _, tc := range []struct {
		in   []float64
		want float64
	}{
		{[]float64{3, 1, 2}, 2},
		{[]float64{4, 1, 3, 2}, 2.5},
		{[]float64{7}, 7},
	} {
		in := append([]float64(nil), tc.in...)
		if got := median(in); got != tc.want {
			t.Errorf("median(%v) = %g, want %g", tc.in, got, tc.want)
		}
		for i := range in {
			if in[i] != tc.in[i] {
				t.Fatalf("median modified its input: %v", in)
			}
		}
	}
	if !math.IsNaN(median(nil)) {
		t.Error("median(nil) is not NaN")
	}
}

func binom(n, k int) float64 {
	r := 1.0
	for i := 1; i <= k; i++ {
		r = r * float64(n-k+i) / float64(i)
	}
	return r
}

func TestUDistributionCountsEveryOrdering(t *testing.T) {
	for _, n := range [][2]int{{1, 1}, {3, 3}, {4, 7}, {10, 10}} {
		d := uDistribution(n[0], n[1])
		if len(d) != n[0]*n[1]+1 {
			t.Fatalf("%v: %d values, want %d", n, len(d), n[0]*n[1]+1)
		}
		var sum float64
		for i, c := range d {
			sum += c
			if c != d[len(d)-1-i] {
				t.Fatalf("%v: distribution is not symmetric at U=%d", n, i)
			}
		}
		if want := binom(n[0]+n[1], n[0]); sum != want {
			t.Fatalf("%v: total %g, want C(%d,%d) = %g", n, sum, n[0]+n[1], n[0], want)
		}
	}
}

func TestMannWhitneyExact(t *testing.T) {
	// Fully separated samples: the only ordering with U = 0 (or U = n1*n2),
	// so p = 2 / C(n1+n2, n1).
	lo := []float64{1, 2, 3}
	hi := []float64{4, 5, 6}
	if got, want := mannWhitney(lo, hi), 2/binom(6, 3); math.Abs(got-want) > 1e-12 {
		t.Errorf("3 vs 3 separated: p = %g, want %g", got, want)
	}
	if got, want := mannWhitney(hi, lo), 2/binom(6, 3); math.Abs(got-want) > 1e-12 {
		t.Errorf("separation is two-sided: p = %g, want %g", got, want)
	}
	var a, b []float64
	for i := 0; i < 10; i++ {
		a = append(a, float64(i))
		b = append(b, float64(100+i))
	}
	if got, want := mannWhitney(a, b), 2/binom(20, 10); math.Abs(got-want) > 1e-15 {
		t.Errorf("10 vs 10 separated: p = %g, want %g", got, want)
	}
	// Perfectly interleaved samples are as similar as they can be.
	if got := mannWhitney([]float64{1, 3, 5, 7}, []float64{2, 4, 6, 8}); got < 0.6 {
		t.Errorf("interleaved: p = %g, want a large p", got)
	}
}

func TestMannWhitneyWithTies(t *testing.T) {
	// Deterministic metrics: ten 17s against ten 18s is a clear difference.
	var a, b, c []float64
	for i := 0; i < 10; i++ {
		a = append(a, 17)
		b = append(b, 18)
		c = append(c, 17)
	}
	if p := mannWhitney(a, b); p > 1e-3 {
		t.Errorf("17s vs 18s: p = %g, want < 0.001", p)
	}
	if p := mannWhitney(a, c); p != 1 {
		t.Errorf("identical constants: p = %g, want 1", p)
	}
}

func TestMannWhitneyEmpty(t *testing.T) {
	if p := mannWhitney(nil, []float64{1}); p != 1 {
		t.Errorf("p = %g, want 1", p)
	}
}

func TestParseBench(t *testing.T) {
	in := strings.Join([]string{
		"goos: linux",
		"pkg: github.com/ajitpratap0/GoSQLX/pkg/gosqlx",
		"cpu: AMD EPYC 7763 64-Core Processor",
		"BenchmarkParseE2E/join      \t  300000\t      3912 ns/op\t  70.3 MB/s\t    2363 B/op\t      17 allocs/op",
		"BenchmarkParseE2E/join-4    \t  300000\t      3800 ns/op\t  72.0 MB/s\t    2363 B/op\t      17 allocs/op",
		"BenchmarkParseRW/postgresql/medium \t 1000\t 900000 ns/op\t 14000 ns/stmt\t 100000 B/op\t 900 allocs/op",
		"Benchmark results follow", // log line, not a result
		"PASS",
		"ok  \tgithub.com/ajitpratap0/GoSQLX/pkg/gosqlx\t12.3s",
	}, "\n")
	r := mustParse(t, in)
	if got := strings.Join(r.Names, ","); got != "BenchmarkParseE2E/join,BenchmarkParseRW/postgresql/medium" {
		t.Fatalf("names = %s", got)
	}
	if got := r.Get("BenchmarkParseE2E/join", "ns/op"); len(got) != 2 || got[0] != 3912 || got[1] != 3800 {
		t.Fatalf("join ns/op = %v (the -4 suffix must fold into the same name)", got)
	}
	if got := r.Get("BenchmarkParseRW/postgresql/medium", "ns/stmt"); len(got) != 1 || got[0] != 14000 {
		t.Fatalf("custom metric = %v", got)
	}
	if r.Get("BenchmarkAbsent", "ns/op") != nil {
		t.Fatal("absent benchmark returned samples")
	}

	if _, err := parseBench(strings.NewReader("BenchmarkX 10 12 ns/op 5\n")); err == nil {
		t.Error("dangling value accepted")
	}
	if _, err := parseBench(strings.NewReader("BenchmarkX 10 abc ns/op\n")); err == nil {
		t.Error("non-numeric value accepted")
	}
}
