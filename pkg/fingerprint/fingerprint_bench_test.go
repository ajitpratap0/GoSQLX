// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fingerprint_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/fingerprint"
)

// portableQueries returns the 11 portable benchmark queries shared with
// benchmarks/compare, so a Normalize or Fingerprint number here is directly
// comparable with the competitor harness.
func portableQueries(tb testing.TB) []benchcorpus.Query {
	tb.Helper()
	set, err := benchcorpus.Default()
	if err != nil {
		tb.Fatalf("load benchmark corpus: %v", err)
	}
	qs := set.Portable()
	if len(qs) == 0 {
		tb.Fatal("benchmark corpus has no portable queries")
	}
	return qs
}

// BenchmarkFingerprint measures fingerprint.Fingerprint (parse, normalize,
// hash) over the portable queries.
func BenchmarkFingerprint(b *testing.B) {
	for _, q := range portableQueries(b) {
		b.Run(q.ID, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := fingerprint.Fingerprint(q.SQL); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkNormalize measures fingerprint.Normalize over the portable queries.
func BenchmarkNormalize(b *testing.B) {
	for _, q := range portableQueries(b) {
		b.Run(q.ID, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := fingerprint.Normalize(q.SQL); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkNormalizeScale measures Normalize on a literal list that grows
// 10x per step, to expose non-linear cost in the literal-replacement path.
func BenchmarkNormalizeScale(b *testing.B) {
	for _, shape := range []string{benchcorpus.ScaleIn, benchcorpus.ScaleValues} {
		b.Run(shape, func(b *testing.B) {
			for _, n := range benchcorpus.ScaleSizes {
				sql := benchcorpus.ScaleSQL(shape, n)
				b.Run(fmt.Sprint(n), func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(int64(len(sql)))
					for i := 0; i < b.N; i++ {
						if _, err := fingerprint.Normalize(sql); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

// TestBenchInputsNormalize guards the benchmark inputs: every portable query
// and scale shape must normalize without error, strip its literals, and give
// literal-independent fingerprints, otherwise the benchmarks would time an
// error path or a degenerate input.
func TestBenchInputsNormalize(t *testing.T) {
	for _, q := range portableQueries(t) {
		norm, err := fingerprint.Normalize(q.SQL)
		if err != nil || norm == "" {
			t.Errorf("%s: Normalize = %q, %v", q.ID, norm, err)
		}
		fp, err := fingerprint.Fingerprint(q.SQL)
		if err != nil || len(fp) == 0 {
			t.Errorf("%s: Fingerprint = %q, %v", q.ID, fp, err)
		}
	}

	for _, shape := range []string{benchcorpus.ScaleIn, benchcorpus.ScaleValues} {
		for _, n := range benchcorpus.ScaleSizes {
			norm, err := fingerprint.Normalize(benchcorpus.ScaleSQL(shape, n))
			if err != nil {
				t.Fatalf("%s/%d: %v", shape, n, err)
			}
			if strings.Contains(norm, "name_") {
				t.Errorf("%s/%d: literal survived normalization: %.80s", shape, n, norm)
			}
			if got := strings.Count(norm, "?"); got < n {
				t.Errorf("%s/%d: %d placeholders, want at least %d", shape, n, got, n)
			}
		}
	}
}

// TestFingerprintIgnoresLiteralValues pins the property the benchmarks
// assume: queries differing only in literal values share one fingerprint.
func TestFingerprintIgnoresLiteralValues(t *testing.T) {
	a, err := fingerprint.Fingerprint("SELECT id FROM t WHERE id IN (1, 2, 3) AND name = 'x'")
	if err != nil {
		t.Fatal(err)
	}
	b, err := fingerprint.Fingerprint("SELECT id FROM t WHERE id IN (7, 8, 9) AND name = 'y'")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("fingerprints differ for literal-only change: %s vs %s", a, b)
	}
	c, err := fingerprint.Fingerprint("SELECT id FROM u WHERE id IN (1, 2, 3) AND name = 'x'")
	if err != nil {
		t.Fatal(err)
	}
	if a == c {
		t.Error("fingerprint did not change when the table changed")
	}
}
