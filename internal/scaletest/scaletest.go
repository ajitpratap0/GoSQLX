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

// Package scaletest holds helpers for tests that guard against super-linear
// (typically quadratic) running time without asserting an absolute wall-clock
// budget, plus a context whose cancellation point is a call count rather than
// a time. It is imported only from _test.go files.
package scaletest

import (
	"context"
	"runtime"
	"runtime/debug"
	"sort"
	"sync/atomic"
	"testing"
	"time"
)

const (
	// samples is the number of interleaved small/large runs per attempt; the
	// fastest run of each size is kept, which discards scheduler stalls.
	samples = 7
	// attempts is how many times a ratio may be re-measured. A genuine
	// super-linear regression exceeds the bound in every attempt; a load
	// spike has to hit all of them to cause a false failure.
	attempts = 5
	// minSample is the least wall time one timed sample should span. Faster
	// functions are repeated within the sample and the time divided by the
	// repeat count, so a coarse clock (Windows) cannot read a run as zero.
	minSample = 10 * time.Millisecond
	// maxReps caps the repeat count of very fast functions.
	maxReps = 1 << 14
)

// AssertLinearGrowth fails when run(large) is more than maxRatio times slower
// than run(small), where large is factor times the size of small. Choose
// maxRatio between the linear expectation (factor) and the quadratic one
// (factor squared), for example factor 4 and maxRatio 10.
//
// The measurement is robust against a loaded machine and the race detector:
// runs of the two sizes are interleaved so both see the same load, the
// fastest of several runs of each is kept, short functions are repeated until
// a sample spans minSample, and the whole comparison may be repeated, passing
// if any attempt is within bound. A runtime.GC precedes every sample but the
// collector stays enabled, so allocation-driven super-linear cost is
// measured. Time cannot separate every regression from noise, though: a
// quadratic that mostly copies memory is best guarded by AssertLinearBytes
// as well, which is deterministic. If the small case is still below the clock
// resolution the result is inconclusive and the test is skipped.
func AssertLinearGrowth(t testing.TB, name string, maxRatio float64, small, large func()) {
	t.Helper()
	smallReps, largeReps := calibrate(small), calibrate(large) // also warms caches and pools
	var last float64
	for attempt := 0; attempt < attempts; attempt++ {
		bestSmall, bestLarge := time.Duration(1<<63-1), time.Duration(1<<63-1)
		for i := 0; i < samples; i++ {
			if d := timeReps(small, smallReps); d < bestSmall {
				bestSmall = d
			}
			if d := timeReps(large, largeReps); d < bestLarge {
				bestLarge = d
			}
		}
		if bestSmall <= 0 {
			t.Skipf("%s: small case below clock resolution, ratio inconclusive", name)
			return
		}
		last = float64(bestLarge) / float64(bestSmall)
		t.Logf("%s: small %v, large %v, ratio %.2f (bound %.1f, attempt %d)", name, bestSmall, bestLarge, last, maxRatio, attempt+1)
		if last <= maxRatio {
			return
		}
	}
	t.Errorf("%s: larger input was %.1fx slower in all %d attempts, want at most %.1fx (super-linear growth)", name, last, attempts, maxRatio)
}

// calibrate runs fn once (warm-up) and returns how many repetitions make a
// sample span at least minSample.
func calibrate(fn func()) int {
	start := time.Now()
	fn()
	one := time.Since(start)
	if one >= minSample {
		return 1
	}
	if one <= 0 {
		return maxReps
	}
	reps := int(minSample/one) + 1
	if reps > maxReps {
		reps = maxReps
	}
	return reps
}

// timeReps returns the per-call time of reps calls of fn.
func timeReps(fn func(), reps int) time.Duration {
	runtime.GC()
	start := time.Now()
	for i := 0; i < reps; i++ {
		fn()
	}
	return time.Since(start) / time.Duration(reps)
}

// AssertLinearBytes fails when run(large) allocates more than maxRatio times
// the bytes of run(small). Allocated bytes are deterministic for a given
// input, so unlike AssertLinearGrowth this holds under the race detector and
// on a loaded machine, and it catches regressions that copy or rebuild
// subtrees (quadratic bytes with a linear allocation count, which
// testing.AllocsPerRun cannot see). Each size is measured several times and
// the median delta kept, with the collector paused so pool contents stay stable.
func AssertLinearBytes(t testing.TB, name string, maxRatio float64, small, large func()) {
	t.Helper()
	s, l := minAllocBytes(small), minAllocBytes(large)
	if s == 0 {
		s = 1
	}
	ratio := float64(l) / float64(s)
	t.Logf("%s: B/op small %d, large %d, ratio %.2f (bound %.1f)", name, s, l, ratio, maxRatio)
	if ratio > maxRatio {
		t.Errorf("%s: larger input allocated %.1fx more bytes, want at most %.1fx (super-linear growth)", name, ratio, maxRatio)
	}
}

func minAllocBytes(fn func()) uint64 {
	// A collection mid-measurement empties sync.Pools, which makes later
	// runs allocate objects an earlier run reused; keep it out of the window.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	runtime.GC()
	fn() // warm pools and lazily initialised tables
	var runs [5]uint64
	for i := range runs {
		var a, b runtime.MemStats
		runtime.ReadMemStats(&a)
		fn()
		runtime.ReadMemStats(&b)
		runs[i] = b.TotalAlloc - a.TotalAlloc
	}
	sort.Slice(runs[:], func(i, j int) bool { return runs[i] < runs[j] })
	return runs[len(runs)/2]
}

// TrippingContext is a context.Context whose Err reports nil for the first
// Allow calls and context.Canceled afterwards. Cancellation therefore happens
// at a fixed point in the callee's own progress instead of after a sleep, so
// tests of cancellation responsiveness need no wall-clock bound.
type TrippingContext struct {
	context.Context // supplies Done; closed when the allowance is first exceeded
	cancel          context.CancelFunc
	allow           int64
	polls           atomic.Int64
}

// NewTrippingContext returns a context that starts reporting cancellation
// once Err has been called allow times.
func NewTrippingContext(allow int) *TrippingContext {
	// WithCancel gives a non-nil Done channel, which callers use to decide
	// whether polling Err is worthwhile at all.
	ctx, cancel := context.WithCancel(context.Background())
	return &TrippingContext{Context: ctx, cancel: cancel, allow: int64(allow)}
}

// Err counts the call and reports cancellation once the allowance is spent.
func (c *TrippingContext) Err() error {
	if c.polls.Add(1) > c.allow {
		// Close Done too, so callees that select on Done() and callees that
		// poll Err() observe the same cancellation point.
		c.cancel()
		return context.Canceled
	}
	return nil
}

// Polls returns how many times Err has been called.
func (c *TrippingContext) Polls() int { return int(c.polls.Load()) }

// PollsAfterTrip returns how many Err calls reported cancellation, counting
// the first. A callee that honours cancellation promptly stops after 1.
func (c *TrippingContext) PollsAfterTrip() int {
	if n := c.polls.Load() - c.allow; n > 0 {
		return int(n)
	}
	return 0
}
