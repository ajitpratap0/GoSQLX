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
	attempts = 3
)

// AssertLinearGrowth fails when run(large) is more than maxRatio times slower
// than run(small), where large is factor times the size of small. Choose
// maxRatio between the linear expectation (factor) and the quadratic one
// (factor squared), for example factor 4 and maxRatio 10.
//
// The measurement is robust against a loaded machine and the race detector:
// runs of the two sizes are interleaved so both see the same load, the
// fastest of several runs of each is kept, GC is paused while timing, and the
// whole comparison may be repeated, passing if any attempt is within bound.
func AssertLinearGrowth(t testing.TB, name string, maxRatio float64, small, large func()) {
	t.Helper()
	old := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(old)

	small()
	large() // warm caches, pools and lazily initialised tables
	var last float64
	for attempt := 0; attempt < attempts; attempt++ {
		bestSmall, bestLarge := time.Duration(1<<63-1), time.Duration(1<<63-1)
		for i := 0; i < samples; i++ {
			if d := timeOnce(small); d < bestSmall {
				bestSmall = d
			}
			if d := timeOnce(large); d < bestLarge {
				bestLarge = d
			}
		}
		if bestSmall <= 0 {
			bestSmall = 1
		}
		last = float64(bestLarge) / float64(bestSmall)
		t.Logf("%s: small %v, large %v, ratio %.2f (bound %.1f, attempt %d)", name, bestSmall, bestLarge, last, maxRatio, attempt+1)
		if last <= maxRatio {
			return
		}
	}
	t.Errorf("%s: larger input was %.1fx slower in all %d attempts, want at most %.1fx (super-linear growth)", name, last, attempts, maxRatio)
}

func timeOnce(fn func()) time.Duration {
	runtime.GC()
	start := time.Now()
	fn()
	return time.Since(start)
}

// TrippingContext is a context.Context whose Err reports nil for the first
// Allow calls and context.Canceled afterwards. Cancellation therefore happens
// at a fixed point in the callee's own progress instead of after a sleep, so
// tests of cancellation responsiveness need no wall-clock bound.
type TrippingContext struct {
	context.Context // never cancelled itself; supplies a non-nil Done channel
	allow           int64
	polls           atomic.Int64
}

// NewTrippingContext returns a context that starts reporting cancellation
// once Err has been called allow times.
func NewTrippingContext(allow int) *TrippingContext {
	// WithCancel gives a non-nil Done channel, which callers use to decide
	// whether polling Err is worthwhile at all.
	ctx, cancel := context.WithCancel(context.Background())
	_ = cancel // released when the test process exits; the context holds no resources
	return &TrippingContext{Context: ctx, allow: int64(allow)}
}

// Err counts the call and reports cancellation once the allowance is spent.
func (c *TrippingContext) Err() error {
	if c.polls.Add(1) > c.allow {
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
