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

package scaletest

import (
	"context"
	"errors"
	"testing"
	"time"
)

// recorder captures failures so the helper can be shown to reject a bad curve.
type recorder struct {
	testing.TB
	failed bool
}

func (r *recorder) Errorf(string, ...any) { r.failed = true }
func (r *recorder) Logf(string, ...any)   {}
func (r *recorder) Helper()               {}

var sink int

// work burns CPU proportional to n (linear) or n*n/64 (quadratic) steps.
func work(n int, quadratic bool) func() {
	return func() {
		steps := n
		if quadratic {
			steps = n * n / 64
		}
		x := 0
		for i := 0; i < steps; i++ {
			x += i ^ (x << 1)
		}
		sink = x
	}
}

func TestAssertLinearGrowthAcceptsLinear(t *testing.T) {
	r := &recorder{TB: t}
	AssertLinearGrowth(r, "linear", 10, work(100000, false), work(400000, false))
	if r.failed {
		t.Error("linear work was reported as super-linear")
	}
}

func TestAssertLinearGrowthRejectsQuadratic(t *testing.T) {
	r := &recorder{TB: t}
	AssertLinearGrowth(r, "quadratic", 10, work(4000, true), work(16000, true))
	if !r.failed {
		t.Error("quadratic work was not reported")
	}
}

// A real regression makes the large case slow; the helper must fail with the
// ratio within its time budget rather than retry until the package times out.
func TestAssertLinearGrowthSlowQuadraticFailsWithinBudget(t *testing.T) {
	old := budget
	budget = 200 * time.Millisecond
	defer func() { budget = old }()
	r := &recorder{TB: t}
	start := time.Now()
	// Large case takes a few hundred ms; unbounded retries would take
	// 5 attempts x 7 samples of it (tens of seconds).
	AssertLinearGrowth(r, "slow quadratic", 10, work(40000, true), work(160000, true))
	if !r.failed {
		t.Error("slow quadratic work was not reported")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("slow quadratic took %v to fail, want it bounded by the time budget", d)
	}
}

func TestTrippingContext(t *testing.T) {
	ctx := NewTrippingContext(2)
	if ctx.Done() == nil {
		t.Fatal("Done must be non-nil so callers poll Err")
	}
	for i := 0; i < 2; i++ {
		if err := ctx.Err(); err != nil {
			t.Fatalf("poll %d: unexpected %v", i+1, err)
		}
	}
	if err := ctx.Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("poll 3: got %v, want context.Canceled", err)
	}
	if ctx.Polls() != 3 || ctx.PollsAfterTrip() != 1 {
		t.Errorf("polls=%d afterTrip=%d, want 3 and 1", ctx.Polls(), ctx.PollsAfterTrip())
	}
}

// copyBytes allocates n bytes per call (linear) or n*n/4096 (quadratic).
func copyBytes(n int, quadratic bool) func() {
	return func() {
		size := n
		if quadratic {
			size = n * n / 4096
		}
		sink = len(make([]byte, size))
	}
}

func TestAssertLinearBytes(t *testing.T) {
	r := &recorder{TB: t}
	AssertLinearBytes(r, "linear", 10, copyBytes(1<<16, false), copyBytes(1<<18, false))
	if r.failed {
		t.Error("linear allocation was reported as super-linear")
	}
	r = &recorder{TB: t}
	AssertLinearBytes(r, "quadratic", 10, copyBytes(1<<16, true), copyBytes(1<<18, true))
	if !r.failed {
		t.Error("quadratic allocation was not reported")
	}
}

func TestTrippingContextClosesDone(t *testing.T) {
	ctx := NewTrippingContext(1)
	select {
	case <-ctx.Done():
		t.Fatal("Done closed before the allowance was exceeded")
	default:
	}
	_ = ctx.Err()
	_ = ctx.Err()
	select {
	case <-ctx.Done():
	default:
		t.Fatal("Done not closed after the allowance was exceeded")
	}
}
