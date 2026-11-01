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

package gosqlx

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

// flipCtx is a context whose Err() returns nil for the first okCalls calls and
// context.Canceled afterwards. It lets tests reach the mid-tokenize and
// mid-parse cancellation branches of ParseWithContext deterministically.
type flipCtx struct {
	context.Context
	calls   atomic.Int64
	okCalls int64
}

func (c *flipCtx) Err() error {
	if c.calls.Add(1) > c.okCalls {
		return context.Canceled
	}
	return nil
}

// TestParseWithContext_MidFlightCancelWrapsTimeout sweeps the cancellation
// point across every ctx.Err() call and requires that every failure caused by
// cancellation wraps ErrTimeout together with context.Canceled, never
// ErrTokenize or ErrSyntax.
func TestParseWithContext_MidFlightCancelWrapsTimeout(t *testing.T) {
	const sql = "SELECT a, b FROM t WHERE a IN (SELECT x FROM u) ORDER BY b"
	sawTimeout := 0
	for k := int64(1); k < 400; k++ {
		ctx := &flipCtx{Context: context.Background(), okCalls: k}
		_, err := ParseWithContext(ctx, sql)
		if err == nil {
			continue
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("okCalls=%d: unexpected non-cancel error: %v", k, err)
		}
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("okCalls=%d: cancel error does not wrap ErrTimeout: %v", k, err)
		}
		if errors.Is(err, ErrTokenize) || errors.Is(err, ErrSyntax) {
			t.Fatalf("okCalls=%d: cancel error wraps wrong sentinel: %v", k, err)
		}
		sawTimeout++
	}
	if sawTimeout == 0 {
		t.Fatal("never observed a mid-flight cancellation")
	}
}
