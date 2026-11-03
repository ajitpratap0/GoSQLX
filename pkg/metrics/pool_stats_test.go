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

package metrics_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/metricsgate"
	"github.com/ajitpratap0/GoSQLX/internal/poolstats"
	"github.com/ajitpratap0/GoSQLX/pkg/metrics"
)

func TestPoolStats_ReturnsNonNilResult(t *testing.T) {
	stats := metrics.GetPoolStats()
	if stats == nil {
		t.Fatal("GetPoolStats returned nil")
	}
}

func TestPoolStats_HasTokenizerPool(t *testing.T) {
	stats := metrics.GetPoolStats()
	if _, ok := stats["tokenizer"]; !ok {
		t.Error("expected 'tokenizer' key in pool stats")
	}
}

func TestPoolStats_HasParserPool(t *testing.T) {
	stats := metrics.GetPoolStats()
	if _, ok := stats["parser"]; !ok {
		t.Error("expected 'parser' key in pool stats")
	}
}

func TestPoolStats_HasASTPool(t *testing.T) {
	stats := metrics.GetPoolStats()
	if _, ok := stats["ast"]; !ok {
		t.Error("expected 'ast' key in pool stats")
	}
}

func TestPoolStats_RecordGet(t *testing.T) {
	enablePoolStats(t)
	metrics.ResetPoolStats()

	_ = metrics.RecordNamedPoolGet("tokenizer")
	_ = metrics.RecordNamedPoolPut("tokenizer")

	stats := metrics.GetPoolStats()
	ts, ok := stats["tokenizer"]
	if !ok {
		t.Fatal("missing tokenizer key after reset+record")
	}
	if ts.Gets < 1 {
		t.Errorf("expected Gets >= 1 after RecordNamedPoolGet, got %d", ts.Gets)
	}
	if ts.Puts < 1 {
		t.Errorf("expected Puts >= 1 after RecordNamedPoolPut, got %d", ts.Puts)
	}
}

func TestPoolStats_ActiveCalculation(t *testing.T) {
	enablePoolStats(t)
	metrics.ResetPoolStats()

	metrics.RecordNamedPoolGet("parser")
	metrics.RecordNamedPoolGet("parser")
	metrics.RecordNamedPoolPut("parser")

	stats := metrics.GetPoolStats()
	ps := stats["parser"]
	if ps.Gets != 2 {
		t.Errorf("expected Gets=2, got %d", ps.Gets)
	}
	if ps.Puts != 1 {
		t.Errorf("expected Puts=1, got %d", ps.Puts)
	}
	if ps.Active() != 1 {
		t.Errorf("expected Active()=1, got %d", ps.Active())
	}
}

func TestPoolStats_ResetClearsCounters(t *testing.T) {
	enablePoolStats(t)
	metrics.ResetPoolStats()
	metrics.RecordNamedPoolGet("ast")
	metrics.ResetPoolStats()

	stats := metrics.GetPoolStats()
	// After reset, standard pools are recreated with zero values
	as := stats["ast"]
	if as.Gets != 0 {
		t.Errorf("expected Gets=0 after reset, got %d", as.Gets)
	}
}

func TestPoolStats_ConcurrentSafe(t *testing.T) {
	enablePoolStats(t)
	metrics.ResetPoolStats()

	done := make(chan struct{})
	for i := 0; i < 100; i++ {
		go func() {
			metrics.RecordNamedPoolGet("tokenizer")
			metrics.RecordNamedPoolPut("tokenizer")
			done <- struct{}{}
		}()
	}
	for i := 0; i < 100; i++ {
		<-done
	}

	stats := metrics.GetPoolStats()
	ts := stats["tokenizer"]
	if ts.Gets != 100 {
		t.Errorf("expected Gets=100, got %d", ts.Gets)
	}
	if ts.Puts != 100 {
		t.Errorf("expected Puts=100, got %d", ts.Puts)
	}
}

// TestPoolStats_TypedCountersEquivalent checks that the string-keyed API and
// the typed internal counters feed the same standard-pool statistics, that a
// custom pool keeps the map path, and that ResetPoolStats zeroes both.
func TestPoolStats_TypedCountersEquivalent(t *testing.T) {
	enablePoolStats(t)
	metrics.ResetPoolStats()
	t.Cleanup(metrics.ResetPoolStats)

	poolstats.Tokenizer.Get()
	poolstats.Tokenizer.Get()
	poolstats.Tokenizer.Put()
	metrics.RecordNamedPoolGet("tokenizer")
	metrics.RecordNamedPoolPut("parser")
	poolstats.AST.Get()
	metrics.RecordNamedPoolGet("custom-pool")

	stats := metrics.GetPoolStats()
	want := map[string]metrics.PoolStat{
		"tokenizer":   {Gets: 3, Puts: 1},
		"parser":      {Gets: 0, Puts: 1},
		"ast":         {Gets: 1, Puts: 0},
		"custom-pool": {Gets: 1, Puts: 0},
	}
	if len(stats) != len(want) {
		t.Fatalf("got %d pools %v, want %d", len(stats), stats, len(want))
	}
	for name, w := range want {
		if stats[name] != w {
			t.Errorf("%s = %+v, want %+v", name, stats[name], w)
		}
	}

	metrics.ResetPoolStats()
	stats = metrics.GetPoolStats()
	if len(stats) != 3 {
		t.Fatalf("after reset got %d pools, want exactly the 3 standard pools: %v", len(stats), stats)
	}
	for name, s := range stats {
		if s.Gets != 0 || s.Puts != 0 {
			t.Errorf("%s not zeroed: %+v", name, s)
		}
	}
}

func enablePoolStats(t testing.TB) {
	was := metrics.IsEnabled()
	metrics.Enable()
	t.Cleanup(func() {
		if !was {
			metrics.Disable()
		}
	})
}

func TestPoolStats_DisabledReturnsZeros(t *testing.T) {
	enablePoolStats(t)
	metrics.ResetPoolStats()
	t.Cleanup(metrics.ResetPoolStats)
	metrics.RecordNamedPoolGet("tokenizer")
	metrics.RecordNamedPoolGet("tokenizer")
	metrics.RecordNamedPoolGet("custom")
	poolstats.AST.Get()
	metrics.Disable()
	stats := metrics.GetPoolStats()
	if len(stats) != 3 {
		t.Fatalf("disabled stats = %v, want exactly three standard pools", stats)
	}
	for _, name := range []string{"tokenizer", "parser", "ast"} {
		if got, ok := stats[name]; !ok || got != (metrics.PoolStat{}) {
			t.Errorf("disabled %s = %+v (present %v), want zero", name, got, ok)
		}
	}
	if _, ok := stats["custom"]; ok {
		t.Error("custom pool visible while disabled")
	}
	// Each disabled read returns a fresh map, with no shared caller mutations.
	stats["tokenizer"] = metrics.PoolStat{Gets: 99}
	delete(stats, "parser")
	if fresh := metrics.GetPoolStats(); len(fresh) != 3 || fresh["tokenizer"] != (metrics.PoolStat{}) {
		t.Fatalf("disabled read reused a mutated map: %v", fresh)
	}
	metrics.Enable()
	stats = metrics.GetPoolStats()
	want := map[string]metrics.PoolStat{"tokenizer": {Gets: 2}, "parser": {}, "ast": {Gets: 1}, "custom": {Gets: 1}}
	if len(stats) != len(want) {
		t.Fatalf("restored stats = %v, want %v", stats, want)
	}
	for name, expected := range want {
		if got, ok := stats[name]; !ok || got != expected {
			t.Errorf("restored %s = %+v (present %v), want %+v", name, got, ok, expected)
		}
	}
}

func TestPoolStats_DisabledDoesNotCount(t *testing.T) {
	enablePoolStats(t)
	metrics.ResetPoolStats()
	t.Cleanup(metrics.ResetPoolStats)
	metrics.Disable()
	if got := metrics.RecordNamedPoolGet("tokenizer"); got != 0 {
		t.Errorf("disabled tokenizer Get = %d", got)
	}
	if got := metrics.RecordNamedPoolPut("parser"); got != 0 {
		t.Errorf("disabled parser Put = %d", got)
	}
	if got := metrics.RecordNamedPoolGet("custom-x"); got != 0 {
		t.Errorf("disabled custom Get = %d", got)
	}
	if got := metrics.RecordNamedPoolPut("custom-put-x"); got != 0 {
		t.Errorf("disabled custom Put = %d", got)
	}
	poolstats.Parser.Get()
	metrics.Enable()
	stats := metrics.GetPoolStats()
	if len(stats) != 3 {
		t.Fatalf("got pools %v, want exactly three standard pools", stats)
	}
	for _, name := range []string{"tokenizer", "parser", "ast"} {
		if got, ok := stats[name]; !ok || got != (metrics.PoolStat{}) {
			t.Errorf("%s = %+v (present %v), want zero", name, got, ok)
		}
	}
	if _, ok := stats["custom-x"]; ok {
		t.Error("disabled Get created a custom pool")
	}
	if _, ok := stats["custom-put-x"]; ok {
		t.Error("disabled Put created a custom pool")
	}
}

func TestPoolStats_FollowsEnableDisable(t *testing.T) {
	enablePoolStats(t)
	metrics.ResetPoolStats()
	t.Cleanup(metrics.ResetPoolStats)
	if !metricsgate.Enabled() {
		t.Fatal("Enable did not enable the shared gate")
	}
	if got := poolstats.Tokenizer.Get(); got != 1 {
		t.Fatalf("enabled Get = %d, want 1", got)
	}
	metrics.Disable()
	if metricsgate.Enabled() {
		t.Fatal("Disable did not disable the shared gate")
	}
	if got := poolstats.Tokenizer.Get(); got != 0 {
		t.Fatalf("disabled Get = %d, want 0", got)
	}
	if g, p := poolstats.Tokenizer.Load(); g != 1 || p != 0 {
		t.Fatalf("retained counts = %d/%d, want 1/0", g, p)
	}
	metrics.Enable()
}
