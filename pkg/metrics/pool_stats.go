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

package metrics

import (
	"sync"
	"sync/atomic"

	"github.com/ajitpratap0/GoSQLX/internal/metricsgate"
	"github.com/ajitpratap0/GoSQLX/internal/poolstats"
)

// PoolStat holds utilization counters for a single named object pool.
// Gets counts Get() calls (items retrieved) and Puts counts Put() calls (items
// returned) made only while metrics are enabled. Active() estimates currently
// borrowed items and can be skewed if metrics are toggled while items are borrowed.
type PoolStat struct {
	Gets int64 `json:"gets"` // Get() calls while metrics are enabled
	Puts int64 `json:"puts"` // Put() calls while metrics are enabled
}

// Active returns an estimate of currently borrowed items (Gets - Puts).
// Toggling metrics while items are borrowed can skew the estimate. It can be
// negative if a Get occurred while disabled and its Put occurred after Enable.
func (s PoolStat) Active() int64 {
	return s.Gets - s.Puts
}

// poolCounter is the internal per-pool atomic counter pair.
type poolCounter struct {
	gets int64
	puts int64
}

var (
	poolStatsMu  sync.RWMutex
	poolCounters = map[string]*poolCounter{}
)

// standardPoolNames are always pre-populated in GetPoolStats output.
var standardPoolNames = []string{"tokenizer", "parser", "ast"}

func getOrCreatePoolCounter(name string) *poolCounter {
	poolStatsMu.RLock()
	c, ok := poolCounters[name]
	poolStatsMu.RUnlock()
	if ok {
		return c
	}
	poolStatsMu.Lock()
	defer poolStatsMu.Unlock()
	if c, ok = poolCounters[name]; ok {
		return c
	}
	c = &poolCounter{}
	poolCounters[name] = c
	return c
}

// RecordNamedPoolGet records a Get() call for the named pool only while metrics
// are enabled and returns the new total, or 0 when disabled (nothing is recorded).
// Call this immediately after retrieving an object from a sync.Pool.
// This is safe for concurrent use and uses atomic operations.
func RecordNamedPoolGet(name string) int64 {
	if !metricsgate.Enabled() {
		return 0
	}
	// poolstats.Counter checks the gate again; a toggle between the two reads
	// only records or skips one count, which the documented semantics allow.
	if c := poolstats.ByName(name); c != nil {
		return c.Get()
	}
	c := getOrCreatePoolCounter(name)
	return atomic.AddInt64(&c.gets, 1)
}

// RecordNamedPoolPut records a Put() call for the named pool only while metrics
// are enabled and returns the new total, or 0 when disabled (nothing is recorded).
// Call this immediately before or after returning an object to a sync.Pool.
// This is safe for concurrent use and uses atomic operations.
func RecordNamedPoolPut(name string) int64 {
	if !metricsgate.Enabled() {
		return 0
	}
	// poolstats.Counter checks the gate again; a toggle between the two reads
	// only records or skips one count, which the documented semantics allow.
	if c := poolstats.ByName(name); c != nil {
		return c.Put()
	}
	c := getOrCreatePoolCounter(name)
	return atomic.AddInt64(&c.puts, 1)
}

// GetPoolStats returns a snapshot of named pool counters counting only operations
// made while metrics are enabled. Standard pool names ("tokenizer", "parser", "ast")
// are always present. While disabled, it returns a new map containing exactly those
// names with zero values. Counters are retained and become visible after Enable;
// disabled operations are not retroactively counted. ResetPoolStats clears them.
// This function is safe for concurrent use.
func GetPoolStats() map[string]PoolStat {
	if !metricsgate.Enabled() {
		zero := make(map[string]PoolStat, len(standardPoolNames))
		for _, name := range standardPoolNames {
			zero[name] = PoolStat{}
		}
		return zero
	}
	poolStatsMu.RLock()
	defer poolStatsMu.RUnlock()
	result := make(map[string]PoolStat, len(poolCounters)+len(standardPoolNames))
	// Standard pools are always present, read from the precreated counters.
	for _, name := range standardPoolNames {
		g, p := poolstats.ByName(name).Load()
		result[name] = PoolStat{Gets: g, Puts: p}
	}
	for name, c := range poolCounters {
		result[name] = PoolStat{
			Gets: atomic.LoadInt64(&c.gets),
			Puts: atomic.LoadInt64(&c.puts),
		}
	}
	return result
}

// ResetPoolStats zeroes all named pool counters. Primarily intended for testing.
// This is safe for concurrent use.
func ResetPoolStats() {
	poolStatsMu.Lock()
	defer poolStatsMu.Unlock()
	poolCounters = map[string]*poolCounter{}
	for _, name := range standardPoolNames {
		poolstats.ByName(name).Reset()
	}
}
