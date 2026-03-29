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
)

// PoolStat holds utilization counters for a single named object pool.
// Gets counts total Get() calls (items retrieved), Puts counts total Put() calls
// (items returned). Active() returns an estimate of currently borrowed items.
type PoolStat struct {
	Gets int64 `json:"gets"` // total Get() calls
	Puts int64 `json:"puts"` // total Put() calls
}

// Active returns an estimate of currently borrowed items (Gets - Puts).
// May be negative during warm-up before items are returned to the pool.
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

// RecordNamedPoolGet records a Get() call for the named pool and returns the new total.
// Call this immediately after retrieving an object from a sync.Pool.
// This is safe for concurrent use and uses atomic operations.
func RecordNamedPoolGet(name string) int64 {
	c := getOrCreatePoolCounter(name)
	return atomic.AddInt64(&c.gets, 1)
}

// RecordNamedPoolPut records a Put() call for the named pool and returns the new total.
// Call this immediately before or after returning an object to a sync.Pool.
// This is safe for concurrent use and uses atomic operations.
func RecordNamedPoolPut(name string) int64 {
	c := getOrCreatePoolCounter(name)
	return atomic.AddInt64(&c.puts, 1)
}

// GetPoolStats returns a snapshot of all named pool counters.
// The map is keyed by pool name. Standard pool names ("tokenizer", "parser", "ast")
// are always present with zero values even if no operations have been recorded.
// This function is safe for concurrent use.
func GetPoolStats() map[string]PoolStat {
	// Ensure standard pools are always present
	for _, name := range standardPoolNames {
		getOrCreatePoolCounter(name)
	}

	poolStatsMu.RLock()
	defer poolStatsMu.RUnlock()
	result := make(map[string]PoolStat, len(poolCounters))
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
}
