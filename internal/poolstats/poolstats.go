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

// Package poolstats holds the precreated, cache-line padded counters for the
// three standard pools (tokenizer, parser, ast). The typed API is a single
// atomic add and inlines at every call site, with no lock, map lookup or
// string hash. pkg/metrics exposes the counters through GetPoolStats and
// ResetPoolStats.
package poolstats

import "sync/atomic"

// Counter is a Get/Put counter pair padded to its own 64-byte cache line so
// the three standard pools never false-share.
type Counter struct {
	gets atomic.Int64
	puts atomic.Int64
	_    [48]byte
}

// Get records one Get() and returns the new total.
func (c *Counter) Get() int64 { return c.gets.Add(1) }

// Put records one Put() and returns the new total.
func (c *Counter) Put() int64 { return c.puts.Add(1) }

// Load returns the current gets and puts.
func (c *Counter) Load() (gets, puts int64) { return c.gets.Load(), c.puts.Load() }

// Reset zeroes both counters in place.
func (c *Counter) Reset() {
	c.gets.Store(0)
	c.puts.Store(0)
}

// The standard pool counters. They are never replaced.
var (
	Tokenizer Counter
	Parser    Counter
	AST       Counter
)

// ByName returns the counter for a standard pool name, or nil.
func ByName(name string) *Counter {
	switch name {
	case "tokenizer":
		return &Tokenizer
	case "parser":
		return &Parser
	case "ast":
		return &AST
	}
	return nil
}
