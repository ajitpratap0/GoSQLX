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

// Package metricsgate holds the shared flag controlling metrics collection.
package metricsgate

import "sync/atomic"

const cacheLine = 64

var gate struct {
	_  [cacheLine]byte
	on atomic.Bool
	_  [cacheLine]byte
}

// Enabled reports whether metrics collection is enabled.
func Enabled() bool { return gate.on.Load() }

// Set enables or disables metrics collection.
func Set(on bool) { gate.on.Store(on) }
