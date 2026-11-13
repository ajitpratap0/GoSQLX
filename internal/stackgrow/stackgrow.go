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

// Package stackgrow reserves stack space before tokenizing and parsing, so a
// fresh goroutine copies its stack once while its live frames are shallow.
// Reserve's 12 KiB frame lands a fresh goroutine at 16 KiB. The array is guarded
// by a package variable that is never written, so the compiler preserves the
// frame but the array is never zeroed. This package adds no public API.
//
// Windows starts fresh goroutines at 8 KiB and lands at 32 KiB because its stack
// system allowance is 4 KiB. Under race detection, the larger guard can land at
// 16-32 KiB. js/wasm behaves like Linux and lands at 16 KiB.
package stackgrow

const reserveBytes = 12 << 10

var never bool

// Reserve reserves the parse stack. Callers put it first, before tokenizing.
// It is a no-op of about 1 ns when the stack is already large enough.
//
//go:noinline
func Reserve() {
	if never {
		var buf [reserveBytes]byte
		sink(&buf)
	}
}

//go:noinline
func sink(b *[reserveBytes]byte) { b[0] = 1 }
