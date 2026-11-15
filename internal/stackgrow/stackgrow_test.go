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

package stackgrow

import (
	"testing"
	"unsafe"
)

//go:noinline
func reserveAnchor() uintptr {
	var local byte
	return uintptr(unsafe.Pointer(&local))
}

//go:noinline
func reserveDescent(depth int) byte {
	var pad [256]byte
	pad[depth&255] = byte(depth)
	if depth == 0 {
		return pad[0]
	}
	value := reserveDescent(depth - 1)
	return value + pad[depth&255]
}

//go:noinline
func reserveProbe(reserve bool) bool {
	if reserve {
		Reserve()
	}
	before := reserveAnchor()
	reserveDescent(32)
	return before != reserveAnchor()
}

func TestReserveAvoidsLaterCopies(t *testing.T) {
	const trials = 200
	controlMoves := 0
	for range trials {
		moved := make(chan bool)
		go func() { moved <- reserveProbe(false) }()
		if <-moved {
			controlMoves++
		}
	}
	if controlMoves == 0 {
		t.Skip("control stack never moved; adaptive goroutine starting stack is already large enough")
	}
	for trial := range trials {
		moved := make(chan bool)
		go func() { moved <- reserveProbe(true) }()
		if <-moved {
			t.Fatalf("trial %d: stack moved during descent after Reserve (control moved %d/%d times)", trial, controlMoves, trials)
		}
	}
}
