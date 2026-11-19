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

package metricsgate

import (
	"sync"
	"testing"
	"unsafe"
)

func TestDefaultAndToggle(t *testing.T) {
	if Enabled() {
		t.Fatal("gate must default to disabled in a fresh test binary")
	}
	t.Cleanup(func() { Set(false) })
	Set(true)
	if !Enabled() {
		t.Fatal("Set(true) did not enable gate")
	}
	Set(false)
	if Enabled() {
		t.Fatal("Set(false) did not disable gate")
	}
}

func TestGatePadding(t *testing.T) {
	size := unsafe.Sizeof(gate)
	offset := unsafe.Offsetof(gate.on)
	if size < 64+4+64 {
		t.Errorf("gate size = %d, want at least 132", size)
	}
	if offset < 64 {
		t.Errorf("flag offset = %d, want at least 64", offset)
	}
	if trailing := size - offset - unsafe.Sizeof(gate.on); trailing < 64 {
		t.Errorf("trailing padding = %d, want at least 64", trailing)
	}
}

func TestGateConcurrentToggle(t *testing.T) {
	was := Enabled()
	t.Cleanup(func() { Set(was) })
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5000; j++ {
				_ = Enabled()
			}
		}()
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5000; j++ {
				Set(j%2 == 0)
			}
		}()
	}
	wg.Wait()
}
