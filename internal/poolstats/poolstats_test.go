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

package poolstats

import (
	"sync"
	"testing"
	"unsafe"

	"github.com/ajitpratap0/GoSQLX/internal/metricsgate"
)

func TestCounterPaddedToCacheLine(t *testing.T) {
	if got := unsafe.Sizeof(Counter{}); got != 64 {
		t.Fatalf("Counter size = %d, want 64 (one cache line)", got)
	}
}

func TestCounterGetPutReset(t *testing.T) {
	enablePoolStats(t)
	var c Counter
	if n := c.Get(); n != 1 {
		t.Fatalf("first Get = %d, want 1", n)
	}
	c.Get()
	if n := c.Put(); n != 1 {
		t.Fatalf("first Put = %d, want 1", n)
	}
	if g, p := c.Load(); g != 2 || p != 1 {
		t.Fatalf("Load = %d/%d, want 2/1", g, p)
	}
	c.Reset()
	if g, p := c.Load(); g != 0 || p != 0 {
		t.Fatalf("after Reset Load = %d/%d, want 0/0", g, p)
	}
}

func TestByName(t *testing.T) {
	cases := map[string]*Counter{"tokenizer": &Tokenizer, "parser": &Parser, "ast": &AST}
	for name, want := range cases {
		if got := ByName(name); got != want {
			t.Errorf("ByName(%q) wrong counter", name)
		}
	}
	if ByName("custom") != nil || ByName("") != nil {
		t.Error("ByName must return nil for non-standard names")
	}
}

func TestCounterConcurrent(t *testing.T) {
	enablePoolStats(t)
	var c Counter
	const goroutines, per = 8, 5000
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < per; j++ {
				c.Get()
				c.Put()
			}
		}()
	}
	wg.Wait()
	if g, p := c.Load(); g != goroutines*per || p != goroutines*per {
		t.Fatalf("Load = %d/%d, want %d each", g, p, goroutines*per)
	}
}

func enablePoolStats(t testing.TB) {
	was := metricsgate.Enabled()
	metricsgate.Set(true)
	t.Cleanup(func() { metricsgate.Set(was) })
}

func TestCounterDisabledIsNoop(t *testing.T) {
	enablePoolStats(t)
	metricsgate.Set(false)
	var c Counter
	if got := c.Get(); got != 0 {
		t.Fatalf("disabled Get = %d, want 0", got)
	}
	if got := c.Put(); got != 0 {
		t.Fatalf("disabled Put = %d, want 0", got)
	}
	if g, p := c.Load(); g != 0 || p != 0 {
		t.Fatalf("disabled Load = %d/%d, want 0/0", g, p)
	}
	metricsgate.Set(true)
	if got := c.Get(); got != 1 {
		t.Fatalf("enabled Get = %d, want 1", got)
	}
	if got := c.Put(); got != 1 {
		t.Fatalf("enabled Put = %d, want 1", got)
	}
	metricsgate.Set(false)
	if got := c.Get(); got != 0 {
		t.Fatalf("disabled Get after toggle = %d, want 0", got)
	}
	if got := c.Put(); got != 0 {
		t.Fatalf("disabled Put after toggle = %d, want 0", got)
	}
	if g, p := c.Load(); g != 1 || p != 1 {
		t.Fatalf("retained Load = %d/%d, want 1/1", g, p)
	}
}

func TestCounterToggleRace(t *testing.T) {
	enablePoolStats(t)
	var c Counter
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5000; j++ {
				c.Get()
				c.Put()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 5000; j++ {
			metricsgate.Set(j%2 == 0)
		}
	}()
	wg.Wait()
	metricsgate.Set(true)
	if g, p := c.Load(); g < 0 || p < 0 {
		t.Fatalf("negative counts: %d/%d", g, p)
	}
}
