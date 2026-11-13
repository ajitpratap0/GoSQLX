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

package gosqlx_test

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"testing"
	"unsafe"

	"github.com/ajitpratap0/GoSQLX/internal/stackgrow"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// stackReserveLocalAddr returns a value, rather than a pointer that the runtime
// would adjust when copying the stack. Both calls must come from the same frame.
//
//go:noinline
func stackReserveLocalAddr() uintptr {
	var local byte
	return uintptr(unsafe.Pointer(&local))
}

// stackReserveDescent keeps each pad live across the recursive call.
//
//go:noinline
func stackReserveDescent(depth int) byte {
	var pad [256]byte
	pad[depth%len(pad)] = byte(depth)
	if depth == 0 {
		return pad[0]
	}
	result := stackReserveDescent(depth - 1)
	runtime.KeepAlive(&pad)
	return result + pad[depth%len(pad)]
}

func stackReserveDescentMoves(depth int) bool {
	moved := make(chan bool)
	go func() {
		stackgrow.Reserve()
		before := stackReserveLocalAddr()
		stackReserveDescent(depth)
		after := stackReserveLocalAddr()
		moved <- before != after
	}()
	return <-moved
}

func TestStackReserve_LandsAt16KiB(t *testing.T) {
	if raceEnabled {
		t.Skip("race instrumentation changes stack classes")
	}
	if runtime.GOOS == "windows" {
		t.Skip("Windows reserves 32 KiB because of stackSystem")
	}
	for attempt := 0; attempt < 3; attempt++ {
		if stackReserveDescentMoves(32) {
			t.Fatal("about 10 KiB of descent moved the reserved stack; want at least 16 KiB")
		}
		if !stackReserveDescentMoves(64) {
			t.Fatal("about 20 KiB of descent did not move the reserved stack; want 16 KiB, not 32 KiB")
		}
	}
}

// stackReserveParseMoves probes the parse and release together, using a fresh
// goroutine for every attempt so a previous parse cannot hide stack growth.
func stackReserveParseMoves(sql string, parse func(string) error) (bool, error) {
	type result struct {
		moved bool
		err   error
	}
	results := make(chan result)
	go func() {
		stackgrow.Reserve()
		before := stackReserveLocalAddr()
		err := parse(sql)
		after := stackReserveLocalAddr()
		results <- result{moved: before != after, err: err}
	}()
	got := <-results
	return got.moved, got.err
}

// Not skipped under -race on purpose: it asserts only that the reserved stack
// is not copied again during a parse (no stack move), which holds for any
// landing class, so the 16-32 KiB race variance does not affect it.
func TestStackReserve_CoversPortableCorpus(t *testing.T) {
	// A GC cycle shrinks under-used goroutine stacks, which moves the stack and
	// would be mistaken for a growth copy. Finish any running cycle and keep GC
	// off while measuring.
	runtime.GC()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	apis := []struct {
		name  string
		parse func(string) error
	}{
		{"Parse", parseAndRelease},
		{"Validate", gosqlx.Validate},
		{"ParseWithDialect", func(sql string) error {
			tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectPostgreSQL)
			if err == nil {
				ast.ReleaseAST(tree)
			}
			return err
		}},
		{"ParseTree", func(sql string) error {
			tree, err := gosqlx.ParseTree(context.Background(), sql)
			if err == nil {
				tree.Release()
			}
			return err
		}},
	}
	for _, q := range portableQueries(t) {
		for _, api := range apis {
			t.Run(q.ID+"/"+api.name, func(t *testing.T) {
				for attempt := 0; attempt < 3; attempt++ {
					moved, err := stackReserveParseMoves(q.SQL, api.parse)
					if err != nil {
						t.Fatal(err)
					}
					if moved {
						t.Fatalf("parse copied the reserved stack on attempt %d", attempt+1)
					}
				}
			})
		}
	}
}

func TestStackBudget_RealWorldCoverage(t *testing.T) {
	if raceEnabled {
		t.Skip("race instrumentation changes stack classes")
	}
	statements := mxCorpus(t).All()
	if len(statements) == 0 {
		t.Fatal("benchmark corpus is empty")
	}
	runtime.GC()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	movedCount := 0
	var offenders []string
	for _, statement := range statements {
		moved := false
		for attempt := 0; attempt < 3; attempt++ {
			copied, _ := stackReserveParseMoves(statement.SQL, func(sql string) error {
				tree, err := gosqlx.ParseWithDialect(sql, keywords.SQLDialect(statement.Dialect))
				if err == nil {
					ast.ReleaseAST(tree)
				}
				return err
			})
			moved = moved || copied
		}
		if moved {
			movedCount++
			if len(offenders) < 10 {
				offenders = append(offenders, fmt.Sprintf("%s (%s)", statement.Key(), statement.Dialect))
			}
		}
	}
	covered := len(statements) - movedCount
	coverage := 100 * float64(covered) / float64(len(statements))
	t.Logf("reserved stack covers %d/%d statements (%.2f%%); %d moved", covered, len(statements), coverage, movedCount)
	if covered*100 < len(statements)*99 {
		t.Fatalf("stack coverage %.2f%% is below 99.0%%; first offenders: %v", coverage, offenders)
	}
}
