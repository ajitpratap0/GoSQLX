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

package tokenizer

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// tokenizerSink keeps constructed tokenizers reachable so the allocation
// tests measure real heap allocations.
var tokenizerSink *Tokenizer

// TestSetDialect_AllocationFree pins that switching dialects does not build
// a keyword table (#550): SetDialect is a field assignment.
func TestSetDialect_AllocationFree(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under the race detector")
	}
	tkz, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	allocs := testing.AllocsPerRun(100, func() {
		tkz.SetDialect(keywords.DialectMySQL)
		tkz.SetDialect(keywords.DialectPostgreSQL)
	})
	if allocs != 0 {
		t.Errorf("SetDialect(MySQL)+SetDialect(PostgreSQL) allocs = %v, want 0", allocs)
	}
}

// TestNewWithDialect_Allocs pins that NewWithDialect allocates only the
// tokenizer itself and its initial lineStarts slice (#550).
func TestNewWithDialect_Allocs(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under the race detector")
	}
	allocs := testing.AllocsPerRun(100, func() {
		tkz, err := NewWithDialect(keywords.DialectMySQL)
		if err != nil {
			t.Fatal(err)
		}
		tokenizerSink = tkz
	})
	if allocs > 2 {
		t.Errorf("NewWithDialect(MySQL) allocs = %v, want <= 2", allocs)
	}
}

// TestPutTokenizer_DialectRestoreAllocationFree pins that returning a
// dialect-configured tokenizer to the pool no longer rebuilds a keyword table.
func TestPutTokenizer_DialectRestoreAllocationFree(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under the race detector")
	}
	// Warm the pool so Get does not allocate a fresh tokenizer.
	PutTokenizer(GetTokenizer())
	allocs := testing.AllocsPerRun(100, func() {
		tkz := GetTokenizer()
		tkz.SetDialect(keywords.DialectClickHouse)
		PutTokenizer(tkz)
	})
	// AllocsPerRun returns the integer average; a steady-state
	// Get+SetDialect+Put must not allocate at all.
	if allocs >= 1 {
		t.Errorf("Get+SetDialect+Put allocs = %v, want < 1", allocs)
	}
}

// TestNewWithKeywords_StillValidates pins the unchanged exported contract of
// NewWithKeywords after the unread keywords field was removed (#550).
func TestNewWithKeywords_StillValidates(t *testing.T) {
	if _, err := NewWithKeywords(nil); err == nil {
		t.Fatal("NewWithKeywords(nil) error = nil, want error")
	}
	tkz, err := NewWithKeywords(keywords.New(keywords.DialectMySQL, true))
	if err != nil {
		t.Fatalf("NewWithKeywords() error = %v", err)
	}
	tokens, err := tkz.Tokenize([]byte("SELECT 1"))
	if err != nil {
		t.Fatalf("Tokenize() error = %v", err)
	}
	if len(tokens) == 0 {
		t.Fatal("Tokenize() returned no tokens")
	}
}

// TestSetDialect_NormalizesEmptyAndUnknown pins the ""/Unknown -> PostgreSQL
// normalization in SetDialect and NewWithDialect.
func TestSetDialect_NormalizesEmptyAndUnknown(t *testing.T) {
	for _, d := range []keywords.SQLDialect{"", keywords.DialectUnknown} {
		tkz, err := NewWithDialect(d)
		if err != nil {
			t.Fatalf("NewWithDialect(%q) error = %v", d, err)
		}
		if tkz.Dialect() != keywords.DialectPostgreSQL {
			t.Errorf("NewWithDialect(%q).Dialect() = %q, want %q", d, tkz.Dialect(), keywords.DialectPostgreSQL)
		}
		tkz.SetDialect(keywords.DialectMySQL)
		tkz.SetDialect(d)
		if tkz.Dialect() != keywords.DialectPostgreSQL {
			t.Errorf("SetDialect(%q) -> Dialect() = %q, want %q", d, tkz.Dialect(), keywords.DialectPostgreSQL)
		}
	}
}
