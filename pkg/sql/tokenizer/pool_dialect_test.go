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

// Package tokenizer - pool_dialect_test.go
// Regression tests ensuring the tokenizer pool does not leak dialect-specific
// keyword state between callers.

package tokenizer

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestReset_PreservesDialect verifies that Reset preserves the configured
// dialect. Reset runs at the start of every Tokenize call, so a dialect set via
// SetDialect must survive it — otherwise "set dialect once, tokenize many"
// would break.
func TestReset_PreservesDialect(t *testing.T) {
	tkz, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tkz.SetDialect(keywords.DialectMySQL)
	tkz.Reset()
	if tkz.Dialect() != keywords.DialectMySQL {
		t.Errorf("after Reset, dialect = %q, want %q (dialect must persist across Tokenize)",
			tkz.Dialect(), keywords.DialectMySQL)
	}
}

// TestTokenize_PreservesDialectAcrossCalls guards the "set dialect once,
// tokenize many" pattern end-to-end: the dialect must survive the internal
// Reset that Tokenize performs on each call.
func TestTokenize_PreservesDialectAcrossCalls(t *testing.T) {
	tkz, err := NewWithDialect(keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("NewWithDialect error = %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := tkz.Tokenize([]byte("SELECT @@VERSION")); err != nil {
			t.Fatalf("Tokenize #%d error = %v", i, err)
		}
		if tkz.Dialect() != keywords.DialectSQLServer {
			t.Fatalf("after Tokenize #%d, dialect = %q, want %q",
				i, tkz.Dialect(), keywords.DialectSQLServer)
		}
	}
}

// TestPool_NoDialectLeak verifies that returning a dialect-configured tokenizer
// to the pool does not leak that dialect to a subsequent acquisition.
func TestPool_NoDialectLeak(t *testing.T) {
	// Acquire, switch to a non-default dialect, and return to the pool.
	a := GetTokenizer()
	a.SetDialect(keywords.DialectMySQL)
	PutTokenizer(a)

	// The next acquisition must be a clean PostgreSQL-default tokenizer.
	b := GetTokenizer()
	defer PutTokenizer(b)
	if b.Dialect() != keywords.DialectPostgreSQL {
		t.Errorf("pooled tokenizer leaked dialect: got %q, want %q",
			b.Dialect(), keywords.DialectPostgreSQL)
	}
}

// TestReset_DefaultDialectStaysDefault is a sanity check that the common path
// (already the default dialect) still ends up at the default after Reset.
func TestReset_DefaultDialectStaysDefault(t *testing.T) {
	tkz, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	tkz.Reset()
	if tkz.Dialect() != keywords.DialectPostgreSQL {
		t.Errorf("after Reset, dialect = %q, want %q", tkz.Dialect(), keywords.DialectPostgreSQL)
	}
}
