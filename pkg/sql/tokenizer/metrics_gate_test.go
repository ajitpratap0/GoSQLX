// Copyright 2026 GoSQLX Contributors
// SPDX-License-Identifier: Apache-2.0

package tokenizer

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/metrics"
)

// TestTokenize_MetricsGate verifies tokenization is recorded when metrics are
// enabled and leaves every counter untouched when they are disabled.
func TestTokenize_MetricsGate(t *testing.T) {
	was := metrics.IsEnabled()
	t.Cleanup(func() {
		if was {
			metrics.Enable()
		} else {
			metrics.Disable()
		}
	})

	run := func() {
		tkz := GetTokenizer()
		defer PutTokenizer(tkz)
		if _, err := tkz.Tokenize([]byte("SELECT a, b FROM t WHERE c = 1")); err != nil {
			t.Fatalf("tokenize: %v", err)
		}
		if _, err := tkz.Tokenize([]byte("SELECT 'unterminated")); err == nil {
			t.Fatal("expected error for unterminated string")
		}
		if _, err := tkz.Tokenize([]byte(strings.Repeat("x", MaxInputSize+1))); err == nil {
			t.Fatal("expected error for oversized input")
		}
	}

	metrics.Enable()
	metrics.Reset()
	run()
	on := metrics.GetStats()
	if on.TokenizeOperations != 3 {
		t.Fatalf("enabled: TokenizeOperations = %d, want 3", on.TokenizeOperations)
	}
	if on.TokenizeErrors != 2 {
		t.Fatalf("enabled: TokenizeErrors = %d, want 2", on.TokenizeErrors)
	}

	metrics.Disable()
	metrics.Reset()
	run()
	off := metrics.GetStats()
	if off.TokenizeOperations != 0 || off.TokenizeErrors != 0 {
		t.Fatalf("disabled: recorded ops=%d errs=%d, want 0", off.TokenizeOperations, off.TokenizeErrors)
	}
}

// TestTokenize_MetricsDoNotChangeTokens checks output is identical with
// metrics on and off.
func TestTokenize_MetricsDoNotChangeTokens(t *testing.T) {
	was := metrics.IsEnabled()
	t.Cleanup(func() {
		if was {
			metrics.Enable()
		} else {
			metrics.Disable()
		}
	})
	sql := []byte("SELECT a, COUNT(*) FROM t JOIN u ON t.id = u.id GROUP BY a")
	get := func() int {
		tkz := GetTokenizer()
		defer PutTokenizer(tkz)
		toks, err := tkz.Tokenize(sql)
		if err != nil {
			t.Fatal(err)
		}
		return len(toks)
	}
	metrics.Enable()
	a := get()
	metrics.Disable()
	b := get()
	if a != b {
		t.Fatalf("token count differs: on=%d off=%d", a, b)
	}
}
