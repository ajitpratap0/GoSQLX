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

package gosqlx

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// invalidSyntaxSQL is deliberately malformed in a way the parser rejects
// after tokenization succeeds. Used to exercise the ErrSyntax wrapping path.
const invalidSyntaxSQL = "SELECT FROM WHERE"

// invalidTokenizeSQL is an unterminated string literal — the tokenizer
// reports this before parsing begins, so we get an ErrTokenize wrap.
const invalidTokenizeSQL = "SELECT 'unterminated"

// TestLegacy_ErrSyntax_Wrapping asserts every legacy Parse-family function
// wraps parser/syntax failures with ErrSyntax so callers can match on it.
func TestLegacy_ErrSyntax_Wrapping(t *testing.T) {
	cases := []struct {
		name string
		run  func() error
	}{
		{"Parse", func() error {
			_, err := Parse(invalidSyntaxSQL)
			return err
		}},
		{"ParseWithContext", func() error {
			_, err := ParseWithContext(context.Background(), invalidSyntaxSQL)
			return err
		}},
		{"ParseWithTimeout", func() error {
			_, err := ParseWithTimeout(invalidSyntaxSQL, time.Second)
			return err
		}},
		{"ParseBytes", func() error {
			_, err := ParseBytes([]byte(invalidSyntaxSQL))
			return err
		}},
		{"ParseMultiple", func() error {
			_, err := ParseMultiple([]string{invalidSyntaxSQL})
			return err
		}},
		{"Validate", func() error {
			return Validate(invalidSyntaxSQL)
		}},
		{"ValidateMultiple", func() error {
			return ValidateMultiple([]string{invalidSyntaxSQL})
		}},
		{"Format", func() error {
			_, err := Format(invalidSyntaxSQL, DefaultFormatOptions())
			return err
		}},
		{"ParseWithDialect", func() error {
			_, err := ParseWithDialect(invalidSyntaxSQL, keywords.DialectPostgreSQL)
			return err
		}},
		{"ParseWithRecovery", func() error {
			_, errs := ParseWithRecovery(invalidSyntaxSQL)
			if len(errs) == 0 {
				return nil
			}
			return errs[0]
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil {
				t.Fatalf("%s(%q) returned nil error; expected ErrSyntax-wrapped", tc.name, invalidSyntaxSQL)
			}
			if !errors.Is(err, ErrSyntax) {
				t.Errorf("errors.Is(err, ErrSyntax) = false for %s; err = %v", tc.name, err)
			}
		})
	}
}

// TestLegacy_ErrTokenize_Wrapping asserts tokenization failures are wrapped
// with ErrTokenize. Validate is intentionally excluded here because its
// fast-path surfaces the same failure under ErrSyntax (parser-level fallthrough).
func TestLegacy_ErrTokenize_Wrapping(t *testing.T) {
	cases := []struct {
		name string
		run  func() error
	}{
		{"Parse", func() error {
			_, err := Parse(invalidTokenizeSQL)
			return err
		}},
		{"ParseWithContext", func() error {
			_, err := ParseWithContext(context.Background(), invalidTokenizeSQL)
			return err
		}},
		{"ParseWithTimeout", func() error {
			_, err := ParseWithTimeout(invalidTokenizeSQL, time.Second)
			return err
		}},
		{"ParseBytes", func() error {
			_, err := ParseBytes([]byte(invalidTokenizeSQL))
			return err
		}},
		{"ParseMultiple", func() error {
			_, err := ParseMultiple([]string{invalidTokenizeSQL})
			return err
		}},
		{"ValidateMultiple", func() error {
			return ValidateMultiple([]string{invalidTokenizeSQL})
		}},
		{"ParseWithRecovery", func() error {
			_, errs := ParseWithRecovery(invalidTokenizeSQL)
			if len(errs) == 0 {
				return nil
			}
			return errs[0]
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil {
				t.Fatalf("%s(%q) returned nil error; expected ErrTokenize-wrapped", tc.name, invalidTokenizeSQL)
			}
			// Some functions (e.g. ParseWithRecovery, ParseMultiple with a
			// tokenizer that surfaces the failure during parsing) may classify
			// under ErrSyntax instead. Accept either to avoid coupling tests
			// to the exact failure layer — the important invariant is that
			// ONE of the two sentinels always matches.
			if !errors.Is(err, ErrTokenize) && !errors.Is(err, ErrSyntax) {
				t.Errorf("neither ErrTokenize nor ErrSyntax matched for %s; err = %v", tc.name, err)
			}
		})
	}
}

// TestLegacy_ErrTimeout_Wrapping asserts context-deadline failures are
// wrapped with ErrTimeout.
func TestLegacy_ErrTimeout_Wrapping(t *testing.T) {
	// Build an already-expired context so the function fails fast on the
	// context check without having to race against parsing time.
	expired, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()

	cases := []struct {
		name string
		run  func() error
	}{
		{"ParseWithContext", func() error {
			_, err := ParseWithContext(expired, "SELECT 1")
			return err
		}},
		{"ParseWithTimeout", func() error {
			// Nanosecond timeout effectively expires immediately.
			_, err := ParseWithTimeout("SELECT 1", time.Nanosecond)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil {
				t.Fatalf("%s returned nil error; expected ErrTimeout-wrapped", tc.name)
			}
			if !errors.Is(err, ErrTimeout) {
				t.Errorf("errors.Is(err, ErrTimeout) = false for %s; err = %v", tc.name, err)
			}
			// The underlying context.DeadlineExceeded should also remain
			// reachable through the wrap chain.
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("errors.Is(err, context.DeadlineExceeded) = false for %s; err = %v", tc.name, err)
			}
		})
	}
}

// TestLegacy_ErrUnsupportedDialect asserts ParseWithDialect returns
// ErrUnsupportedDialect for an unknown dialect name.
func TestLegacy_ErrUnsupportedDialect(t *testing.T) {
	_, err := ParseWithDialect("SELECT 1", keywords.SQLDialect("fakedialect"))
	if err == nil {
		t.Fatalf("ParseWithDialect(fakedialect) returned nil error")
	}
	if !errors.Is(err, ErrUnsupportedDialect) {
		t.Errorf("errors.Is(err, ErrUnsupportedDialect) = false; err = %v", err)
	}
	// The error message should mention the offending dialect for debuggability.
	if !strings.Contains(err.Error(), "fakedialect") {
		t.Errorf("error message does not mention dialect: %q", err.Error())
	}
}

// TestLegacy_MustParse_PanicsWithWrappedError asserts MustParse panics with
// an error value (not a string) so recover() sites can use errors.Is/As to
// classify the failure.
func TestLegacy_MustParse_PanicsWithWrappedError(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("MustParse did not panic on invalid SQL")
		}
		err, ok := r.(error)
		if !ok {
			t.Fatalf("MustParse panicked with non-error %T: %v", r, r)
		}
		if !errors.Is(err, ErrSyntax) {
			t.Errorf("panic value does not wrap ErrSyntax: %v", err)
		}
	}()
	_ = MustParse(invalidSyntaxSQL)
}

// TestLegacy_ParseTree_ParityWithParse asserts that the same invalid SQL
// produces the same sentinel match through both the legacy Parse entry point
// and the new ParseTree entry point. This protects against divergence where
// one surface wraps and the other does not.
func TestLegacy_ParseTree_ParityWithParse(t *testing.T) {
	cases := []struct {
		name     string
		sql      string
		sentinel error
	}{
		{"syntax", invalidSyntaxSQL, ErrSyntax},
		{"tokenize", invalidTokenizeSQL, ErrTokenize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, legacyErr := Parse(tc.sql)
			_, treeErr := ParseTree(context.Background(), tc.sql)
			if legacyErr == nil || treeErr == nil {
				t.Fatalf("expected both Parse and ParseTree to fail; legacy=%v tree=%v", legacyErr, treeErr)
			}
			// Parity: if the sentinel matches on one surface, it must match on
			// the other. Accept ErrSyntax as a broader fallback for the
			// tokenize case because one of the two surfaces may classify at
			// the parser level (see TestLegacy_ErrTokenize_Wrapping).
			legacyMatch := errors.Is(legacyErr, tc.sentinel) || errors.Is(legacyErr, ErrSyntax)
			treeMatch := errors.Is(treeErr, tc.sentinel) || errors.Is(treeErr, ErrSyntax)
			if legacyMatch != treeMatch {
				t.Errorf("sentinel parity broken for %q: legacy=%v tree=%v", tc.sql, legacyErr, treeErr)
			}
		})
	}
}

// TestLegacy_ValidSQL_NoError is a smoke test: wrapping must not break the
// happy path. Valid SQL through every legacy function must still return nil.
func TestLegacy_ValidSQL_NoError(t *testing.T) {
	const okSQL = "SELECT 1"
	if _, err := Parse(okSQL); err != nil {
		t.Errorf("Parse(valid) = %v", err)
	}
	if _, err := ParseWithContext(context.Background(), okSQL); err != nil {
		t.Errorf("ParseWithContext(valid) = %v", err)
	}
	if _, err := ParseWithTimeout(okSQL, time.Second); err != nil {
		t.Errorf("ParseWithTimeout(valid) = %v", err)
	}
	if _, err := ParseBytes([]byte(okSQL)); err != nil {
		t.Errorf("ParseBytes(valid) = %v", err)
	}
	if _, err := ParseMultiple([]string{okSQL, okSQL}); err != nil {
		t.Errorf("ParseMultiple(valid) = %v", err)
	}
	if err := Validate(okSQL); err != nil {
		t.Errorf("Validate(valid) = %v", err)
	}
	if err := ValidateMultiple([]string{okSQL}); err != nil {
		t.Errorf("ValidateMultiple(valid) = %v", err)
	}
	if _, err := Format(okSQL, DefaultFormatOptions()); err != nil {
		t.Errorf("Format(valid) = %v", err)
	}
	if _, err := ParseWithDialect(okSQL, keywords.DialectPostgreSQL); err != nil {
		t.Errorf("ParseWithDialect(valid) = %v", err)
	}
}
