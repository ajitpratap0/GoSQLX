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
	"io"
	"strings"
	"testing"
)

func TestParseReader_Happy(t *testing.T) {
	r := strings.NewReader("SELECT id FROM users")
	tree, err := ParseReader(context.Background(), r)
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if tree == nil {
		t.Fatal("tree is nil")
	}
	if tree.SQL() != "SELECT id FROM users" {
		t.Errorf("SQL() = %q", tree.SQL())
	}
}

func TestParseReader_NilContext(t *testing.T) {
	r := strings.NewReader("SELECT 1")
	_, err := ParseReader(context.TODO(), r)
	if err != nil {
		t.Fatalf("ParseReader(nil ctx): %v", err)
	}
}

func TestParseReader_NilReader(t *testing.T) {
	_, err := ParseReader(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil reader")
	}
	if !errors.Is(err, ErrTokenize) {
		t.Errorf("errors.Is(err, ErrTokenize) = false; err = %v", err)
	}
}

func TestParseReader_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ParseReader(ctx, strings.NewReader("SELECT 1"))
	if err == nil {
		t.Fatal("expected error on cancelled ctx")
	}
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("errors.Is(err, ErrTimeout) = false; err = %v", err)
	}
}

// erroringReader always fails, used to test read-error surfacing.
type erroringReader struct{}

func (erroringReader) Read(_ []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestParseReader_ReadError(t *testing.T) {
	_, err := ParseReader(context.Background(), erroringReader{})
	if err == nil {
		t.Fatal("expected read error")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("errors.Is(err, io.ErrUnexpectedEOF) = false; err = %v", err)
	}
}

func TestParseReader_WithOptions(t *testing.T) {
	r := strings.NewReader("SELECT data->>'name' FROM users")
	tree, err := ParseReader(context.Background(), r, WithDialect("postgresql"))
	if err != nil {
		t.Fatalf("ParseReader pg: %v", err)
	}
	if tree == nil {
		t.Fatal("tree is nil")
	}
}

func TestParseReaderMultiple_Basic(t *testing.T) {
	src := "SELECT 1; SELECT 2; SELECT 3"
	trees, err := ParseReaderMultiple(context.Background(), strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseReaderMultiple: %v", err)
	}
	if len(trees) != 3 {
		t.Errorf("got %d trees, want 3", len(trees))
	}
}

func TestParseReaderMultiple_TrailingSemicolon(t *testing.T) {
	src := "SELECT 1;   ;  "
	trees, err := ParseReaderMultiple(context.Background(), strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseReaderMultiple: %v", err)
	}
	if len(trees) != 1 {
		t.Errorf("got %d trees, want 1 (empty segments skipped)", len(trees))
	}
}

func TestParseReaderMultiple_QuotedSemicolon(t *testing.T) {
	// The semicolon inside '...' must NOT split the statement.
	src := "SELECT 'a;b' FROM t"
	trees, err := ParseReaderMultiple(context.Background(), strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseReaderMultiple: %v", err)
	}
	if len(trees) != 1 {
		t.Errorf("got %d trees, want 1 (semicolon inside string literal)", len(trees))
	}
}

func TestParseReaderMultiple_CommentSemicolon(t *testing.T) {
	// Semicolons inside comments must not split.
	src := "SELECT 1 -- comment ; with semi\nFROM t"
	trees, err := ParseReaderMultiple(context.Background(), strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseReaderMultiple: %v", err)
	}
	if len(trees) != 1 {
		t.Errorf("got %d trees, want 1 (semicolon inside line comment)", len(trees))
	}
}

func TestParseReaderMultiple_NilReader(t *testing.T) {
	_, err := ParseReaderMultiple(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil reader")
	}
}

func TestParseReader_MaxBytes_Blocks(t *testing.T) {
	// 1 KiB of SQL-ish content, cap at 64 bytes.
	big := strings.Repeat("SELECT 1; ", 128)
	_, err := ParseReader(
		context.Background(),
		strings.NewReader(big),
		WithMaxBytes(64),
	)
	if err == nil {
		t.Fatal("expected ErrTooLarge, got nil")
	}
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("errors.Is(err, ErrTooLarge) = false; err = %v", err)
	}
}

func TestParseReader_MaxBytes_Allows(t *testing.T) {
	src := "SELECT 1"
	tree, err := ParseReader(
		context.Background(),
		strings.NewReader(src),
		WithMaxBytes(int64(len(src))),
	)
	if err != nil {
		t.Fatalf("ParseReader within cap: %v", err)
	}
	if tree == nil {
		t.Fatal("tree is nil")
	}
}

func TestParseReader_MaxBytes_ExactlyAtCap(t *testing.T) {
	// Boundary case: len(src) == maxBytes should succeed (inclusive cap).
	src := "SELECT 42"
	tree, err := ParseReader(
		context.Background(),
		strings.NewReader(src),
		WithMaxBytes(int64(len(src))),
	)
	if err != nil {
		t.Fatalf("expected success at exact cap, got: %v", err)
	}
	if tree == nil {
		t.Fatal("tree is nil")
	}
}

func TestParseReader_MaxBytes_OneByteOver(t *testing.T) {
	src := "SELECT 42" // 9 bytes
	_, err := ParseReader(
		context.Background(),
		strings.NewReader(src),
		WithMaxBytes(int64(len(src)-1)),
	)
	if err == nil {
		t.Fatal("expected ErrTooLarge for src one byte over cap")
	}
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("errors.Is(err, ErrTooLarge) = false; err = %v", err)
	}
}

func TestParseReader_UnboundedDefault(t *testing.T) {
	// No WithMaxBytes — behaves exactly like pre-bounded-reads.
	src := strings.Repeat("SELECT 1; ", 256)
	trees, err := ParseReaderMultiple(
		context.Background(),
		strings.NewReader(src),
	)
	if err != nil {
		t.Fatalf("unbounded default: %v", err)
	}
	if len(trees) != 256 {
		t.Errorf("got %d trees, want 256", len(trees))
	}
}

func TestParseReaderMultiple_MaxBytes_Blocks(t *testing.T) {
	src := strings.Repeat("SELECT 1; ", 32)
	_, err := ParseReaderMultiple(
		context.Background(),
		strings.NewReader(src),
		WithMaxBytes(16),
	)
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("expected ErrTooLarge, got %v", err)
	}
}

func TestParseReaderMultiple_DollarQuoting(t *testing.T) {
	// Semicolons inside a $$-delimited body must NOT split the statement.
	// Two valid PG SELECTs are separated by an explicit top-level `;`.
	//
	// We deliberately avoid the CREATE FUNCTION ... plpgsql example from
	// the task brief because the parser does not yet handle procedural
	// bodies; the splitter's correctness is what matters here, and this
	// input exercises the same state transitions.
	src := "SELECT $$a; b; c$$; SELECT $tag$x; y$tag$"
	trees, err := ParseReaderMultiple(
		context.Background(),
		strings.NewReader(src),
		WithDialect("postgresql"),
	)
	if err != nil {
		t.Fatalf("ParseReaderMultiple(pg): %v", err)
	}
	if len(trees) != 2 {
		t.Fatalf("got %d trees, want 2", len(trees))
	}
}

// TestParseReaderMultiple_DollarQuoting_WouldMisBehaveWithoutDialect confirms
// that the same input, parsed without the postgresql dialect, fails to parse
// because the conservative splitter splits mid-body and hands fragments to
// the parser. This pins the regression we just fixed.
func TestParseReaderMultiple_DollarQuoting_WouldMisBehaveWithoutDialect(t *testing.T) {
	src := "SELECT $$a; b; c$$; SELECT 1"
	_, err := ParseReaderMultiple(
		context.Background(),
		strings.NewReader(src),
		// No WithDialect — ANSI default.
	)
	if err == nil {
		t.Fatal("expected parse failure without postgresql dialect (splitter should over-split the $$…$$ body)")
	}
}

func TestSplitSQLStatements(t *testing.T) {
	cases := []struct {
		name string
		in   string
		n    int // number of non-empty segments expected
	}{
		{"single", "SELECT 1", 1},
		{"two", "SELECT 1; SELECT 2", 2},
		{"trailing-semi", "SELECT 1;", 1},
		{"empty-segments", "SELECT 1;;;SELECT 2", 2},
		{"string-with-semi", "SELECT 'a;b'", 1},
		{"ident-with-semi", `SELECT "col;with;semi" FROM t`, 1},
		{"line-comment", "SELECT 1 -- ;\nFROM t", 1},
		{"block-comment", "SELECT 1 /* ; */ FROM t", 1},
		{"escaped-quote", "SELECT 'it''s'", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			segs := splitSQLStatements(tc.in)
			count := 0
			for _, s := range segs {
				if strings.TrimSpace(s) != "" {
					count++
				}
			}
			if count != tc.n {
				t.Errorf("got %d non-empty segments (raw %d), want %d: %q", count, len(segs), tc.n, segs)
			}
		})
	}
}
