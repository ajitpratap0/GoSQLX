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
