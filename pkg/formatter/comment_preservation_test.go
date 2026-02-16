package formatter

import (
	"strings"
	"testing"
)

func TestFormat_LineCommentPreservation(t *testing.T) {
	f := New(Options{Compact: true})

	t.Run("leading line comment", func(t *testing.T) {
		input := "-- header comment\nSELECT col FROM t"
		result, err := f.Format(input)
		if err != nil {
			t.Fatalf("Format() error = %v", err)
		}
		if !strings.Contains(result, "-- header comment") {
			t.Errorf("Expected leading comment preserved, got: %s", result)
		}
		if !strings.Contains(result, "SELECT") || !strings.Contains(result, "col") {
			t.Errorf("Expected SQL preserved, got: %s", result)
		}
	})

	t.Run("trailing line comment", func(t *testing.T) {
		input := "SELECT col FROM t -- trailing"
		result, err := f.Format(input)
		if err != nil {
			t.Fatalf("Format() error = %v", err)
		}
		if !strings.Contains(result, "-- trailing") {
			t.Errorf("Expected trailing comment preserved, got: %s", result)
		}
	})
}

func TestFormat_BlockCommentPreservation(t *testing.T) {
	f := New(Options{Compact: true})

	t.Run("leading block comment", func(t *testing.T) {
		input := "/* header */\nSELECT col FROM t"
		result, err := f.Format(input)
		if err != nil {
			t.Fatalf("Format() error = %v", err)
		}
		if !strings.Contains(result, "/* header */") {
			t.Errorf("Expected block comment preserved, got: %s", result)
		}
	})

	t.Run("inline block comment", func(t *testing.T) {
		input := "SELECT /* inline */ col FROM t"
		result, err := f.Format(input)
		if err != nil {
			t.Fatalf("Format() error = %v", err)
		}
		if !strings.Contains(result, "/* inline */") {
			t.Errorf("Expected inline block comment preserved, got: %s", result)
		}
	})
}

func TestFormat_CommentRoundTrip(t *testing.T) {
	f := New(Options{Compact: true})

	inputs := []string{
		"-- header\nSELECT col FROM t",
		"SELECT col FROM t -- trailing",
		"/* block */ SELECT col FROM t",
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			first, err := f.Format(input)
			if err != nil {
				t.Fatalf("First format error: %v", err)
			}
			second, err := f.Format(first)
			if err != nil {
				t.Fatalf("Second format error: %v", err)
			}
			if first != second {
				t.Errorf("Round-trip mismatch:\n  first:  %q\n  second: %q", first, second)
			}
		})
	}
}

func TestFormat_MultipleComments(t *testing.T) {
	f := New(Options{Compact: true})

	input := "-- first comment\n-- second comment\nSELECT col FROM t"
	result, err := f.Format(input)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	if !strings.Contains(result, "-- first comment") {
		t.Errorf("Expected first comment, got: %s", result)
	}
	if !strings.Contains(result, "-- second comment") {
		t.Errorf("Expected second comment, got: %s", result)
	}
}
