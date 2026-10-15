package main

import (
	"strings"
	"testing"
)

func TestSyncBanners(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"bold version", "**Version**: v1.13.0 | **Last Updated**: 2026-03-20", "**Version**: v1.15.0 | **Last Updated**: 2026-03-20"},
		{"title", "# API Reference (v1.14.0)", "# API Reference (v1.15.0)"},
		{"bold version no v", "**Version**: 1.6.0", "**Version**: 1.15.0"},
		{"current version", "**Current Version**: v1.14.0 | x", "**Current Version**: v1.15.0 | x"},
		{"no v prefix", "**GoSQLX Version**: 1.14.0", "**GoSQLX Version**: 1.15.0"},
		{"colon inside bold", "**Version:** v1.6.0", "**Version:** v1.15.0"},
		{"colon inside bold GoSQLX", "**GoSQLX Version:** v1.6.0", "**GoSQLX Version:** v1.15.0"},
		{"history untouched", "| ✅ v1.14.0 |", "| ✅ v1.14.0 |"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := syncBanners(tc.in, "1.15.0"); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReplaceBlock(t *testing.T) {
	src := "a\n<!-- x:start -->\nold\n<!-- x:end -->\nb <!-- y:start -->old<!-- y:end -->"
	got, err := replaceBlock(src, "x", "new")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "<!-- x:start -->\nnew\n<!-- x:end -->") {
		t.Fatalf("block not replaced: %q", got)
	}
	got, err = replaceBlock(got, "y", "new")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got, "<!-- y:start -->new<!-- y:end -->") {
		t.Fatalf("inline block not replaced: %q", got)
	}
	if _, err := replaceBlock(src, "missing", "n"); err == nil {
		t.Fatal("expected error for missing markers")
	}
}

func TestParsesPerSec(t *testing.T) {
	if got := (metrics{ParseNsPerOp: 318}).parsesPerSec(); got != "~3.1M" {
		t.Fatalf("got %s", got)
	}
}
