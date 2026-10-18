package main

import (
	"strings"
	"testing"
)

var testMetrics = metrics{
	ParseNsPerOp: 318, Hardware: "Apple M4", GoVersion: "1.27",
	Dialects: 8, SQL99Estimate: "~80–85%", Stage: "parse",
}

func TestCheckLLMS(t *testing.T) {
	ok := "- SQL dialects: 8\n- SQL-99 compliance: ~80–85% (estimated)\n- Performance: ~318 ns/op (~3.14M ops/sec) for a simple SELECT (parse stage) on Apple M4, Go 1.27. x"
	if p := checkLLMS(ok, testMetrics); len(p) != 0 {
		t.Fatalf("unexpected problems: %v", p)
	}
	seeded := strings.Replace(ok, "318 ns/op", "500 ns/op", 1)
	if p := checkLLMS(seeded, testMetrics); len(p) == 0 {
		t.Fatal("seeded llms.txt mismatch was not detected")
	}
}

func TestCheckAbout(t *testing.T) {
	cases := []struct {
		name, text string
		wantBad    bool
	}{
		{"no numbers", "High-performance SQL parser for Go", false},
		{"matching ops", "SQL parser, ~3.1M ops/sec", false},
		{"matching ns", "parses in 318 ns", false},
		{"stale ops", "SQL parser - 1.5M+ ops/sec, multi-dialect", true},
		{"stale ns", "parses in 500 ns", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(checkAbout(tc.text, testMetrics)) > 0; got != tc.wantBad {
				t.Fatalf("bad=%v, want %v", got, tc.wantBad)
			}
		})
	}
}

func TestCheckFresh(t *testing.T) {
	cases := []struct {
		name, measured, tag string
		wantBad             bool
	}{
		{"newer than tag", "2026-10-13", "2026-07-30", false},
		{"same day with timestamp", "2026-10-15T22:14:33Z", "2026-10-15", false},
		{"older than tag", "2026-07-01", "2026-07-30", true},
		{"missing date", "", "2026-07-30", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(checkFresh("x", tc.measured, tc.tag)) > 0; got != tc.wantBad {
				t.Fatalf("bad=%v, want %v", got, tc.wantBad)
			}
		})
	}
}
