package main

import (
	"os"
	"strings"
	"testing"
)

// TestReadmeQuickstartMatchesSource fails when the fenced go block under
// "## Quick start" in README.md drifts from main.go, so the snippet readers
// copy is always the file that CI compiles.
func TestReadmeQuickstartMatchesSource(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}

	text := strings.ReplaceAll(string(readme), "\r\n", "\n")
	_, after, found := strings.Cut(text, "\n## Quick start\n")
	if !found {
		t.Fatal("README.md has no '## Quick start' section")
	}
	// Restrict the search to this section.
	if i := strings.Index(after, "\n## "); i >= 0 {
		after = after[:i]
	}
	_, block, found := strings.Cut(after, "```go\n")
	if !found {
		t.Fatal("Quick start section has no ```go block")
	}
	block, _, found = strings.Cut(block, "\n```")
	if !found {
		t.Fatal("Quick start go block is not terminated")
	}

	want := strings.TrimSpace(strings.ReplaceAll(string(src), "\r\n", "\n"))
	if strings.TrimSpace(block) != want {
		t.Error("README.md Quick start go block differs from examples/readme_quickstart/main.go; update one to match the other")
	}
}
