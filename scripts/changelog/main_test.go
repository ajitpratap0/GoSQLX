// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestCollect(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		fragments         map[string]string
	}{
		{"append and sort", "intro\n\n## [Unreleased]\n\n### Added\n- old\n\n### Fixed\n- fix\n\n## [1.0] - yesterday\n\n### Added\n- released\n", "intro\n\n## [Unreleased]\n\n### Added\n- old\n- first\n- second\n\n### Fixed\n- fix\n\n## [1.0] - yesterday\n\n### Added\n- released\n", map[string]string{"b.added.md": "- second\n", "a.added.md": "- first\n"}},
		{"retain Markdown spaces", "## [Unreleased]\n\n### Fixed\n- old  \n\n## [1.0]\n", "## [Unreleased]\n\n### Fixed\n- old  \n- new  \n\n## [1.0]\n", map[string]string{"x.fixed.md": "- new  \n"}},
		{"CRLF bytes", "prefix\r\n## [Unreleased]\r\n\r\n### Fixed\r\n- old\r\n\r\n## [1.0]\r\nrelease", "prefix\r\n## [Unreleased]\r\n\r\n### Fixed\r\n- old\r\n- new\r\n\r\n## [1.0]\r\nrelease", map[string]string{"x.fixed.md": "- new\n"}},
		{"canonical missing headings", "## [Unreleased]\n\n### Added\n- old\n\n### Fixed\n- fix\n\n## [1.0]\nunchanged", "## [Unreleased]\n\n### Breaking Changes\n- break\n\n### Added\n- old\n\n### Fixed\n- fix\n\n### Security\n- secure\n\n## [1.0]\nunchanged", map[string]string{"x.breaking-changes.md": "- break\n", "x.security.md": "- secure\n"}},
		{"empty existing heading", "## [Unreleased]\n\n### Performance\n\n### Fixed\n- fix\n\n## [1.0]\n", "## [Unreleased]\n\n### Performance\n- fast\n\n### Fixed\n- fix\n\n## [1.0]\n", map[string]string{"x.performance.md": "- fast\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "CHANGELOG.md")
			fragments := filepath.Join(dir, "fragments")
			if err := os.Mkdir(fragments, 0700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, path, tc.input)
			writeFile(t, filepath.Join(fragments, "README.md"), "documentation")
			for name, body := range tc.fragments {
				writeFile(t, filepath.Join(fragments, name), body)
			}
			for i := 0; i < 2; i++ {
				if err := run([]string{"collect", "-changelog", path, "-dir", fragments}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != tc.want {
					t.Fatalf("got %q\nwant %q", got, tc.want)
				}
			}
			entries, err := os.ReadDir(fragments)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != "README.md" {
				t.Fatalf("remaining: %v", entries)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"bad.unknown.md", "- item\n", false}, {"Upper.added.md", "- item\n", false}, {"empty.added.md", "\n", false}, {"heading.added.md", "- item\n  # heading\n", false}, {"plain.added.md", "item\n", false}, {"newline.added.md", "- item", false}, {"README.md", "# Instructions", true}, {"nested.added.md", "\n- item\n  continuation\n  - nested\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, tc.name), tc.body)
			var stderr bytes.Buffer
			err := run([]string{"check", "-dir", dir}, &bytes.Buffer{}, &stderr)
			if (err == nil) != tc.valid {
				t.Fatalf("error=%v, diagnostics=%s", err, &stderr)
			}
			if !tc.valid && !strings.Contains(stderr.String(), tc.name+":") {
				t.Fatalf("missing filename: %s", &stderr)
			}
		})
	}
}

func TestPreviewAndMissingUnreleased(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		wantError   bool
	}{{"preview", "prefix\n## [Unreleased]\n\n### Added\n- old\n\n## [1.0]\nrelease\n", false}, {"missing", "## [1.0]\nrelease\n", true}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "CHANGELOG.md")
			fragments := filepath.Join(dir, "fragments")
			if err := os.Mkdir(fragments, 0700); err != nil {
				t.Fatal(err)
			}
			fragment := filepath.Join(fragments, "x.added.md")
			writeFile(t, path, tc.input)
			writeFile(t, fragment, "- new\n")
			var out bytes.Buffer
			command := "preview"
			if tc.wantError {
				command = "collect"
			}
			err := run([]string{command, "-changelog", path, "-dir", fragments}, &out, &bytes.Buffer{})
			if err == nil && tc.wantError {
				t.Fatal("expected error")
			}
			if !tc.wantError && err != nil {
				t.Fatal(err)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(got) != tc.input {
				t.Fatal("modified changelog")
			}
			if _, err := os.Stat(fragment); err != nil {
				t.Fatal(err)
			}
			if !tc.wantError && (!strings.HasPrefix(out.String(), "## [Unreleased]\n") || !strings.Contains(out.String(), "- new\n") || strings.Contains(out.String(), "## [1.0]")) {
				t.Fatalf("preview: %s", &out)
			}
		})
	}
}
