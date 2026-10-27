// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunInvalidDialect(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-dialect", "typo"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "invalid SQL dialect") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunJSONFailuresOnly(t *testing.T) {
	for _, tc := range []struct {
		sql      string
		code     int
		failures int
	}{
		{"/* block only */; SELECT 1; -- line only", 0, 0},
		{"SELECT 1; SELECT FROM", 1, 1},
	} {
		file := filepath.Join(t.TempDir(), "input.sql")
		if err := os.WriteFile(file, []byte(tc.sql), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := run([]string{"-json", "-v", file}, &stdout, &stderr); code != tc.code {
			t.Fatalf("exit=%d stderr=%s", code, &stderr)
		}
		lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
		if tc.failures == 0 {
			if stdout.Len() != 0 {
				t.Fatalf("stdout=%q", stdout.String())
			}
			continue
		}
		if len(lines) != tc.failures {
			t.Fatalf("stdout=%q", stdout.String())
		}
		for _, line := range lines {
			var r result
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				t.Fatal(err)
			}
			if r.Stage == "ok" || r.Stage == "empty" {
				t.Fatalf("passing JSON result: %+v", r)
			}
		}
	}
}
