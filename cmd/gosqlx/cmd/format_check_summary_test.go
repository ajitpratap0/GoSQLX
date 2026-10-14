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

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFormat_CheckSummaryOmitsFailedFiles checks that --check does not claim
// every file is properly formatted when some files failed the check.
func TestFormat_CheckSummaryOmitsFailedFiles(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.sql")
	bad := filepath.Join(dir, "bad.sql")
	// EXPLAIN is refused by the formatter, so bad.sql always fails.
	if err := os.WriteFile(good, []byte("SELECT a FROM t"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("EXPLAIN VERBOSE DELETE FROM users"), 0600); err != nil {
		t.Fatal(err)
	}

	var out, errBuf bytes.Buffer
	f := NewFormatter(&out, &errBuf, CLIFormatterOptions{Check: true, Compact: true, Uppercase: true})
	res, err := f.Format([]string{good, bad})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if res.FailedFiles != 1 {
		t.Fatalf("FailedFiles = %d, want 1 (stderr: %s)", res.FailedFiles, errBuf.String())
	}
	if strings.Contains(out.String(), "properly formatted") {
		t.Fatalf("check summary claims files are properly formatted although one failed:\n%s", out.String())
	}

	// With no failures the summary is still printed.
	out.Reset()
	errBuf.Reset()
	f = NewFormatter(&out, &errBuf, CLIFormatterOptions{Check: true, Compact: true, Uppercase: true})
	if _, err := f.Format([]string{good}); err != nil {
		t.Fatalf("Format: %v (stderr: %s)", err, errBuf.String())
	}
	if !strings.Contains(out.String(), "All 1 files are properly formatted") {
		t.Fatalf("missing check summary, got stdout %q", out.String())
	}
}
