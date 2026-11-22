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

func TestWatchProcessesChangedFiles(t *testing.T) {
	for _, mode := range []WatchMode{WatchModeValidate, WatchModeFormat} {
		t.Run(string(mode), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "query.sql")
			var out, stderr bytes.Buffer
			fw, err := NewFileWatcher(WatchOptions{Mode: mode, Out: &out, Err: &stderr})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := fw.Close(); err != nil {
					t.Error(err)
				}
			}()
			write := func(sql string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(sql), 0600); err != nil {
					t.Fatal(err)
				}
			}
			write("SELECT 1")
			fw.processFile(path)
			out.Reset()
			stderr.Reset()
			changed := "-- keep this comment\nselect a from t where a=1"
			write(changed)
			fw.processFile(path)
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if stderr.Len() != 0 {
				t.Fatalf("unexpected error: %s", &stderr)
			}
			if mode == WatchModeValidate {
				if !strings.Contains(out.String(), " - Valid") {
					t.Fatalf("missing validation: %s", &out)
				}
				if string(content) != changed {
					t.Fatal("validation modified input")
				}
			} else {
				if !strings.Contains(out.String(), " - Formatted") {
					t.Fatalf("missing formatting: %s", &out)
				}
				if string(content) == changed || !strings.Contains(string(content), "SELECT") || !strings.Contains(string(content), "-- keep this comment") {
					t.Fatalf("not formatted faithfully: %s", content)
				}
				out.Reset()
				fw.processFile(path)
				if !strings.Contains(out.String(), "No changes needed") {
					t.Fatalf("formatting not stable: %s", &out)
				}
			}
			out.Reset()
			stderr.Reset()
			invalid := "SELECT * FROM"
			write(invalid)
			fw.processFile(path)
			content, err = os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(content) != invalid {
				t.Fatalf("invalid input changed: %q", content)
			}
			if stderr.Len() == 0 {
				t.Fatalf("missing syntax error, stdout: %s", &out)
			}
		})
	}
}

func TestWatchFormatRefusesUnplaceableHint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hint.sql")
	original := "select a from /*+ FULL(t) */ t"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	fw, err := NewFileWatcher(WatchOptions{Mode: WatchModeFormat, Out: &out, Err: &stderr})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fw.Close(); err != nil {
			t.Error(err)
		}
	}()
	fw.processFile(path)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != original || stderr.Len() == 0 {
		t.Fatalf("content=%q stderr=%q", content, stderr.String())
	}
}

func TestWatchRespectsDialect(t *testing.T) {
	for _, mode := range []WatchMode{WatchModeValidate, WatchModeFormat} {
		t.Run(string(mode), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "batch.sql")
			source := "select 1\nGO\nselect 2"
			if err := os.WriteFile(path, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			var out, stderr bytes.Buffer
			fw, err := NewFileWatcher(WatchOptions{Mode: mode, Out: &out, Err: &stderr,
				ValidatorOpts: &ValidatorOptions{Dialect: "sqlserver"},
				FormatterOpts: &CLIFormatterOptions{Dialect: "sqlserver", Uppercase: true, IndentSize: 2},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := fw.Close(); err != nil {
					t.Error(err)
				}
			}()
			fw.processFile(path)
			if stderr.Len() != 0 {
				t.Fatalf("SQL Server batch rejected: %s", &stderr)
			}
			if out.Len() == 0 {
				t.Fatal("no processing output")
			}
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(content), "\nGO\n") {
				t.Fatalf("batch separator lost: %q", content)
			}
		})
	}
}

func TestWatchCommandDialect(t *testing.T) {
	for _, mode := range []string{"validate", "format"} {
		for _, dialect := range []string{"sqlserver", "mssql", "postgresql"} {
			t.Run(mode+"/"+dialect, func(t *testing.T) {
				resetCLIFlags()
				t.Cleanup(resetCLIFlags)
				var out, stderr bytes.Buffer
				watchCmd.SetOut(&out)
				watchCmd.SetErr(&stderr)
				t.Cleanup(func() { watchCmd.SetOut(nil); watchCmd.SetErr(nil) })
				if err := watchCmd.ParseFlags([]string{"--mode", mode, "--dialect", dialect}); err != nil {
					t.Fatal(err)
				}
				fw, err := newWatcherFromCommand(watchCmd)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := fw.Close(); err != nil {
						t.Error(err)
					}
				}()
				path := filepath.Join(t.TempDir(), "batch.sql")
				source := "select 1\nGO\nselect 2"
				if err := os.WriteFile(path, []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				fw.processFile(path)
				content, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if dialect == "postgresql" {
					if stderr.Len() == 0 {
						t.Fatalf("PostgreSQL accepted GO script: %s", &out)
					}
					if string(content) != source {
						t.Fatalf("rejected script changed: %q", content)
					}
				} else {
					if stderr.Len() != 0 {
						t.Fatalf("SQL Server rejected GO script: %s", &stderr)
					}
					if mode == "validate" && !strings.Contains(out.String(), " - Valid") {
						t.Fatalf("missing validation: %s", &out)
					}
					if mode == "format" && (!strings.Contains(string(content), "SELECT") || !strings.Contains(string(content), "\nGO\n")) {
						t.Fatalf("incorrect formatting: %q", content)
					}
				}
			})
		}
	}
}

func TestWatchCommandRejectsUnknownDialect(t *testing.T) {
	res := runCLI(t, nil, "watch", "--dialect", "invalid-dialect", t.TempDir())
	if res.err == nil || !strings.Contains(res.err.Error(), "unknown SQL dialect") {
		t.Fatalf("expected dialect error, got %v", res.err)
	}
}

func TestNewWatcherFromCommandRejectsUnknownMode(t *testing.T) {
	resetCLIFlags()
	t.Cleanup(resetCLIFlags)
	if err := watchCmd.ParseFlags([]string{"--mode", "lint"}); err != nil {
		t.Fatal(err)
	}
	if _, err := newWatcherFromCommand(watchCmd); err == nil || !strings.Contains(err.Error(), "invalid --mode") {
		t.Fatalf("expected invalid --mode error, got %v", err)
	}
}
