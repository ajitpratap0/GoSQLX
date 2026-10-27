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
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/dialectaudit"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// realworldRoot holds one directory per dialect of real-world SQL; every
// statement is run through split → parse → format → reparse → reformat.
var realworldRoot = filepath.Join("..", "..", "testdata", "realworld")

var updateKnownFailures = flag.Bool("update-known-failures", false,
	"rewrite testdata/realworld/known_failures.txt from the current results")

// TestRealWorldCorpus is a ratchet: a statement must pass every stage unless
// it is listed in testdata/realworld/known_failures.txt, and a listed
// statement that now passes fails the test so the list only ever shrinks.
func TestRealWorldCorpus(t *testing.T) {
	dirs, err := os.ReadDir(realworldRoot)
	if os.IsNotExist(err) {
		t.Skip("testdata/realworld not present")
	}
	if err != nil {
		t.Fatalf("read %s: %v", realworldRoot, err)
	}
	// After every statement has been parsed, formatted and re-parsed, the
	// shared read-only stand-ins returned by the DialectExtras/DialectModifiers
	// accessors must still be empty: a write through one would leak into every
	// AST that lacks its own extras.
	t.Cleanup(func() { assertDialectStandInsUntouched(t) })
	known := loadKnownFailures(t)
	seen := map[string]bool{}
	var current []string // "key stage" for every failing statement

	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		dialect := d.Name()
		if !keywords.IsValidDialect(dialect) {
			t.Errorf("testdata/realworld/%s: not a valid dialect name", dialect)
			continue
		}
		files, err := realworldSQLFiles(filepath.Join(realworldRoot, dialect))
		if err != nil {
			t.Fatalf("corpus dialect %s: %v", dialect, err)
		}
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read %s: %v", file, err)
			}
			base := dialect + "/" + filepath.Base(file)
			for i, stmt := range SplitStatements(string(data), dialect) {
				if onlyComments(stmt) {
					continue
				}
				key := fmt.Sprintf("%s#%d", base, i)
				seen[key] = true
				result := dialectaudit.Check(stmt, keywords.SQLDialect(dialect), ParseWithDialect, func(tree *ast.AST) string { return FormatAST(tree) })
				stage, detail := result.Stage, result.Error
				if result.Format != "" {
					detail += "\n  formatted: " + compact(result.Format)
				}
				if stage != "ok" {
					current = append(current, key+" "+stage)
				}
				if *updateKnownFailures {
					continue
				}
				want, isKnown := known[key]
				switch {
				case stage == "ok" && isKnown:
					t.Errorf("%s now passes; remove it from known_failures.txt (was %q)", key, want)
				case stage != "ok" && !isKnown:
					t.Errorf("%s failed at %s: %s\n  sql: %s", key, stage, detail, compact(stmt))
				case stage != "ok" && stage != want:
					t.Errorf("%s failure stage changed %s → %s: %s", key, want, stage, detail)
				}
			}
		}
	}

	if *updateKnownFailures {
		writeKnownFailures(t, current)
		return
	}

	var stale []string
	for key := range known {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		t.Errorf("known_failures.txt lists %s, which no longer exists", key)
	}
}

func realworldSQLFiles(dir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		return nil, fmt.Errorf("glob %s: %w", dir, err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s: no .sql files", dir)
	}
	return files, nil
}

func TestRealworldSQLFilesRejectsMissingCorpus(t *testing.T) {
	for _, dir := range []string{t.TempDir(), "["} {
		if _, err := realworldSQLFiles(dir); err == nil {
			t.Errorf("realworldSQLFiles(%q) succeeded", dir)
		}
	}
}

func writeKnownFailures(t *testing.T, lines []string) {
	t.Helper()
	sort.Strings(lines)
	header := "# Real-world corpus statements that GoSQLX does not yet handle.\n" +
		"# Format: <dialect>/<file>#<statement index> <failing stage>\n" +
		"# Stages: parse, reparse, idempotent, drop (formatter lost words), panic.\n" +
		"# Indexes shift when statements are added to or removed from a file: regenerate then.\n" +
		"# Regenerate: go test ./pkg/gosqlx -run TestRealWorldCorpus -update-known-failures\n"
	data := header + strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(realworldRoot, "known_failures.txt"), []byte(data), 0o644); err != nil {
		t.Fatalf("write known_failures.txt: %v", err)
	}
	t.Logf("wrote %d known failures", len(lines))
}

// loadKnownFailures reads "dialect/file.sql#N stage  # reason" lines.
func loadKnownFailures(t *testing.T) map[string]string {
	t.Helper()
	known := map[string]string{}
	f, err := os.Open(filepath.Join(realworldRoot, "known_failures.txt"))
	if os.IsNotExist(err) {
		return known
	}
	if err != nil {
		t.Fatalf("open known_failures.txt: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i == 0 {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			t.Errorf("known_failures.txt: malformed entry %q (want \"file.sql#N stage\")", sc.Text())
			continue
		}
		if _, dup := known[fields[0]]; dup {
			t.Errorf("known_failures.txt: duplicate entry %s", fields[0])
		}
		known[fields[0]] = fields[1]
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan known_failures.txt: %v", err)
	}
	return known
}

func onlyComments(s string) bool { return dialectaudit.Empty(s) }

func compact(s string) string { return dialectaudit.Compact(s) }

func assertDialectStandInsUntouched(t *testing.T) {
	t.Helper()
	checks := []struct {
		name      string
		got, want any
	}{
		{"FunctionCall", *(&ast.FunctionCall{}).DialectExtras(), ast.FunctionExtras{}},
		{"BinaryExpression", *(&ast.BinaryExpression{}).DialectExtras(), ast.BinaryExtras{}},
		{"InsertStatement", *(&ast.InsertStatement{}).DialectExtras(), ast.InsertDialectFields{}},
		{"UpdateStatement", *(&ast.UpdateStatement{}).DialectExtras(), ast.DMLTargetFields{}},
		{"DeleteStatement", *(&ast.DeleteStatement{}).DialectExtras(), ast.DMLTargetFields{}},
		{"SelectStatement", *(&ast.SelectStatement{}).DialectExtras(), ast.SelectExtras{}},
		{"TableReference", *(&ast.TableReference{}).DialectModifiers(), ast.TableModifiers{}},
		{"LiteralValue", (&ast.LiteralValue{}).DialectExtras(), ast.LiteralExtras{}},
	}
	for _, c := range checks {
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("%s: shared read-only dialect stand-in was mutated: %+v", c.name, c.got)
		}
	}
}
