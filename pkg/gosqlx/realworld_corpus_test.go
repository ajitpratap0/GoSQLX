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
	"sort"
	"strings"
	"testing"

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
		files, _ := filepath.Glob(filepath.Join(realworldRoot, dialect, "*.sql"))
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
				stage, detail := realworldCheck(stmt, keywords.SQLDialect(dialect))
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

func realworldCheck(stmt string, d keywords.SQLDialect) (stage, detail string) {
	defer func() {
		if p := recover(); p != nil {
			stage, detail = "panic", fmt.Sprint(p)
		}
	}()
	tree, err := ParseWithDialect(stmt, d)
	if err != nil {
		return "parse", err.Error()
	}
	f1 := FormatAST(tree)
	tree2, err := ParseWithDialect(f1, d)
	if err != nil {
		return "reparse", err.Error() + "\n  formatted: " + compact(f1)
	}
	if f2 := FormatAST(tree2); f2 != f1 {
		return "idempotent", compact(f1) + "\n  != " + compact(f2)
	}
	if lost := realworldDroppedWords(stmt, f1); len(lost) > 0 {
		return "drop", "formatter lost " + strings.Join(lost, " ") + "\n  formatted: " + compact(f1)
	}
	return "ok", ""
}

// realworldDroppedWords reports words of the input (outside comments and string
// literals) that are missing from the formatted output — a cheap detector for
// clauses the formatter silently drops even though its output reparses.
func realworldDroppedWords(in, out string) []string {
	have := map[string]bool{}
	for _, w := range realworldWords(out) {
		have[w] = true
	}
	var lost []string
	seen := map[string]bool{}
	for _, w := range realworldWords(in) {
		if !have[w] && !realworldIgnorable[w] && !seen[w] {
			seen[w] = true
			lost = append(lost, w)
		}
	}
	return lost
}

// realworldIgnorable are noise words the formatter may legitimately add or drop.
var realworldIgnorable = map[string]bool{"AS": true, "ASC": true, "INNER": true, "OUTER": true}

// realworldWords returns the upper-cased identifier-like words of s, skipping
// comments and quoted string literals but keeping quoted identifiers' text.
func realworldWords(s string) []string {
	var words []string
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return words
			}
			i += end + 4
		case c == '\'':
			for i++; i < len(s); i++ {
				if s[i] == '\\' {
					i++
					continue
				}
				if s[i] == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						i++
						continue
					}
					break
				}
			}
			i++
		case c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= 0x80:
			j := i
			for j < len(s) && (s[j] == '_' || s[j] == '$' || s[j] >= '0' && s[j] <= '9' ||
				s[j] >= 'A' && s[j] <= 'Z' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= 0x80) {
				j++
			}
			words = append(words, strings.ToUpper(s[i:j]))
			i = j
		case c >= '0' && c <= '9':
			for i < len(s) && (s[i] == '.' || s[i] == '_' || s[i] >= '0' && s[i] <= '9' ||
				s[i] >= 'A' && s[i] <= 'Z' || s[i] >= 'a' && s[i] <= 'z') {
				i++
			}
		default:
			i++
		}
	}
	return words
}

func writeKnownFailures(t *testing.T, lines []string) {
	t.Helper()
	sort.Strings(lines)
	header := "# Real-world corpus statements that GoSQLX does not yet handle.\n" +
		"# Format: <dialect>/<file>#<statement index> <failing stage>\n" +
		"# Stages: parse, reparse, idempotent, drop (formatter lost words), panic.\n" +
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
		if len(fields) != 2 {
			continue
		}
		known[fields[0]] = fields[1]
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan known_failures.txt: %v", err)
	}
	return known
}

func onlyComments(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "--") {
			return false
		}
	}
	return true
}

func compact(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}
