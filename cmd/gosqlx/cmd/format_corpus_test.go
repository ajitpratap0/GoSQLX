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
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// corpusFormatKnownGaps lists corpus files (relative to testdata) whose
// formatted output does not yet round-trip because of a pkg/formatter or SQL()
// rendering gap. For these the CLI must refuse to format (return an error)
// rather than emit changed SQL; once the gap is fixed they simply pass.
var corpusFormatKnownGaps = map[string]string{
	"corpus/orm/gorm_joins.sql":      "follow-up: a name quoted only for case (\"Company\") renders bare; the AST does not record quoting, so the CLI refuses",
	"mssql/13_cross_apply.sql":       "follow-up: CROSS APPLY rendered as CROSS APPLY JOIN, TOP lost in derived table",
	"mssql/14_outer_apply.sql":       "follow-up: OUTER APPLY rendered as OUTER APPLY JOIN, TOP lost in derived table",
	"mysql/29_full_text_search.sql":  "follow-up: MATCH ... AGAINST rendered as AGAINST AGAINST(...)",
	"oracle/08_connect_by_path.sql":  "follow-up: START WITH / CONNECT BY not rendered",
	"oracle/19_regexp_functions.sql": "follow-up: string literal backslashes doubled for a dialect that keeps them literal",
}

// corpusDialect maps a testdata path to the dialect its SQL is written in.
func corpusDialect(rel string) string {
	p := "/" + rel
	switch {
	case strings.Contains(p, "/mssql/"):
		return "sqlserver"
	case strings.Contains(p, "/mysql/"):
		return "mysql"
	case strings.Contains(p, "/oracle/"):
		return "oracle"
	case strings.Contains(p, "/postgresql/"):
		return "postgresql"
	default:
		return ""
	}
}

// TestFormatSQL_CorpusRoundTrip formats every parseable testdata/**/*.sql file
// with the CLI formatter in several modes and requires that the output
// re-parses to an equivalent tree and formats idempotently (#599).
func TestFormatSQL_CorpusRoundTrip(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata")
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".sql") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	sort.Strings(files)

	modes := []struct {
		name string
		opts CLIFormatterOptions
	}{
		{"readable-upper", CLIFormatterOptions{IndentSize: 2, Uppercase: true}},
		{"compact-upper", CLIFormatterOptions{Compact: true, Uppercase: true}},
		{"readable-lower", CLIFormatterOptions{IndentSize: 4, Uppercase: false}},
	}

	parsed := 0
	for _, path := range files {
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatalf("relative path for %s: %v", path, err)
		}
		rel := filepath.ToSlash(relPath)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", rel, err)
		}
		input := strings.ReplaceAll(string(data), "\r\n", "\n")
		dialect := corpusDialect(rel)

		orig, err := parseWithDialect(t, input, dialect)
		if err != nil || len(orig.Statements) == 0 {
			if orig != nil {
				ast.ReleaseAST(orig)
			}
			continue // the corpus also holds inputs the parser does not support yet
		}
		parsed++
		origSQL := orig.SQL()
		origCount := len(orig.Statements)
		ast.ReleaseAST(orig)

		for _, m := range modes {
			opts := m.opts
			opts.Dialect = dialect
			out, err := formatWith(input, opts)
			if err != nil {
				if reason, ok := corpusFormatKnownGaps[rel]; ok {
					t.Logf("%s [%s]: known gap (%s): %v", rel, m.name, reason, err)
					continue
				}
				t.Errorf("%s [%s]: format failed: %v", rel, m.name, err)
				continue
			}
			// The parser does not yet accept every lowercase keyword sequence
			// (e.g. "returning", "cross join lateral"), so lowercase output is
			// checked through its uppercase-keyword twin, mirroring the CLI's
			// own verification: the two must differ only in case.
			checkText, checkOpts := out, opts
			if !opts.Uppercase {
				checkOpts.Uppercase = true
				twin, err := formatWith(input, checkOpts)
				if err != nil {
					t.Errorf("%s [%s]: uppercase twin failed: %v", rel, m.name, err)
					continue
				}
				if !strings.EqualFold(out, twin) {
					t.Errorf("%s [%s]: output differs from its uppercase twin beyond keyword case\nlower:\n%s\nupper:\n%s", rel, m.name, out, twin)
					continue
				}
				checkText = twin
			}
			checkCorpusOutput(t, rel, m.name, checkText, dialect, origSQL, origCount)
			again, err := formatWith(checkText, checkOpts)
			if err != nil {
				t.Errorf("%s [%s]: re-formatting output failed: %v", rel, m.name, err)
				continue
			}
			if again != checkText {
				t.Errorf("%s [%s]: formatting is not idempotent\nfirst:\n%s\nsecond:\n%s", rel, m.name, checkText, again)
			}
		}
	}
	if parsed < 100 {
		t.Fatalf("only %d corpus files parsed; expected at least 100 (is testdata missing?)", parsed)
	}
	t.Logf("formatted %d parseable corpus files in %d modes", parsed, len(modes))
}

// checkCorpusOutput independently re-parses out and compares it with the
// original input's statement count and SQL().
func checkCorpusOutput(t *testing.T, rel, mode, out, dialect, origSQL string, origCount int) {
	t.Helper()
	reparsed, err := parseWithDialect(t, out, dialect)
	if err != nil {
		t.Errorf("%s [%s]: output does not re-parse: %v\noutput:\n%s", rel, mode, err, out)
		return
	}
	defer ast.ReleaseAST(reparsed)
	if len(reparsed.Statements) != origCount {
		t.Errorf("%s [%s]: statement count changed: %d -> %d", rel, mode, origCount, len(reparsed.Statements))
		return
	}
	if got := reparsed.SQL(); !strings.EqualFold(got, origSQL) {
		t.Errorf("%s [%s]: output changes the query\n original SQL(): %s\nreparsed SQL(): %s", rel, mode, origSQL, got)
	}
}
