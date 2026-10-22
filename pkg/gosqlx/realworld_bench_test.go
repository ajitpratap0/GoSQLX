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
	"os"
	"path/filepath"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

type realworldStmt struct {
	dialect keywords.SQLDialect
	sql     string
}

// loadRealworldParseable returns every statement of testdata/realworld that
// currently parses in its dialect, so the benchmarks measure the user path on
// production-shaped SQL rather than on synthetic one-liners.
func loadRealworldParseable(b *testing.B) ([]realworldStmt, int64) {
	b.Helper()
	dirs, err := os.ReadDir(realworldRoot)
	if err != nil {
		b.Skipf("testdata/realworld not available: %v", err)
	}
	var stmts []realworldStmt
	var bytes int64
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		dialect := keywords.SQLDialect(d.Name())
		files, _ := filepath.Glob(filepath.Join(realworldRoot, d.Name(), "*.sql"))
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				b.Fatalf("read %s: %v", file, err)
			}
			for _, stmt := range SplitStatements(string(data), d.Name()) {
				if onlyComments(stmt) {
					continue
				}
				if _, err := ParseWithDialect(stmt, dialect); err != nil {
					continue
				}
				stmts = append(stmts, realworldStmt{dialect, stmt})
				bytes += int64(len(stmt))
			}
		}
	}
	if len(stmts) == 0 {
		b.Skip("no parseable real-world statements")
	}
	return stmts, bytes
}

// BenchmarkRealWorldParse parses the whole parseable real-world corpus once
// per iteration with the statement's own dialect.
func BenchmarkRealWorldParse(b *testing.B) {
	stmts, size := loadRealworldParseable(b)
	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, s := range stmts {
			if _, err := ParseWithDialect(s.sql, s.dialect); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkRealWorldParseFormat measures the format path users run in the
// CLI and LSP: parse with dialect, then render.
func BenchmarkRealWorldParseFormat(b *testing.B) {
	stmts, size := loadRealworldParseable(b)
	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, s := range stmts {
			tree, err := ParseWithDialect(s.sql, s.dialect)
			if err != nil {
				b.Fatal(err)
			}
			_ = FormatAST(tree)
		}
	}
}
