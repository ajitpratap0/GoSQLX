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
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

type formatRealworldStatement struct {
	dialect        keywords.SQLDialect
	sql            string
	commentRefusal bool
}

// BenchmarkFormatWithDialectRealworld measures one statement per operation,
// cycling through the parseable real-world corpus in sorted path order. Corpus
// discovery and preflight are outside the timer. Statements whose executable
// comments cannot be preserved remain in the workload with their expected
// refusal checked. Compare corpus hashes as well as counts across revisions.
func BenchmarkFormatWithDialectRealworld(b *testing.B) {
	statements := loadFormatRealworldStatements(b)
	options := DefaultFormatOptions()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		statement := statements[i%len(statements)]
		formatted, err := FormatWithDialect(statement.sql, options, statement.dialect)
		if statement.commentRefusal {
			if !errors.Is(err, formatter.ErrUnplaceableComment) || formatted != "" {
				b.Fatalf("format %s statement %d: expected empty output and comment refusal, got %q, %v", statement.dialect, i%len(statements), formatted, err)
			}
			continue
		}
		if err != nil {
			b.Fatalf("format %s statement %d: %v", statement.dialect, i%len(statements), err)
		}
		if formatted == "" {
			b.Fatalf("format %s statement %d returned empty SQL", statement.dialect, i%len(statements))
		}
	}
}

func loadFormatRealworldStatements(b *testing.B) []formatRealworldStatement {
	b.Helper()
	const root = "../../testdata/realworld"
	dirs, err := os.ReadDir(root) // ReadDir and Glob both return sorted paths.
	if err != nil {
		b.Fatalf("read real-world corpus: %v", err)
	}
	var statements []formatRealworldStatement
	counts := make(map[keywords.SQLDialect]int)
	skipped := 0
	refusals := 0
	options := DefaultFormatOptions()
	digest := sha256.New()
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		dialect := keywords.SQLDialect(dir.Name())
		if !keywords.IsValidDialect(string(dialect)) {
			b.Fatalf("unknown corpus dialect %q", dialect)
		}
		files, err := filepath.Glob(filepath.Join(root, dir.Name(), "*.sql"))
		if err != nil {
			b.Fatalf("find %s corpus files: %v", dialect, err)
		}
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				b.Fatalf("read %s: %v", file, err)
			}
			for _, sql := range SplitStatements(string(data), string(dialect)) {
				if onlyComments(sql) {
					continue
				}
				if !formatRealworldParseable(sql, dialect) {
					skipped++
					continue
				}
				formatted, err := FormatWithDialect(sql, options, dialect)
				commentRefusal := errors.Is(err, formatter.ErrUnplaceableComment)
				if commentRefusal {
					if formatted != "" {
						b.Fatalf("format preflight %s returned SQL alongside comment refusal: %q", file, formatted)
					}
					refusals++
				} else if err != nil || formatted == "" {
					b.Fatalf("format preflight %s: output %q, error %v", file, formatted, err)
				}
				statements = append(statements, formatRealworldStatement{dialect: dialect, sql: sql, commentRefusal: commentRefusal})
				counts[dialect]++
				if _, err := fmt.Fprintf(digest, "%s\x00%d\x00%s\x00", dialect, len(sql), sql); err != nil {
					b.Fatalf("hash corpus statement: %v", err)
				}
			}
		}
	}
	if len(statements) == 0 {
		b.Fatal("no parseable real-world statements")
	}
	b.Logf("corpus: %d statements, %d unparseable skipped, %d expected comment refusals, sha256=%x; dialect counts=%v", len(statements), skipped, refusals, digest.Sum(nil), counts)
	return statements
}

func formatRealworldParseable(sql string, dialect keywords.SQLDialect) bool {
	tree, err := ParseWithDialect(sql, dialect)
	if err != nil {
		return false
	}
	defer ast.ReleaseAST(tree)
	return true
}
