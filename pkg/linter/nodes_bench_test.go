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

package linter_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

var nodeTestDialects = []string{"postgresql", "mysql", "mariadb", "sqlserver", "oracle", "sqlite", "snowflake", "clickhouse"}

type lintCorpusInput struct{ name, sql string }

// lintCorpusInputs includes complete files and semicolon-newline delimited
// statements, matching the original differential verifier's splitting.
// Generic corpus files are exercised under every dialect as well.
func lintCorpusInputs(tb testing.TB, dialect string, corpus bool) []lintCorpusInput {
	tb.Helper()
	roots := []string{filepath.Join("..", "..", "testdata", "realworld", dialect)}
	if corpus {
		roots = append(roots, filepath.Join("..", "..", "testdata", "corpus"))
	}
	var inputs []lintCorpusInput
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || filepath.Ext(path) != ".sql" {
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			name := filepath.ToSlash(strings.TrimPrefix(path, "../../testdata/"))
			inputs = append(inputs, lintCorpusInput{name + "/file", string(content)})
			for i, statement := range strings.Split(string(content), ";\n") {
				if statement = strings.TrimSpace(statement); statement != "" {
					inputs = append(inputs, lintCorpusInput{fmt.Sprintf("%s/stmt/%d", name, i), statement})
				}
			}
			return nil
		})
		if err != nil {
			tb.Fatal(err)
		}
	}
	if len(inputs) == 0 {
		tb.Fatal("no SQL corpus inputs found")
	}
	return inputs
}

// BenchmarkLintWithDialect measures end-to-end linting of each dialect's
// realworld statements, using the original verification harness workload.
func BenchmarkLintWithDialect(b *testing.B) {
	for _, dialect := range nodeTestDialects {
		var statements []string
		for _, input := range lintCorpusInputs(b, dialect, false) {
			if strings.Contains(input.name, "/stmt/") {
				statements = append(statements, input.sql)
			}
		}
		b.Run(dialect, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for _, sql := range statements {
					_, _ = gosqlx.LintWithDialect(sql, keywords.SQLDialect(dialect))
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*len(statements)), "ns/stmt")
		})
	}
}
