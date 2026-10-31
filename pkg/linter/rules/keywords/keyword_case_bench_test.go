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

package keywords_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/keywords"
	sqlkeywords "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

var benchmarkDialects = []string{"postgresql", "mysql", "mariadb", "sqlserver", "oracle", "sqlite", "snowflake", "clickhouse"}

func benchmarkStatements(b *testing.B) map[string][]string {
	b.Helper()
	statements := make(map[string][]string)
	walkSQL(b, func(_ string, dialect string, sql string) {
		if dialect == "" {
			return
		}
		// Preserve the prototype's workload partitioning, including invalid SQL:
		// text rules also run when tokenization or parsing fails.
		for _, fragment := range strings.Split(sql, ";\n") {
			if statement := strings.TrimSpace(fragment); statement != "" {
				statements[dialect] = append(statements[dialect], statement)
			}
		}
	})
	for _, dialect := range benchmarkDialects {
		if len(statements[dialect]) == 0 {
			b.Fatalf("no statements for %s", dialect)
		}
	}
	return statements
}

// One operation scans the entire realworld corpus for the named dialect.
func BenchmarkLintRule(b *testing.B) {
	statements := benchmarkStatements(b)
	b.Run("L007", func(b *testing.B) {
		for _, dialect := range benchmarkDialects {
			b.Run(dialect, func(b *testing.B) {
				rule := keywords.NewKeywordCaseRule(keywords.CaseUpper)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					for _, sql := range statements[dialect] {
						if _, err := rule.Check(linter.NewContext(sql, "benchmark.sql")); err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	})
}

// One operation lints the entire realworld corpus for the named dialect through
// the public API. Parse errors are expected in these intentionally broad fixtures.
func BenchmarkLintWithDialect(b *testing.B) {
	statements := benchmarkStatements(b)
	for _, dialect := range benchmarkDialects {
		b.Run(dialect, func(b *testing.B) {
			d := sqlkeywords.SQLDialect(dialect)
			for _, sql := range statements[dialect] {
				_, _ = gosqlx.LintWithDialect(sql, d)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, sql := range statements[dialect] {
					if result, err := gosqlx.LintWithDialect(sql, d); result == nil {
						b.Fatalf("nil lint result: %v", err)
					}
				}
			}
		})
	}
}
