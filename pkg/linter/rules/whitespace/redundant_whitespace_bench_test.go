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

package whitespace_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/whitespace"
)

var redundantWhitespaceBenchmarkSink []linter.Violation

// BenchmarkLintRule measures only Check, with IO and context creation outside
// the timer. Each dialect uses every realworld SQL fixture.
func BenchmarkLintRule(b *testing.B) {
	b.Run("L010", func(b *testing.B) {
		for _, dialect := range []string{"postgresql", "mysql", "mariadb", "sqlserver", "oracle", "sqlite", "snowflake", "clickhouse"} {
			b.Run(dialect, func(b *testing.B) {
				files, err := filepath.Glob(filepath.Join("../../../../testdata/realworld", dialect, "*.sql"))
				if err != nil {
					b.Fatal(err)
				}
				if len(files) == 0 {
					b.Fatal("empty benchmark corpus")
				}
				contexts := make([]*linter.Context, 0, len(files))
				bytes := 0
				for _, file := range files {
					data, err := os.ReadFile(file)
					if err != nil {
						b.Fatal(err)
					}
					contexts = append(contexts, &linter.Context{Lines: strings.Split(string(data), "\n")})
					bytes += len(data)
				}
				rule := whitespace.NewRedundantWhitespaceRule()
				b.SetBytes(int64(bytes))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					for _, ctx := range contexts {
						var err error
						redundantWhitespaceBenchmarkSink, err = rule.Check(ctx)
						if err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	})
}
