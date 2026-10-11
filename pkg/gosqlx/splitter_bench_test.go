// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gosqlx

import (
	"strings"
	"testing"
)

// splitBenchSink prevents the compiler from eliding the benchmarked call.
var splitBenchSink []string

// splitBenchScript builds a deterministic ~200-statement script mixing quoted
// semicolons, line comments and block comments. When dollar is true, every
// fourth statement carries a PostgreSQL dollar-quoted body containing ';'.
func splitBenchScript(dollar bool) string {
	var sb strings.Builder
	for i := 0; i < 200; i++ {
		switch i % 4 {
		case 0:
			sb.WriteString("SELECT id, name FROM users WHERE id = 1 AND note = 'a;b';\n")
		case 1:
			sb.WriteString("INSERT INTO t (a, b) VALUES (1, 'x'); -- trailing ; comment\n")
		case 2:
			sb.WriteString("/* block ; comment */ UPDATE t SET a = 2 WHERE b = 'y';\n")
		case 3:
			if dollar {
				sb.WriteString("DELETE FROM t WHERE c = $$dollar;quoted$$;\n")
			} else {
				sb.WriteString("DELETE FROM t WHERE c = 'plain;quoted';\n")
			}
		}
	}
	return sb.String()
}

// BenchmarkSplitStatements measures statement splitting per dialect profile.
// Segments are substrings of the input, so the only allocation is the result
// slice (1 alloc/op).
func BenchmarkSplitStatements(b *testing.B) {
	profiles := []struct {
		name    string
		dialect string
		dollar  bool
	}{
		{"ansi", "", false},
		{"postgresql", "postgresql", true},
		{"mysql", "mysql", false},
		{"sqlserver", "sqlserver", false},
	}
	for _, p := range profiles {
		src := splitBenchScript(p.dollar)
		b.Run(p.name, func(b *testing.B) {
			b.SetBytes(int64(len(src)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				splitBenchSink = SplitStatements(src, p.dialect)
			}
		})
	}
}
