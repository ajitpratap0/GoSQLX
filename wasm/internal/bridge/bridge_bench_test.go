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

package bridge

import (
	"encoding/json"
	"strings"
	"testing"
)

// wasmBenchQueries are fixed so results stay comparable across commits.
var wasmBenchQueries = []struct{ name, sql string }{
	{"small", "SELECT id, name FROM users WHERE id = 1"},
	{"medium", "SELECT u.id, u.name, COUNT(o.id) AS orders, SUM(o.total) AS spent " +
		"FROM users u LEFT JOIN orders o ON o.user_id = u.id " +
		"WHERE u.created_at > '2024-01-01' AND u.status IN ('active', 'trial') " +
		"GROUP BY u.id, u.name HAVING COUNT(o.id) > 2 ORDER BY spent DESC LIMIT 50"},
	{"large", "SELECT " + strings.TrimSuffix(strings.Repeat("c, ", 120), ", ") +
		" FROM t WHERE " + strings.TrimSuffix(strings.Repeat("a = 1 AND ", 80), " AND ")},
}

// BenchmarkWASMBridge measures the playground entry points as wasm/main.go
// drives them, including the JSON encoding of the response. It runs natively
// (go test -bench WASMBridge ./wasm/internal/bridge) and, for the real engine,
// under Node via scripts/perf/wasm-bench.sh.
func BenchmarkWASMBridge(b *testing.B) {
	ops := []struct {
		name string
		call func(sql string) (int, error)
	}{
		{"parse", func(s string) (int, error) {
			tree, err := Parse(s, "")
			if err != nil {
				return 0, err
			}
			out, err := json.MarshalIndent(tree, "", "  ")
			return len(out), err
		}},
		{"lint", func(s string) (int, error) {
			out, err := json.MarshalIndent(Lint(s, ""), "", "  ")
			return len(out), err
		}},
		{"format", func(s string) (int, error) {
			out, err := json.MarshalIndent(Format(s, ""), "", "  ")
			return len(out), err
		}},
		{"highlight", func(s string) (int, error) {
			out, err := json.Marshal(Highlight(s, ""))
			return len(out), err
		}},
	}
	for _, op := range ops {
		b.Run(op.name, func(b *testing.B) {
			for _, q := range wasmBenchQueries {
				b.Run(q.name, func(b *testing.B) {
					n, err := op.call(q.sql)
					if err != nil || n == 0 {
						b.Fatalf("%s/%s: %d bytes, err %v", op.name, q.name, n, err)
					}
					b.ReportAllocs()
					b.SetBytes(int64(len(q.sql))) // input throughput: stable when the output shape changes
					b.ReportMetric(float64(n), "outB/op")
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_, _ = op.call(q.sql)
					}
				})
			}
		})
	}
}

// TestWASMBenchQueriesAreValid keeps the benchmark inputs on the success path.
func TestWASMBenchQueriesAreValid(t *testing.T) {
	for _, q := range wasmBenchQueries {
		if _, err := Parse(q.sql, ""); err != nil {
			t.Errorf("%s query does not parse: %v", q.name, err)
		}
		if r := Lint(q.sql, ""); r.ParseError != "" || r.Error != "" {
			t.Errorf("%s query: lint reported an error: parse=%q error=%q", q.name, r.ParseError, r.Error)
		}
		if r := Format(q.sql, ""); r.Error != "" {
			t.Errorf("%s query: format failed: %s", q.name, r.Error)
		}
	}
}
