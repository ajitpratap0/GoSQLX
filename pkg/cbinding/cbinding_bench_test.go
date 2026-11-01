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

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// benchQueries are fixed so results stay comparable across commits.
var benchQueries = []struct{ name, sql string }{
	{"small", "SELECT id, name FROM users WHERE id = 1"},
	{"medium", "SELECT u.id, u.name, COUNT(o.id) AS orders, SUM(o.total) AS spent " +
		"FROM users u LEFT JOIN orders o ON o.user_id = u.id " +
		"WHERE u.created_at > '2024-01-01' AND u.status IN ('active', 'trial') " +
		"GROUP BY u.id, u.name HAVING COUNT(o.id) > 2 ORDER BY spent DESC LIMIT 50"},
	{"large", "SELECT " + strings.TrimSuffix(strings.Repeat("c, ", 120), ", ") +
		" FROM t WHERE " + strings.TrimSuffix(strings.Repeat("a = 1 AND ", 80), " AND ")},
}

// BenchmarkCBinding measures one C-ABI call each, including the JSON build and
// the copy back to Go. Run: go test -run '^$' -bench CBinding -benchtime=10x.
func BenchmarkCBinding(b *testing.B) {
	for _, op := range []struct {
		name string
		call func(sql string) string
	}{
		{"parse", func(s string) string { return callLegacyRaw(exportParse, &s) }},
		{"validate", func(s string) string { return callLegacyRaw(exportValidate, &s) }},
		{"format", func(s string) string { return callLegacyRaw(exportFormat, &s) }},
		{"lint", func(s string) string { return lintRaw(s, nil) }},
	} {
		b.Run(op.name, func(b *testing.B) {
			for _, q := range benchQueries {
				b.Run(q.name, func(b *testing.B) {
					if err := checkBenchResult(op.call(q.sql)); err != nil {
						b.Fatalf("%s/%s took the error path: %v", op.name, q.name, err)
					}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_ = op.call(q.sql)
					}
				})
			}
		})
	}
	b.Run("free", func(b *testing.B) {
		sql := benchQueries[1].sql
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			allocAndFreeCString(sql)
		}
	})
}

// checkBenchResult fails on an error-shaped JSON result. Error results are
// non-empty JSON, so an emptiness check cannot detect them: parse, format and
// lint report success=false, validate reports valid=false, and all may carry
// an error field.
func checkBenchResult(out string) error {
	var r struct {
		Success *bool  `json:"success"`
		Valid   *bool  `json:"valid"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return fmt.Errorf("undecodable result %q: %w", out, err)
	}
	if r.Error != "" || (r.Success != nil && !*r.Success) || (r.Valid != nil && !*r.Valid) {
		return fmt.Errorf("error result: %s", out)
	}
	if r.Success == nil && r.Valid == nil {
		return fmt.Errorf("result has neither success nor valid: %s", out)
	}
	return nil
}

// TestBenchQueriesAreValid keeps the benchmark inputs honest: a query that
// stopped parsing would turn the benchmark into an error-path measurement.
func TestBenchQueriesAreValid(t *testing.T) {
	for _, q := range benchQueries {
		if r := validateSQL(q.sql); !r.Valid {
			t.Errorf("%s query is invalid: %+v", q.name, r)
		}
		if r := formatSQL(q.sql); !r.Success || r.Error != "" {
			t.Errorf("%s query does not format: %+v", q.name, r)
		}
		for name, out := range map[string]string{
			"parse": callLegacyRaw(exportParse, &q.sql),
			"lint":  lintRaw(q.sql, nil),
		} {
			if err := checkBenchResult(out); err != nil {
				t.Errorf("%s query, %s: %v", q.name, name, err)
			}
		}
	}
}
