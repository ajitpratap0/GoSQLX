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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// BenchmarkParseError measures error handling without requesting error text.
func BenchmarkParseError(b *testing.B) {
	for _, tc := range []struct{ name, sql string }{
		{"syntax_mid", "SELECT id, FROM users WHERE id = 1"},
		{"syntax_end", "SELECT id FROM users WHERE"},
		{"tokenize", "SELECT 'unterminated"},
		{"long_prefix", "SELECT " + strings.Repeat("id, ", 128) + "FROM users"},
	} {
		b.Run(tc.name, func(b *testing.B) { benchmarkParseAndValidate(b, tc.sql, false) })
	}
}

func BenchmarkParseSuccess(b *testing.B) {
	for _, tc := range []struct{ name, sql string }{
		{"simple", "SELECT id, name FROM users WHERE id = 1"},
		{"complex", "SELECT u.id, COUNT(o.id) FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.id ORDER BY u.id"},
	} {
		b.Run(tc.name, func(b *testing.B) { benchmarkParseAndValidate(b, tc.sql, true) })
	}
}

func benchmarkParseAndValidate(b *testing.B, sql string, valid bool) {
	b.Helper()
	b.Run("Parse", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			a, err := Parse(sql)
			if a != nil {
				ast.ReleaseAST(a)
			}
			if (err == nil) != valid {
				b.Fatalf("unexpected parse result: %v", err)
			}
		}
	})
	b.Run("Validate", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := Validate(sql); (err == nil) != valid {
				b.Fatalf("unexpected validation result: %v", err)
			}
		}
	})
}
