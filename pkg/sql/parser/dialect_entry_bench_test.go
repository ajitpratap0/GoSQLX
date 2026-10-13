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

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// dialectEntrySQL is the same statement as BenchmarkParseBytes so the
// dialect-aware and default entry points can be compared directly (#550).
var dialectEntrySQL = []byte("SELECT u.id, u.name, u.email FROM users u JOIN orders o ON u.id = o.user_id WHERE u.active = true AND o.total > 100 ORDER BY o.created_at DESC LIMIT 50")

func BenchmarkParseBytesDefault(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result, err := parser.ParseBytes(dialectEntrySQL)
		if err != nil {
			b.Fatal(err)
		}
		ast.ReleaseAST(result)
	}
}

func BenchmarkParseBytesWithDialect(b *testing.B) {
	for _, d := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL} {
		b.Run(string(d), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				result, err := parser.ParseBytesWithDialect(dialectEntrySQL, d)
				if err != nil {
					b.Fatal(err)
				}
				ast.ReleaseAST(result)
			}
		})
	}
}

func BenchmarkValidateBytesWithDialect(b *testing.B) {
	for _, d := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL} {
		b.Run(string(d), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := parser.ValidateBytesWithDialect(dialectEntrySQL, d); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
