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

package transform

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func BenchmarkParseSQL(b *testing.B) {
	sql := "SELECT id, name FROM users WHERE id = 1"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseSQL(sql); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseSQLWithDialect(b *testing.B) {
	sql := "SELECT TOP 10 * FROM users"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseSQLWithDialect(sql, keywords.DialectSQLServer); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAddWhereFromSQL(b *testing.B) {
	tree, err := ParseSQL("SELECT id, name FROM users")
	if err != nil {
		b.Fatal(err)
	}
	stmt := tree.Statements[0]
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Apply(stmt, AddWhereFromSQL("id = 1"), RemoveWhere()); err != nil {
			b.Fatal(err)
		}
	}
}
