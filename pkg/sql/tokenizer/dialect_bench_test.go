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

package tokenizer

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// dialectBenchSQL is a short MySQL statement used by the dialect benchmarks
// (#550). It exercises backtick identifiers and LIMIT offset, count.
var dialectBenchSQL = []byte("SELECT `id`, `name` FROM `users` WHERE `active` = 1 ORDER BY `id` LIMIT 10, 20")

// BenchmarkNewWithDialect measures constructing a dialect tokenizer and
// tokenizing one short statement with it (the unpooled path used by the
// linter and CLI).
func BenchmarkNewWithDialect(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tkz, err := NewWithDialect(keywords.DialectMySQL)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := tkz.Tokenize(dialectBenchSQL); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSetDialect measures switching a tokenizer to a non-default dialect
// and back, which is what a pooled dialect-aware call pays per use.
func BenchmarkSetDialect(b *testing.B) {
	tkz, err := New()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tkz.SetDialect(keywords.DialectMySQL)
		tkz.SetDialect(keywords.DialectPostgreSQL)
	}
}

// BenchmarkPooledDialectTokenize measures GetTokenizer + SetDialect +
// Tokenize + PutTokenizer, the pattern used by the dialect-aware entry points.
func BenchmarkPooledDialectTokenize(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tkz := GetTokenizer()
		tkz.SetDialect(keywords.DialectMySQL)
		if _, err := tkz.Tokenize(dialectBenchSQL); err != nil {
			b.Fatal(err)
		}
		PutTokenizer(tkz)
	}
}
