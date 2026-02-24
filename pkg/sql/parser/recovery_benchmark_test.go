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

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// BenchmarkParseWithRecovery_AllValid benchmarks recovery parsing with no errors.
func BenchmarkParseWithRecovery_AllValid(b *testing.B) {
	tokens := []token.Token{
		tok("SELECT", "SELECT"), tok("INT", "1"), semi(),
		tok("SELECT", "SELECT"), tok("INT", "2"), semi(),
		tok("SELECT", "SELECT"), tok("*", "*"), tok("FROM", "FROM"), tok("IDENT", "users"), semi(),
		eof(),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := ParseMultiWithRecovery(tokens)
		result.Release()
	}
}

// BenchmarkParseWithRecovery_Mixed benchmarks recovery parsing with mixed valid/invalid.
func BenchmarkParseWithRecovery_Mixed(b *testing.B) {
	tokens := []token.Token{
		tok("SELECT", "SELECT"), tok("INT", "1"), semi(),
		tok("IDENT", "BAD1"), tok("IDENT", "stuff"), semi(),
		tok("SELECT", "SELECT"), tok("*", "*"), tok("FROM", "FROM"), tok("IDENT", "users"), semi(),
		tok("IDENT", "BAD2"), semi(),
		eof(),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := ParseMultiWithRecovery(tokens)
		result.Release()
	}
}

// BenchmarkParseWithRecovery_AllInvalid benchmarks recovery parsing with heavy error recovery.
func BenchmarkParseWithRecovery_AllInvalid(b *testing.B) {
	tokens := []token.Token{
		tok("IDENT", "BAD1"), tok("IDENT", "x"), tok("IDENT", "y"), semi(),
		tok("IDENT", "BAD2"), tok("IDENT", "x"), semi(),
		tok("IDENT", "BAD3"), semi(),
		tok("IDENT", "BAD4"), tok("IDENT", "a"), tok("IDENT", "b"), tok("IDENT", "c"), semi(),
		eof(),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := ParseMultiWithRecovery(tokens)
		result.Release()
	}
}
