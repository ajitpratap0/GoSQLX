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

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// tw is a test helper that builds a TokenWithSpan with zero-value span.
func tw(typ models.TokenType, val string) models.TokenWithSpan {
	return models.TokenWithSpan{Token: models.Token{Type: typ, Value: val}}
}

var (
	// Simple SELECT query tokens - with Type for fast int comparison path
	simpleSelectTokens = []models.TokenWithSpan{
		tw(models.TokenTypeSelect, "SELECT"),
		tw(models.TokenTypeIdentifier, "id"),
		tw(models.TokenTypeComma, ","),
		tw(models.TokenTypeIdentifier, "name"),
		tw(models.TokenTypeFrom, "FROM"),
		tw(models.TokenTypeIdentifier, "users"),
	}

	// Complex SELECT query with JOIN, WHERE, ORDER BY, LIMIT, OFFSET
	complexSelectTokens = []models.TokenWithSpan{
		tw(models.TokenTypeSelect, "SELECT"),
		tw(models.TokenTypeIdentifier, "u"),
		tw(models.TokenTypePeriod, "."),
		tw(models.TokenTypeIdentifier, "id"),
		tw(models.TokenTypeComma, ","),
		tw(models.TokenTypeIdentifier, "u"),
		tw(models.TokenTypePeriod, "."),
		tw(models.TokenTypeIdentifier, "name"),
		tw(models.TokenTypeComma, ","),
		tw(models.TokenTypeIdentifier, "o"),
		tw(models.TokenTypePeriod, "."),
		tw(models.TokenTypeIdentifier, "order_date"),
		tw(models.TokenTypeFrom, "FROM"),
		tw(models.TokenTypeIdentifier, "users"),
		tw(models.TokenTypeIdentifier, "u"),
		tw(models.TokenTypeJoin, "JOIN"),
		tw(models.TokenTypeIdentifier, "orders"),
		tw(models.TokenTypeIdentifier, "o"),
		tw(models.TokenTypeOn, "ON"),
		tw(models.TokenTypeIdentifier, "u"),
		tw(models.TokenTypePeriod, "."),
		tw(models.TokenTypeIdentifier, "id"),
		tw(models.TokenTypeEq, "="),
		tw(models.TokenTypeIdentifier, "o"),
		tw(models.TokenTypePeriod, "."),
		tw(models.TokenTypeIdentifier, "user_id"),
		tw(models.TokenTypeWhere, "WHERE"),
		tw(models.TokenTypeIdentifier, "u"),
		tw(models.TokenTypePeriod, "."),
		tw(models.TokenTypeIdentifier, "active"),
		tw(models.TokenTypeEq, "="),
		tw(models.TokenTypeTrue, "TRUE"),
		tw(models.TokenTypeOrder, "ORDER"),
		tw(models.TokenTypeBy, "BY"),
		tw(models.TokenTypeIdentifier, "o"),
		tw(models.TokenTypePeriod, "."),
		tw(models.TokenTypeIdentifier, "order_date"),
		tw(models.TokenTypeDesc, "DESC"),
		tw(models.TokenTypeLimit, "LIMIT"),
		tw(models.TokenTypeNumber, "10"),
		tw(models.TokenTypeOffset, "OFFSET"),
		tw(models.TokenTypeNumber, "20"),
	}

	// INSERT query tokens
	insertTokens = []models.TokenWithSpan{
		tw(models.TokenTypeInsert, "INSERT"),
		tw(models.TokenTypeInto, "INTO"),
		tw(models.TokenTypeIdentifier, "users"),
		tw(models.TokenTypeLParen, "("),
		tw(models.TokenTypeIdentifier, "name"),
		tw(models.TokenTypeComma, ","),
		tw(models.TokenTypeIdentifier, "email"),
		tw(models.TokenTypeRParen, ")"),
		tw(models.TokenTypeValues, "VALUES"),
		tw(models.TokenTypeLParen, "("),
		tw(models.TokenTypeString, "John"),
		tw(models.TokenTypeComma, ","),
		tw(models.TokenTypeString, "john@example.com"),
		tw(models.TokenTypeRParen, ")"),
	}

	// UPDATE query tokens
	updateTokens = []models.TokenWithSpan{
		tw(models.TokenTypeUpdate, "UPDATE"),
		tw(models.TokenTypeIdentifier, "users"),
		tw(models.TokenTypeSet, "SET"),
		tw(models.TokenTypeIdentifier, "active"),
		tw(models.TokenTypeEq, "="),
		tw(models.TokenTypeFalse, "FALSE"),
		tw(models.TokenTypeWhere, "WHERE"),
		tw(models.TokenTypeIdentifier, "last_login"),
		tw(models.TokenTypeLt, "<"),
		tw(models.TokenTypeString, "2024-01-01"),
	}

	// DELETE query tokens
	deleteTokens = []models.TokenWithSpan{
		tw(models.TokenTypeDelete, "DELETE"),
		tw(models.TokenTypeFrom, "FROM"),
		tw(models.TokenTypeIdentifier, "users"),
		tw(models.TokenTypeWhere, "WHERE"),
		tw(models.TokenTypeIdentifier, "active"),
		tw(models.TokenTypeEq, "="),
		tw(models.TokenTypeFalse, "FALSE"),
	}
)

// benchmarkParser benchmarks the parser using the production ParseFromModelTokens path.
func benchmarkParser(b *testing.B, tokens []models.TokenWithSpan) {
	b.Helper()
	parser := NewParser()
	defer parser.Release()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree, err := parser.ParseFromModelTokens(tokens)
		if err != nil {
			b.Fatal(err)
		}
		if tree == nil {
			b.Fatal("expected non-nil AST")
		}
	}
}

// benchmarkParserParallel benchmarks the parser in parallel using the production path.
func benchmarkParserParallel(b *testing.B, tokens []models.TokenWithSpan) {
	b.Helper()
	b.RunParallel(func(pb *testing.PB) {
		parser := NewParser()
		defer parser.Release()

		for pb.Next() {
			tree, err := parser.ParseFromModelTokens(tokens)
			if err != nil {
				b.Fatal(err)
			}
			if tree == nil {
				b.Fatal("expected non-nil AST")
			}
		}
	})
}

// Benchmark simple queries
func BenchmarkParserSimpleSelect(b *testing.B) {
	b.ReportAllocs()
	benchmarkParser(b, simpleSelectTokens)
}

// Benchmark complex queries
func BenchmarkParserComplexSelect(b *testing.B) {
	b.ReportAllocs()
	benchmarkParser(b, complexSelectTokens)
}

// Benchmark INSERT queries
func BenchmarkParserInsert(b *testing.B) {
	b.ReportAllocs()
	benchmarkParser(b, insertTokens)
}

// Benchmark UPDATE queries
func BenchmarkParserUpdate(b *testing.B) {
	b.ReportAllocs()
	benchmarkParser(b, updateTokens)
}

// Benchmark DELETE queries
func BenchmarkParserDelete(b *testing.B) {
	b.ReportAllocs()
	benchmarkParser(b, deleteTokens)
}

// Benchmark parallel execution
func BenchmarkParserSimpleSelectParallel(b *testing.B) {
	b.ReportAllocs()
	benchmarkParserParallel(b, simpleSelectTokens)
}

func BenchmarkParserComplexSelectParallel(b *testing.B) {
	b.ReportAllocs()
	benchmarkParserParallel(b, complexSelectTokens)
}

// Benchmark parser reuse
func BenchmarkParserReuse(b *testing.B) {
	b.ReportAllocs()
	parser := NewParser()
	defer parser.Release()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Parse different types of queries with the same parser instance
		queries := [][]models.TokenWithSpan{
			simpleSelectTokens,
			complexSelectTokens,
			insertTokens,
			updateTokens,
			deleteTokens,
		}

		for _, tokens := range queries {
			tree, err := parser.ParseFromModelTokens(tokens)
			if err != nil {
				b.Fatal(err)
			}
			if tree == nil {
				b.Fatal("expected non-nil AST")
			}
		}
	}
}

// Benchmark parser with mixed workload in parallel
func BenchmarkParserMixedParallel(b *testing.B) {
	queries := [][]models.TokenWithSpan{
		simpleSelectTokens,
		complexSelectTokens,
		insertTokens,
		updateTokens,
		deleteTokens,
	}

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		parser := NewParser()
		defer parser.Release()

		i := 0
		for pb.Next() {
			tokens := queries[i%len(queries)]
			tree, err := parser.ParseFromModelTokens(tokens)
			if err != nil {
				b.Fatal(err)
			}
			if tree == nil {
				b.Fatal("expected non-nil AST")
			}
			i++
		}
	})
}

// BenchmarkParser_RecursionDepthCheck measures the performance impact of recursion depth checking.
// This benchmark compares parsing with depth checks enabled (current implementation) to verify
// that the overhead is negligible (<1% as specified in requirements).
func BenchmarkParser_RecursionDepthCheck(b *testing.B) {
	// Test with various query complexities to ensure depth checking overhead is minimal
	testCases := []struct {
		name   string
		tokens []models.TokenWithSpan
	}{
		{
			name:   "SimpleSelect",
			tokens: simpleSelectTokens,
		},
		{
			name:   "ComplexSelect",
			tokens: complexSelectTokens,
		},
		{
			name: "ModerateNesting",
			tokens: func() []models.TokenWithSpan {
				// Build a moderately nested query (20 levels) - realistic usage
				tokens := []models.TokenWithSpan{tw(models.TokenTypeSelect, "SELECT")}
				for i := 0; i < 20; i++ {
					tokens = append(tokens,
						tw(models.TokenTypeIdentifier, "func"),
						tw(models.TokenTypeLParen, "("),
					)
				}
				tokens = append(tokens, tw(models.TokenTypeIdentifier, "x"))
				for i := 0; i < 20; i++ {
					tokens = append(tokens, tw(models.TokenTypeRParen, ")"))
				}
				tokens = append(tokens,
					tw(models.TokenTypeFrom, "FROM"),
					tw(models.TokenTypeIdentifier, "t"),
				)
				return tokens
			}(),
		},
		{
			name: "DeepNesting80",
			tokens: func() []models.TokenWithSpan {
				// Build a deeply nested query (80 levels) - approaching limit
				tokens := []models.TokenWithSpan{tw(models.TokenTypeSelect, "SELECT")}
				for i := 0; i < 80; i++ {
					tokens = append(tokens,
						tw(models.TokenTypeIdentifier, "func"),
						tw(models.TokenTypeLParen, "("),
					)
				}
				tokens = append(tokens, tw(models.TokenTypeIdentifier, "x"))
				for i := 0; i < 80; i++ {
					tokens = append(tokens, tw(models.TokenTypeRParen, ")"))
				}
				tokens = append(tokens,
					tw(models.TokenTypeFrom, "FROM"),
					tw(models.TokenTypeIdentifier, "t"),
				)
				return tokens
			}(),
		},
		{
			name: "DeepNesting90",
			tokens: func() []models.TokenWithSpan {
				// Build a very deeply nested query (90 levels) - near limit threshold
				tokens := []models.TokenWithSpan{tw(models.TokenTypeSelect, "SELECT")}
				for i := 0; i < 90; i++ {
					tokens = append(tokens,
						tw(models.TokenTypeIdentifier, "func"),
						tw(models.TokenTypeLParen, "("),
					)
				}
				tokens = append(tokens, tw(models.TokenTypeIdentifier, "x"))
				for i := 0; i < 90; i++ {
					tokens = append(tokens, tw(models.TokenTypeRParen, ")"))
				}
				tokens = append(tokens,
					tw(models.TokenTypeFrom, "FROM"),
					tw(models.TokenTypeIdentifier, "t"),
				)
				return tokens
			}(),
		},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			parser := NewParser()
			defer parser.Release()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tree, err := parser.ParseFromModelTokens(tc.tokens)
				if err != nil {
					b.Fatal(err)
				}
				if tree == nil {
					b.Fatal("expected non-nil AST")
				}
			}
		})
	}
}
