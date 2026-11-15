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

package keywords

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

var (
	lookupBenchmarkBool    bool
	lookupBenchmarkType    models.TokenType
	lookupBenchmarkKeyword Keyword
)

func BenchmarkKeywordLookup(b *testing.B) {
	k := New(DialectPostgreSQL, true)
	methods := []struct {
		name string
		call func(string)
	}{
		{"IsKeyword", func(s string) { lookupBenchmarkBool = k.IsKeyword(s) }},
		{"GetKeywordType", func(s string) { lookupBenchmarkType = k.GetKeywordType(s) }},
		{"IsReserved", func(s string) { lookupBenchmarkBool = k.IsReserved(s) }},
		{"GetKeyword", func(s string) { lookupBenchmarkKeyword, lookupBenchmarkBool = k.GetKeyword(s) }},
		{"GetTokenType", func(s string) { lookupBenchmarkType = k.GetTokenType(s) }},
		{"IsCompoundKeywordStart", func(s string) { lookupBenchmarkBool = k.IsCompoundKeywordStart(s) }},
	}
	inputs := []struct{ name, value string }{
		{"upper", "SELECT"}, {"lower", "select"}, {"mixed", "Row_Number"},
		{"miss", "customer_id"}, {"long", strings.Repeat("x", 65)},
	}
	for _, method := range methods {
		b.Run(method.name, func(b *testing.B) {
			for _, input := range inputs {
				b.Run(input.name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						method.call(input.value)
					}
				})
			}
		})
	}
}
