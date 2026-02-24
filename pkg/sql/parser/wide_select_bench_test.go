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
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func buildWideSelect(n int) string {
	var sb strings.Builder
	sb.WriteString("SELECT ")
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteString(", ")
		}
		fmt.Fprintf(&sb, "col%d", i)
	}
	sb.WriteString(" FROM t")
	return sb.String()
}

func benchmarkWideSelect(b *testing.B, numCols int) {
	sql := buildWideSelect(numCols)
	sqlBytes := []byte(sql)

	// Pre-tokenize to measure parser only
	tkz := tokenizer.GetTokenizer()
	tokens, err := tkz.Tokenize(sqlBytes)
	tokenizer.PutTokenizer(tkz)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		p := NewParser()
		_, err := p.ParseFromModelTokens(tokens)
		if err != nil {
			b.Fatal(err)
		}
		p.Release()
	}
}

func BenchmarkWideSelect100(b *testing.B)  { benchmarkWideSelect(b, 100) }
func BenchmarkWideSelect500(b *testing.B)  { benchmarkWideSelect(b, 500) }
func BenchmarkWideSelect1000(b *testing.B) { benchmarkWideSelect(b, 1000) }
func BenchmarkWideSelect5000(b *testing.B) { benchmarkWideSelect(b, 5000) }
