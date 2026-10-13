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
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// BenchmarkTokenizeString compares the []byte entry point, which copies the
// input once into a string, with TokenizeString, which slices the caller's
// string directly (#546).
func BenchmarkTokenizeString(b *testing.B) {
	inputs := []struct {
		name string
		sql  []byte
	}{
		{"SimpleSQL", simpleSQL},
		{"ComplexSQL", complexSQL},
		{"MediumSQL_10KB", mediumSQL10KB},
	}
	for _, in := range inputs {
		s := string(in.sql)
		b.Run(in.name+"/Bytes", func(b *testing.B) {
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)
			b.ReportAllocs()
			b.SetBytes(int64(len(in.sql)))
			for b.Loop() {
				if _, err := tkz.Tokenize(in.sql); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(in.name+"/String", func(b *testing.B) {
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)
			b.ReportAllocs()
			b.SetBytes(int64(len(s)))
			for b.Loop() {
				if _, err := tkz.TokenizeString(s); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// quoteHeavyInputs are literal- and quoted-identifier-heavy statements for
// BenchmarkTokenizeQuoteHeavy (#548).
func quoteHeavyInputs() []struct {
	name    string
	dialect keywords.SQLDialect
	sql     string
} {
	var rows []string
	for i := 0; i < 50; i++ {
		rows = append(rows, "('alpha','beta','gamma','delta')")
	}
	stringLiterals := "INSERT INTO t (a,b,c,d) VALUES " + strings.Join(rows, ",")

	cols := make([]string, 0, 100)
	for i := 1; i <= 100; i++ {
		cols = append(cols, fmt.Sprintf(`"Col%d"`, i))
	}
	quotedIdents := "SELECT " + strings.Join(cols, ",") + ` FROM "Schema"."Table"`
	backticks := strings.ReplaceAll(quotedIdents, `"`, "`")

	long := "'" + strings.Repeat("x", 198) + "'"
	longs := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		longs = append(longs, long)
	}
	longLiterals := "SELECT " + strings.Join(longs, ",")

	escaped := make([]string, 0, 100)
	for i := 0; i < 50; i++ {
		escaped = append(escaped, `'it''s'`, `'a\nb'`)
	}
	escapedPG := "SELECT " + strings.Join(escaped, ",")

	return []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
	}{
		{"StringLiterals", keywords.DialectPostgreSQL, stringLiterals},
		{"QuotedIdents", keywords.DialectPostgreSQL, quotedIdents},
		{"Backticks_MySQL", keywords.DialectMySQL, backticks},
		{"LongLiterals", keywords.DialectPostgreSQL, longLiterals},
		{"Escaped_PG", keywords.DialectPostgreSQL, escapedPG},
	}
}

// BenchmarkTokenizeQuoteHeavy measures string literals and quoted
// identifiers, which take the substring fast path unless they contain an
// escape (#548). Escaped_PG measures the slow path.
func BenchmarkTokenizeQuoteHeavy(b *testing.B) {
	for _, in := range quoteHeavyInputs() {
		input := []byte(in.sql)
		b.Run(in.name+"/Bytes", func(b *testing.B) {
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)
			tkz.SetDialect(in.dialect)
			b.ReportAllocs()
			b.SetBytes(int64(len(input)))
			for b.Loop() {
				if _, err := tkz.Tokenize(input); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(in.name+"/String", func(b *testing.B) {
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)
			tkz.SetDialect(in.dialect)
			b.ReportAllocs()
			b.SetBytes(int64(len(in.sql)))
			for b.Loop() {
				if _, err := tkz.TokenizeString(in.sql); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
