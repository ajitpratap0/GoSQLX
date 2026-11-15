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
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/tokclass"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// The table-level tests (keyword remaps, compound expansion) moved to
// internal/tokclass with the rules; these cover the preprocess loop itself.

func mtok(typ models.TokenType, val string) models.Token {
	return models.Token{Type: typ, Value: val}
}

func TestPreprocessTokensGolden(t *testing.T) {
	sp := func(typ models.TokenType, val string, line, col int) models.TokenWithSpan {
		loc := models.Location{Line: line, Column: col}
		return models.TokenWithSpan{Token: mtok(typ, val), Start: loc, End: models.Location{Line: line, Column: col + len(val)}}
	}
	in := []models.TokenWithSpan{
		sp(models.TokenTypeSelect, "SELECT", 1, 1),
		sp(models.TokenTypeCount, "COUNT", 1, 8),
		sp(models.TokenTypeLParen, "(", 1, 13),
		sp(models.TokenTypeMul, "*", 1, 14),
		sp(models.TokenTypeRParen, ")", 1, 15),
		sp(models.TokenTypeFrom, "FROM", 1, 17),
		sp(models.TokenTypeIdentifier, "users", 1, 22),
		sp(models.TokenTypeInnerJoin, "INNER JOIN", 1, 28),
		sp(models.TokenTypeIdentifier, "with", 1, 39),
		sp(models.TokenTypeKeyword, "LEFT OUTER JOIN", 1, 44),
		sp(models.TokenTypeKeyword, "materialized", 1, 60),
		sp(models.TokenTypeGroupBy, "GROUP BY", 1, 73),
		sp(models.TokenTypeKeyword, "unknownword", 1, 82),
		sp(models.TokenTypeOrderBy, "ORDER BY", 1, 94),
	}
	span := func(l, c, n int) (models.Location, models.Location) {
		return models.Location{Line: l, Column: c}, models.Location{Line: l, Column: c + n}
	}
	mk := func(typ models.TokenType, val string, c, n int) models.TokenWithSpan {
		s, e := span(1, c, n)
		return models.TokenWithSpan{Token: mtok(typ, val), Start: s, End: e}
	}
	want := []models.TokenWithSpan{
		mk(models.TokenTypeSelect, "SELECT", 1, 6),
		mk(models.TokenTypeIdentifier, "COUNT", 8, 5),
		mk(models.TokenTypeLParen, "(", 13, 1),
		mk(models.TokenTypeMul, "*", 14, 1),
		mk(models.TokenTypeRParen, ")", 15, 1),
		mk(models.TokenTypeFrom, "FROM", 17, 4),
		mk(models.TokenTypeIdentifier, "users", 22, 5),
		mk(models.TokenTypeInner, "INNER", 28, 5),
		mk(models.TokenTypeJoin, "JOIN", 34, 4),
		mk(models.TokenTypeWith, "with", 39, 4),
		mk(models.TokenTypeLeft, "LEFT", 44, 15),
		mk(models.TokenTypeOuter, "OUTER", 44, 15),
		mk(models.TokenTypeJoin, "JOIN", 44, 15),
		mk(tokclass.KeywordType("materialized"), "materialized", 60, 12),
		mk(models.TokenTypeGroup, "GROUP", 73, 5),
		mk(models.TokenTypeBy, "BY", 79, 2),
		mk(models.TokenTypeKeyword, "unknownword", 82, 11),
		mk(models.TokenTypeOrder, "ORDER", 94, 5),
		mk(models.TokenTypeBy, "BY", 100, 2),
	}
	if want[13].Token.Type == models.TokenTypeUnknown {
		t.Fatal("test setup: materialized must remap to a specific type")
	}

	orig := append([]models.TokenWithSpan(nil), in...)
	got := preprocessTokens(in)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("preprocessTokens mismatch:\n got  %+v\n want %+v", got, want)
	}
	if !reflect.DeepEqual(in, orig) {
		t.Fatal("preprocessTokens mutated its input")
	}
	got[0].Token.Value = "MUTATED"
	if in[0].Token.Value != "SELECT" {
		t.Error("output aliases input slice")
	}
}

var sinkTokens []models.TokenWithSpan

func TestPreprocessAllocs(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not stable under the race detector")
	}

	// The stream expands by exactly 4 tokens (INNER JOIN, FULL JOIN, GROUP BY,
	// ORDER BY), which fits preprocessTokens' len+4 headroom: one allocation.
	stream := []models.TokenWithSpan{
		{Token: mtok(models.TokenTypeSelect, "SELECT")},
		{Token: mtok(models.TokenTypeIdentifier, "id")},
		{Token: mtok(models.TokenTypeFrom, "FROM")},
		{Token: mtok(models.TokenTypeIdentifier, "users")},
		{Token: mtok(models.TokenTypeInnerJoin, "INNER JOIN")},
		{Token: mtok(models.TokenTypeIdentifier, "orders")},
		{Token: mtok(models.TokenTypeKeyword, "FULL JOIN")},
		{Token: mtok(models.TokenTypeIdentifier, "items")},
		{Token: mtok(models.TokenTypeIdentifier, "with")},
		{Token: mtok(models.TokenTypeIdentifier, "where")},
		{Token: mtok(models.TokenTypeGroupBy, "GROUP BY")},
		{Token: mtok(models.TokenTypeIdentifier, "total")},
		{Token: mtok(models.TokenTypeOrderBy, "ORDER BY")},
		{Token: mtok(models.TokenTypeKeyword, "materialized")},
		{Token: mtok(models.TokenTypeIdentifier, "name")},
	}
	if n := testing.AllocsPerRun(1000, func() { sinkTokens = preprocessTokens(stream) }); n != 1 {
		t.Errorf("preprocessTokens allocs = %v, want 1 (result slice only)", n)
	}
}

func BenchmarkPreprocessTokens(b *testing.B) {
	const query = `SELECT u.id, o.total, COUNT(*) FROM users u INNER JOIN orders o ON u.id = o.user_id LEFT JOIN items i ON i.order_id = o.id WHERE u.active = true GROUP BY u.id, o.total ORDER BY o.total`

	tokenize := func(b *testing.B, sql string) []models.TokenWithSpan {
		b.Helper()
		tkz := tokenizer.GetTokenizer()
		defer tokenizer.PutTokenizer(tkz)
		toks, err := tkz.Tokenize([]byte(sql))
		if err != nil {
			b.Fatalf("tokenize: %v", err)
		}
		// Copy: the tokenizer's result must not be retained across PutTokenizer.
		return append([]models.TokenWithSpan(nil), toks...)
	}

	for _, tc := range []struct{ name, sql string }{
		{"Upper", query},
		{"Lower", strings.ToLower(query)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			tokens := tokenize(b, tc.sql)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sinkTokens = preprocessTokens(tokens)
			}
		})
	}
}
