// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package tokclass

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// All boundaries here are literal; the expected stream does not use SplitSpans.
func TestSplitSpansCompoundTypes(t *testing.T) {
	tests := []struct {
		typ                  models.TokenType
		value, first, second string
		end1, start2         int
	}{
		{models.TokenTypeInnerJoin, "inner join", "INNER", "JOIN", 12, 13},
		{models.TokenTypeLeftJoin, "left join", "LEFT", "JOIN", 11, 13},
		{models.TokenTypeRightJoin, "right join", "RIGHT", "JOIN", 12, 13},
		{models.TokenTypeOuterJoin, "outer join", "OUTER", "JOIN", 12, 13},
		{models.TokenTypeFullJoin, "full join", "FULL", "JOIN", 11, 13},
		{models.TokenTypeCrossJoin, "cross join", "CROSS", "JOIN", 12, 13},
		{models.TokenTypeOrderBy, "order by", "ORDER", "BY", 12, 15},
		{models.TokenTypeGroupBy, "group by", "GROUP", "BY", 12, 15},
		// A wider synthetic span is deliberate (Q2).
		{models.TokenTypeGroupingSets, "grouping sets", "GROUPING", "SETS", 15, 23},
		// Unicode word byte widths differ from the canonical output widths.
		{models.TokenTypeInnerJoin, "ıNNER JOıN", "INNER", "JOIN", 13, 22},
	}
	for _, tc := range tests {
		types := []models.TokenType{tc.typ}
		if tc.typ != models.TokenTypeOuterJoin && tc.value != "ıNNER JOıN" {
			types = append(types, models.TokenTypeKeyword)
		}
		for _, typ := range types {
			values := []string{tc.value, strings.ToUpper(tc.value), strings.ToUpper(tc.value[:1]) + tc.value[1:]}
			if tc.value == "ıNNER JOıN" {
				values = []string{tc.value}
			}
			for _, value := range values {
				t.Run(typ.String()+"/"+value, func(t *testing.T) {
					end := 17
					if tc.typ == models.TokenTypeGroupingSets || tc.value == "ıNNER JOıN" {
						end = 27
					}
					in := models.TokenWithSpan{Token: models.Token{Type: typ, Value: value, Word: &models.Word{Value: value}, Quote: '"', Long: true}, Start: models.Location{Line: 3, Column: 7}, End: models.Location{Line: 3, Column: end}}
					original := in
					originalWord := *in.Token.Word
					prefix := models.TokenWithSpan{Token: models.Token{Type: models.TokenTypeSelect, Value: "sentinel"}}
					dst := make([]models.TokenWithSpan, 1, 4)
					dst[0] = prefix
					got, ok := AppendCompound(dst, &in)
					want := []models.TokenWithSpan{prefix,
						{Token: mtok(typeForSpanWord(tc.first), tc.first), Start: in.Start, End: models.Location{Line: 3, Column: tc.end1}},
						{Token: mtok(typeForSpanWord(tc.second), tc.second), Start: models.Location{Line: 3, Column: tc.start2}, End: in.End},
					}
					if !ok || !reflect.DeepEqual(got, want) {
						t.Fatalf("got %+v (ok %v), want %+v", got, ok, want)
					}
					if !reflect.DeepEqual(in, original) || !reflect.DeepEqual(*in.Token.Word, originalWord) {
						t.Fatal("input mutated")
					}
					if dst[0] != prefix {
						t.Fatal("prefix mutated")
					}
				})
			}
		}
	}
}

func typeForSpanWord(word string) models.TokenType {
	switch word {
	case "INNER":
		return models.TokenTypeInner
	case "LEFT":
		return models.TokenTypeLeft
	case "RIGHT":
		return models.TokenTypeRight
	case "OUTER":
		return models.TokenTypeOuter
	case "FULL":
		return models.TokenTypeFull
	case "CROSS":
		return models.TokenTypeCross
	case "ORDER":
		return models.TokenTypeOrder
	case "GROUP":
		return models.TokenTypeGroup
	case "GROUPING":
		return models.TokenTypeGrouping
	case "JOIN":
		return models.TokenTypeJoin
	case "BY":
		return models.TokenTypeBy
	case "SETS":
		return models.TokenTypeSets
	}
	return models.TokenTypeUnknown
}

func TestSplitSpansLocations(t *testing.T) {
	tests := []struct {
		name, value              string
		start, end, end1, start2 models.Location
		derive                   bool
	}{
		{"one space", "GROUP BY", models.Location{Line: 1, Column: 1}, models.Location{Line: 1, Column: 9}, models.Location{Line: 1, Column: 6}, models.Location{Line: 1, Column: 7}, true},
		{"wide source separator", "GROUP BY", models.Location{Line: 1, Column: 1}, models.Location{Line: 1, Column: 14}, models.Location{Line: 1, Column: 6}, models.Location{Line: 1, Column: 12}, true},
		{"multiline", "GROUP BY", models.Location{Line: 2, Column: 8}, models.Location{Line: 4, Column: 4}, models.Location{Line: 2, Column: 13}, models.Location{Line: 4, Column: 2}, true},
		{"multiline column one", "GROUP BY", models.Location{Line: 2, Column: 8}, models.Location{Line: 3, Column: 3}, models.Location{Line: 2, Column: 13}, models.Location{Line: 3, Column: 1}, true},
		{name: "zero span", value: "GROUP BY"},
		{name: "zero start line", value: "GROUP BY", start: models.Location{Line: 0, Column: 2}, end: models.Location{Line: 1, Column: 20}},
		{name: "negative start line", value: "GROUP BY", start: models.Location{Line: -1, Column: 2}, end: models.Location{Line: 1, Column: 20}},
		{name: "zero start column", value: "GROUP BY", start: models.Location{Line: 1}, end: models.Location{Line: 1, Column: 20}},
		{name: "negative start column", value: "GROUP BY", start: models.Location{Line: 1, Column: -1}, end: models.Location{Line: 1, Column: 20}},
		{name: "reversed lines", value: "GROUP BY", start: models.Location{Line: 2, Column: 1}, end: models.Location{Line: 1, Column: 20}},
		{name: "second column zero", value: "GROUP BY", start: models.Location{Line: 1, Column: 1}, end: models.Location{Line: 2, Column: 2}},
		{name: "second column negative", value: "GROUP BY", start: models.Location{Line: 1, Column: 1}, end: models.Location{Line: 2, Column: 1}},
		{name: "touching", value: "GROUP BY", start: models.Location{Line: 1, Column: 1}, end: models.Location{Line: 1, Column: 8}},
		{name: "overlap", value: "GROUP BY", start: models.Location{Line: 1, Column: 1}, end: models.Location{Line: 1, Column: 7}},
		{name: "empty", value: ""}, {name: "one word", value: "GROUP"}, {name: "three words", value: "GROUP BY X"},
		{name: "empty first", value: " BY"}, {name: "empty second", value: "GROUP "}, {name: "double separator", value: "GROUP  BY"},
		{name: "tab value", value: "GROUP\tBY"}, {name: "newline value", value: "GROUP\nBY"},
		{name: "embedded tab", value: "GR\tOUP BY"}, {name: "embedded newline", value: "GROUP B\nY"},
		{name: "embedded carriage return", value: "GROUP B\rY"},
		{name: "embedded form feed", value: "GROUP B\fY"},
		{name: "embedded vertical tab", value: "GROUP B\vY"},
		{name: "embedded Unicode whitespace", value: "GROUP B\u00a0Y"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Malformed Values also get valid locations so the Value rule is exercised.
			if tc.start == (models.Location{}) && tc.end == (models.Location{}) && tc.name != "zero span" {
				tc.start = models.Location{Line: 1, Column: 1}
				tc.end = models.Location{Line: 1, Column: 30}
			}
			in := models.TokenWithSpan{Token: mtok(models.TokenTypeGroupBy, tc.value), Start: tc.start, End: tc.end}
			end1, start2, derived := SplitSpans(&in)
			if derived != tc.derive || (derived && (end1 != tc.end1 || start2 != tc.start2)) {
				t.Fatalf("SplitSpans = %v / %v, %v; want %v / %v, %v", end1, start2, derived, tc.end1, tc.start2, tc.derive)
			}
			got, ok := AppendCompound(nil, &in)
			if !ok || len(got) != 2 {
				t.Fatal("typed compound did not expand")
			}
			wantEnd, wantStart := tc.end, tc.start
			if tc.derive {
				wantEnd, wantStart = tc.end1, tc.start2
			}
			if got[0].Start != tc.start || got[0].End != wantEnd || got[1].Start != wantStart || got[1].End != tc.end {
				t.Fatalf("got %+v, want outer endpoints and boundaries %v / %v", got, wantEnd, wantStart)
			}
		})
	}
}

func TestSplitSpansThreePartAndLookalikes(t *testing.T) {
	for _, value := range []string{"LEFT OUTER JOIN", "RIGHT OUTER JOIN", "FULL OUTER JOIN"} {
		in := models.TokenWithSpan{Token: mtok(models.TokenTypeKeyword, value), Start: models.Location{Line: 1, Column: 2}, End: models.Location{Line: 1, Column: 40}}
		got, ok := AppendCompound(nil, &in)
		if !ok || len(got) != 3 {
			t.Fatal("three-part expansion missing")
		}
		for _, child := range got {
			if child.Start != in.Start || child.End != in.End {
				t.Fatalf("three-part spans changed: %+v", got)
			}
		}
	}
	for _, tc := range []models.Token{mtok(models.TokenTypeKeyword, "OUTER JOIN"), mtok(models.TokenTypeString, "GROUP BY"), {Type: models.TokenTypeIdentifier, Value: "GROUP BY", Quote: '"'}} {
		in := models.TokenWithSpan{Token: tc, Start: models.Location{Line: 1, Column: 1}, End: models.Location{Line: 1, Column: 20}}
		prefix := []models.TokenWithSpan{{Token: mtok(models.TokenTypeSelect, "SELECT")}}
		got, ok := AppendCompound(prefix, &in)
		if ok || !reflect.DeepEqual(got, prefix) {
			t.Fatalf("lookalike expanded: %+v", tc)
		}
	}
}

func TestSplitSpansAllocs(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not stable under the race detector")
	}
	in := models.TokenWithSpan{Token: mtok(models.TokenTypeGroupBy, "GROUP BY"), Start: models.Location{Line: 1, Column: 1}, End: models.Location{Line: 1, Column: 20}}
	dst := make([]models.TokenWithSpan, 0, 2)
	if n := testing.AllocsPerRun(1000, func() { dst, _ = AppendCompound(dst[:0], &in) }); n != 0 {
		t.Fatalf("allocs = %v, want 0", n)
	}
}
