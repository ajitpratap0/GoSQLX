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

// Unit tests for the classification tables, moved verbatim from
// pkg/sql/parser/preprocess_test.go when the rules moved here (W3-03a1).

package tokclass

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// goldenKeywordTypes pins every keyword handled by KeywordType.
var goldenKeywordTypes = map[string]models.TokenType{
	"INSERT":         models.TokenTypeInsert,
	"UPDATE":         models.TokenTypeUpdate,
	"DELETE":         models.TokenTypeDelete,
	"INTO":           models.TokenTypeInto,
	"VALUES":         models.TokenTypeValues,
	"SET":            models.TokenTypeSet,
	"CREATE":         models.TokenTypeCreate,
	"ALTER":          models.TokenTypeAlter,
	"DROP":           models.TokenTypeDrop,
	"TABLE":          models.TokenTypeTable,
	"INDEX":          models.TokenTypeIndex,
	"VIEW":           models.TokenTypeView,
	"WITH":           models.TokenTypeWith,
	"RECURSIVE":      models.TokenTypeRecursive,
	"UNION":          models.TokenTypeUnion,
	"EXCEPT":         models.TokenTypeExcept,
	"INTERSECT":      models.TokenTypeIntersect,
	"ALL":            models.TokenTypeAll,
	"PRIMARY":        models.TokenTypePrimary,
	"KEY":            models.TokenTypeKey,
	"FOREIGN":        models.TokenTypeForeign,
	"REFERENCES":     models.TokenTypeReferences,
	"UNIQUE":         models.TokenTypeUnique,
	"CHECK":          models.TokenTypeCheck,
	"DEFAULT":        models.TokenTypeDefault,
	"CONSTRAINT":     models.TokenTypeConstraint,
	"AUTO_INCREMENT": models.TokenTypeAutoIncrement,
	"AUTOINCREMENT":  models.TokenTypeAutoIncrement,
	"OVER":           models.TokenTypeOver,
	"PARTITION":      models.TokenTypePartition,
	"ROWS":           models.TokenTypeRows,
	"RANGE":          models.TokenTypeRange,
	"UNBOUNDED":      models.TokenTypeUnbounded,
	"PRECEDING":      models.TokenTypePreceding,
	"FOLLOWING":      models.TokenTypeFollowing,
	"CURRENT":        models.TokenTypeCurrent,
	"ROW":            models.TokenTypeRow,
	"CROSS":          models.TokenTypeCross,
	"NATURAL":        models.TokenTypeNatural,
	"USING":          models.TokenTypeUsing,
	"LATERAL":        models.TokenTypeLateral,
	"DISTINCT":       models.TokenTypeDistinct,
	"EXISTS":         models.TokenTypeExists,
	"ANY":            models.TokenTypeAny,
	"SOME":           models.TokenTypeSome,
	"ROLLUP":         models.TokenTypeRollup,
	"CUBE":           models.TokenTypeCube,
	"GROUPING":       models.TokenTypeGrouping,
	"ADD":            models.TokenTypeAdd,
	"NOSUPERUSER":    models.TokenTypeNosuperuser,
	"NOCREATEDB":     models.TokenTypeNocreatedb,
	"NOCREATEROLE":   models.TokenTypeNocreaterole,
	"NOLOGIN":        models.TokenTypeNologin,
	"VALID":          models.TokenTypeValid,
	"DCPROPERTIES":   models.TokenTypeDcproperties,
	"URL":            models.TokenTypeUrl,
	"OWNER":          models.TokenTypeOwner,
	"MEMBER":         models.TokenTypeMember,
	"CONNECTOR":      models.TokenTypeConnector,
	"POLICY":         models.TokenTypePolicy,
	"UNTIL":          models.TokenTypeUntil,
	"RESET":          models.TokenTypeReset,
	"RENAME":         models.TokenTypeRename,
	"COLUMN":         models.TokenTypeColumn,
	"CASCADE":        models.TokenTypeCascade,
	"RESTRICT":       models.TokenTypeRestrict,
	"MATERIALIZED":   models.TokenTypeMaterialized,
	"REPLACE":        models.TokenTypeReplace,
	"COLLATE":        models.TokenTypeCollate,
	"ASC":            models.TokenTypeAsc,
	"DESC":           models.TokenTypeDesc,
	"JOIN":           models.TokenTypeJoin,
	"INNER":          models.TokenTypeInner,
	"LEFT":           models.TokenTypeLeft,
	"RIGHT":          models.TokenTypeRight,
	"FULL":           models.TokenTypeFull,
	"OUTER":          models.TokenTypeOuter,
	"IS":             models.TokenTypeIs,
	"LIKE":           models.TokenTypeLike,
	"ILIKE":          models.TokenTypeILike,
	"BETWEEN":        models.TokenTypeBetween,
	"CASE":           models.TokenTypeCase,
	"WHEN":           models.TokenTypeWhen,
	"THEN":           models.TokenTypeThen,
	"ELSE":           models.TokenTypeElse,
	"END":            models.TokenTypeEnd,
	"CAST":           models.TokenTypeCast,
	"INTERVAL":       models.TokenTypeInterval,
	"MERGE":          models.TokenTypeMerge,
	"MATCHED":        models.TokenTypeMatched,
	"SOURCE":         models.TokenTypeSource,
	"TARGET":         models.TokenTypeTarget,
	"SETS":           models.TokenTypeSets,
	"FETCH":          models.TokenTypeFetch,
	"NEXT":           models.TokenTypeNext,
	"TIES":           models.TokenTypeTies,
	"PERCENT":        models.TokenTypePercent,
	"ONLY":           models.TokenTypeOnly,
	"SHARE":          models.TokenTypeShare,
	"IF":             models.TokenTypeIf,
	"REFRESH":        models.TokenTypeRefresh,
	"COUNT":          models.TokenTypeCount,
	"TO":             models.TokenTypeTo,
	"NULLS":          models.TokenTypeNulls,
	"FIRST":          models.TokenTypeFirst,
	"LAST":           models.TokenTypeLast,
	"FILTER":         models.TokenTypeFilter,
	"FOR":            models.TokenTypeFor,
	"SELECT":         models.TokenTypeSelect,
	"FROM":           models.TokenTypeFrom,
	"WHERE":          models.TokenTypeWhere,
	"AND":            models.TokenTypeAnd,
	"OR":             models.TokenTypeOr,
	"NOT":            models.TokenTypeNot,
	"NULL":           models.TokenTypeNull,
	"IN":             models.TokenTypeIn,
	"AS":             models.TokenTypeAs,
	"ON":             models.TokenTypeOn,
	"ORDER":          models.TokenTypeOrder,
	"BY":             models.TokenTypeBy,
	"GROUP":          models.TokenTypeGroup,
	"HAVING":         models.TokenTypeHaving,
	"LIMIT":          models.TokenTypeLimit,
	"OFFSET":         models.TokenTypeOffset,
	"TRUE":           models.TokenTypeTrue,
	"FALSE":          models.TokenTypeFalse,
	"TRUNCATE":       models.TokenTypeTruncate,
	"DATABASE":       models.TokenTypeDatabase,
	"SCHEMA":         models.TokenTypeSchema,
	"TRIGGER":        models.TokenTypeTrigger,
	"INTEGER":        models.TokenTypeInteger,
	"VARCHAR":        models.TokenTypeVarchar,
	"TEXT":           models.TokenTypeText,
	"BOOLEAN":        models.TokenTypeBoolean,
	"DATE":           models.TokenTypeDate,
	"TIMESTAMP":      models.TokenTypeTimestamp,
}

// goldenIdentifierKeywords lists every keyword handled by IdentifierKeywordType
// (a strict subset of goldenKeywordTypes).
var goldenIdentifierKeywords = []string{
	"INSERT",
	"UPDATE",
	"DELETE",
	"INTO",
	"VALUES",
	"SET",
	"CREATE",
	"ALTER",
	"DROP",
	"TABLE",
	"INDEX",
	"VIEW",
	"WITH",
	"RECURSIVE",
	"UNION",
	"EXCEPT",
	"INTERSECT",
	"ALL",
	"PRIMARY",
	"KEY",
	"FOREIGN",
	"REFERENCES",
	"UNIQUE",
	"CHECK",
	"DEFAULT",
	"CONSTRAINT",
	"AUTO_INCREMENT",
	"AUTOINCREMENT",
	"OVER",
	"PARTITION",
	"ROWS",
	"RANGE",
	"UNBOUNDED",
	"PRECEDING",
	"FOLLOWING",
	"CURRENT",
	"ROW",
	"CROSS",
	"NATURAL",
	"USING",
	"LATERAL",
	"DISTINCT",
	"EXISTS",
	"ANY",
	"SOME",
	"ROLLUP",
	"CUBE",
	"GROUPING",
	"ADD",
	"NOSUPERUSER",
	"NOCREATEDB",
	"NOCREATEROLE",
	"NOLOGIN",
	"VALID",
	"DCPROPERTIES",
	"URL",
	"OWNER",
	"MEMBER",
	"CONNECTOR",
	"POLICY",
	"UNTIL",
	"RESET",
}

// mixCase alternates upper/lower case per byte, starting with lower.
func mixCase(s string) string {
	b := []byte(strings.ToUpper(s))
	for i := 0; i < len(b); i += 2 {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func TestKeywordTypeCaseInsensitive(t *testing.T) {
	if len(goldenKeywordTypes) != 136 {
		t.Fatalf("golden table has %d entries, want 136", len(goldenKeywordTypes))
	}
	for kw, want := range goldenKeywordTypes {
		if len(kw) > MaxKeywordLen {
			t.Errorf("keyword %q is %d bytes, exceeds MaxKeywordLen=%d", kw, len(kw), MaxKeywordLen)
		}
		for _, in := range []string{kw, strings.ToLower(kw), mixCase(kw)} {
			if got := KeywordType(in); got != want {
				t.Errorf("KeywordType(%q) = %v, want %v", in, got, want)
			}
		}
	}
}

func TestIdentifierKeywordTypeSubset(t *testing.T) {
	if len(goldenIdentifierKeywords) != 62 {
		t.Fatalf("identifier keyword list has %d entries, want 62", len(goldenIdentifierKeywords))
	}
	inSubset := make(map[string]bool, len(goldenIdentifierKeywords))
	for _, kw := range goldenIdentifierKeywords {
		inSubset[kw] = true
		want, ok := goldenKeywordTypes[kw]
		if !ok {
			t.Errorf("identifier keyword %q missing from KeywordType golden table", kw)
			continue
		}
		if want == models.TokenTypeUnknown {
			t.Errorf("golden type for %q is Unknown", kw)
		}
		for _, in := range []string{kw, strings.ToLower(kw), mixCase(kw)} {
			if got := IdentifierKeywordType(in); got != want {
				t.Errorf("IdentifierKeywordType(%q) = %v, want %v", in, got, want)
			}
		}
	}
	for kw := range goldenKeywordTypes {
		if inSubset[kw] {
			continue
		}
		if got := IdentifierKeywordType(kw); got != models.TokenTypeUnknown {
			t.Errorf("IdentifierKeywordType(%q) = %v, want Unknown (keyword-only remap)", kw, got)
		}
	}
}

func TestKeywordTypeRejects(t *testing.T) {
	inputs := []string{
		"",
		"x",
		strings.Repeat("A", MaxKeywordLen+1),
		"AUTO_INCREMENTXYZ", // longer than the buffer
		"AUTO_INCREMENT_X",  // fits the buffer, not a keyword
		"auto_incremen",     // prefix of a keyword
		"SELECT ",           // trailing space
		" SELECT",           // leading space
		"S\u00c9LECT",       // non-ASCII bytes are not folded
		"s\u00e9l\u00e9ct",
	}
	for _, in := range inputs {
		if got := KeywordType(in); got != models.TokenTypeUnknown {
			t.Errorf("KeywordType(%q) = %v, want Unknown", in, got)
		}
		if got := IdentifierKeywordType(in); got != models.TokenTypeUnknown {
			t.Errorf("IdentifierKeywordType(%q) = %v, want Unknown", in, got)
		}
	}
}

var (
	testStart = models.Location{Line: 3, Column: 7}
	testEnd   = models.Location{Line: 3, Column: 17}
)

// wantParts builds the expected sub-token slice for a compound expansion.
func wantParts(parts ...models.Token) []models.TokenWithSpan {
	out := make([]models.TokenWithSpan, len(parts))
	for i, p := range parts {
		out[i] = models.TokenWithSpan{Token: p, Start: testStart, End: testEnd}
	}
	return out
}

func mtok(typ models.TokenType, val string) models.Token {
	return models.Token{Type: typ, Value: val}
}

func TestAppendCompoundGolden(t *testing.T) {
	inner := wantParts(mtok(models.TokenTypeInner, "INNER"), mtok(models.TokenTypeJoin, "JOIN"))
	left := wantParts(mtok(models.TokenTypeLeft, "LEFT"), mtok(models.TokenTypeJoin, "JOIN"))
	right := wantParts(mtok(models.TokenTypeRight, "RIGHT"), mtok(models.TokenTypeJoin, "JOIN"))
	outer := wantParts(mtok(models.TokenTypeOuter, "OUTER"), mtok(models.TokenTypeJoin, "JOIN"))
	full := wantParts(mtok(models.TokenTypeFull, "FULL"), mtok(models.TokenTypeJoin, "JOIN"))
	cross := wantParts(mtok(models.TokenTypeCross, "CROSS"), mtok(models.TokenTypeJoin, "JOIN"))
	orderBy := wantParts(mtok(models.TokenTypeOrder, "ORDER"), mtok(models.TokenTypeBy, "BY"))
	groupBy := wantParts(mtok(models.TokenTypeGroup, "GROUP"), mtok(models.TokenTypeBy, "BY"))
	groupingSets := wantParts(mtok(models.TokenTypeGrouping, "GROUPING"), mtok(models.TokenTypeSets, "SETS"))
	leftOuter := wantParts(mtok(models.TokenTypeLeft, "LEFT"), mtok(models.TokenTypeOuter, "OUTER"), mtok(models.TokenTypeJoin, "JOIN"))
	rightOuter := wantParts(mtok(models.TokenTypeRight, "RIGHT"), mtok(models.TokenTypeOuter, "OUTER"), mtok(models.TokenTypeJoin, "JOIN"))
	fullOuter := wantParts(mtok(models.TokenTypeFull, "FULL"), mtok(models.TokenTypeOuter, "OUTER"), mtok(models.TokenTypeJoin, "JOIN"))

	tests := []struct {
		name string
		typ  models.TokenType
		val  string
		want []models.TokenWithSpan
	}{
		// Type-based: Value is deliberately lowercase and must be ignored.
		{"type InnerJoin", models.TokenTypeInnerJoin, "inner join", inner},
		{"type LeftJoin", models.TokenTypeLeftJoin, "left join", left},
		{"type RightJoin", models.TokenTypeRightJoin, "right join", right},
		{"type OuterJoin", models.TokenTypeOuterJoin, "outer join", outer},
		{"type FullJoin", models.TokenTypeFullJoin, "full join", full},
		{"type CrossJoin", models.TokenTypeCrossJoin, "cross join", cross},
		{"type OrderBy", models.TokenTypeOrderBy, "order by", orderBy},
		{"type GroupBy", models.TokenTypeGroupBy, "group by", groupBy},
		{"type GroupingSets", models.TokenTypeGroupingSets, "grouping sets", groupingSets},
		// Value-based: generic keyword tokens with a multi-word value.
		{"value INNER JOIN", models.TokenTypeKeyword, "INNER JOIN", inner},
		{"value LEFT JOIN", models.TokenTypeKeyword, "LEFT JOIN", left},
		{"value RIGHT JOIN", models.TokenTypeKeyword, "RIGHT JOIN", right},
		{"value FULL JOIN", models.TokenTypeKeyword, "FULL JOIN", full},
		{"value CROSS JOIN", models.TokenTypeKeyword, "CROSS JOIN", cross},
		{"value LEFT OUTER JOIN", models.TokenTypeKeyword, "LEFT OUTER JOIN", leftOuter},
		{"value RIGHT OUTER JOIN", models.TokenTypeKeyword, "RIGHT OUTER JOIN", rightOuter},
		{"value FULL OUTER JOIN", models.TokenTypeKeyword, "FULL OUTER JOIN", fullOuter},
		{"value ORDER BY", models.TokenTypeKeyword, "ORDER BY", orderBy},
		{"value GROUP BY", models.TokenTypeKeyword, "GROUP BY", groupBy},
		{"value GROUPING SETS", models.TokenTypeKeyword, "GROUPING SETS", groupingSets},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := models.TokenWithSpan{
				Token: models.Token{Type: tc.typ, Value: tc.val, Word: &models.Word{Value: tc.val}, Long: true},
				Start: testStart,
				End:   testEnd,
			}
			sentinel := models.TokenWithSpan{Token: mtok(models.TokenTypeSelect, "SELECT")}
			got, ok := AppendCompound([]models.TokenWithSpan{sentinel}, &in)
			if !ok {
				t.Fatalf("AppendCompound ok = false, want true")
			}
			want := append([]models.TokenWithSpan{sentinel}, tc.want...)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("AppendCompound mismatch:\n got  %+v\n want %+v", got, want)
			}
		})
	}

	t.Run("non-compound", func(t *testing.T) {
		in := models.TokenWithSpan{Token: mtok(models.TokenTypeIdentifier, "users"), Start: testStart, End: testEnd}
		dst := []models.TokenWithSpan{{Token: mtok(models.TokenTypeSelect, "SELECT")}}
		got, ok := AppendCompound(dst, &in)
		if ok {
			t.Fatal("AppendCompound ok = true for identifier, want false")
		}
		if !reflect.DeepEqual(got, dst) {
			t.Errorf("dst changed for non-compound token: %+v", got)
		}
	})
}

var sinkType models.TokenType

func TestRemapAndCompoundAllocs(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not stable under the race detector")
	}

	if n := testing.AllocsPerRun(1000, func() { sinkType = IdentifierKeywordType("auto_increment") }); n != 0 {
		t.Errorf("IdentifierKeywordType allocs = %v, want 0", n)
	}
	if n := testing.AllocsPerRun(1000, func() { sinkType = KeywordType("materialized") }); n != 0 {
		t.Errorf("KeywordType allocs = %v, want 0", n)
	}

	compound := models.TokenWithSpan{Token: mtok(models.TokenTypeKeyword, "LEFT OUTER JOIN"), Start: testStart, End: testEnd}
	dst := make([]models.TokenWithSpan, 0, 8)
	if n := testing.AllocsPerRun(1000, func() {
		dst, _ = AppendCompound(dst[:0], &compound)
	}); n != 0 {
		t.Errorf("AppendCompound allocs = %v, want 0", n)
	}
}
