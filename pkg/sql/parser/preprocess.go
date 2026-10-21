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

// preprocessTokens implements token preprocessing (normalization) for the parser.
// It replaces the old token_conversion.go conversion layer.
// Instead of converting models.TokenWithSpan → token.Token (which stripped span
// information), it normalises a []models.TokenWithSpan in-place so the parser
// can consume it directly.
//
// The two responsibilities of the old layer are preserved here:
//
//  1. Compound-token expansion   – e.g. a single INNER_JOIN token becomes
//     [INNER, JOIN] (each carrying the original span).
//  2. Token-type normalisation – identifier/keyword strings whose type was
//     not resolved by the tokenizer are remapped to the appropriate
//     models.TokenType constant.

package parser

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// maxKeywordLen is the size of the stack buffer used to upper-case a value
// before matching it against the keyword tables. The longest remapped keyword
// is AUTO_INCREMENT (14 bytes); TestKeywordTypeCaseInsensitive asserts every
// table entry fits. Longer values cannot be keywords and are rejected early.
const maxKeywordLen = 16

// preprocessTokens normalises a token stream for the parser.
// It expands compound tokens and remaps identifier/keyword types, returning a
// new slice of models.TokenWithSpan that the parser consumes directly.
//
// The returned slice is freshly allocated and owned by the caller; use it when
// the preprocessed stream outlives the parse (e.g. ParseBytesWithTokens).
func preprocessTokens(tokens []models.TokenWithSpan) []models.TokenWithSpan {
	return preprocessTokensInto(nil, tokens)
}

// preprocessTokensInto is preprocessTokens appending into dst[:0], so a caller
// that owns a scratch buffer (Parser.tokenBuf) can reuse it across parses.
// It allocates only when cap(dst) < len(tokens)+4 (the headroom covers the
// common compound-token expansions).
//
// dst must not alias tokens. The returned slice may share dst's backing array,
// so it must not be handed to anyone who could outlive the next call with the
// same dst.
func preprocessTokensInto(dst, tokens []models.TokenWithSpan) []models.TokenWithSpan {
	dst = dst[:0]
	if need := len(tokens) + 4; cap(dst) < need {
		dst = make([]models.TokenWithSpan, 0, need)
	}
	for i := range tokens {
		var ok bool
		if dst, ok = appendCompound(dst, &tokens[i]); ok {
			continue
		}
		dst = append(dst, normalizeToken(tokens[i]))
	}
	return dst
}

// Compound token expansion tables. These slices are shared, read-only package
// data and must never be mutated: appendCompound copies each element into a
// fresh TokenWithSpan, so callers never alias them.
var (
	compoundInnerJoin      = []models.Token{{Type: models.TokenTypeInner, Value: "INNER"}, {Type: models.TokenTypeJoin, Value: "JOIN"}}
	compoundLeftJoin       = []models.Token{{Type: models.TokenTypeLeft, Value: "LEFT"}, {Type: models.TokenTypeJoin, Value: "JOIN"}}
	compoundRightJoin      = []models.Token{{Type: models.TokenTypeRight, Value: "RIGHT"}, {Type: models.TokenTypeJoin, Value: "JOIN"}}
	compoundOuterJoin      = []models.Token{{Type: models.TokenTypeOuter, Value: "OUTER"}, {Type: models.TokenTypeJoin, Value: "JOIN"}}
	compoundFullJoin       = []models.Token{{Type: models.TokenTypeFull, Value: "FULL"}, {Type: models.TokenTypeJoin, Value: "JOIN"}}
	compoundCrossJoin      = []models.Token{{Type: models.TokenTypeCross, Value: "CROSS"}, {Type: models.TokenTypeJoin, Value: "JOIN"}}
	compoundOrderBy        = []models.Token{{Type: models.TokenTypeOrder, Value: "ORDER"}, {Type: models.TokenTypeBy, Value: "BY"}}
	compoundGroupBy        = []models.Token{{Type: models.TokenTypeGroup, Value: "GROUP"}, {Type: models.TokenTypeBy, Value: "BY"}}
	compoundGroupingSets   = []models.Token{{Type: models.TokenTypeGrouping, Value: "GROUPING"}, {Type: models.TokenTypeSets, Value: "SETS"}}
	compoundLeftOuterJoin  = []models.Token{{Type: models.TokenTypeLeft, Value: "LEFT"}, {Type: models.TokenTypeOuter, Value: "OUTER"}, {Type: models.TokenTypeJoin, Value: "JOIN"}}
	compoundRightOuterJoin = []models.Token{{Type: models.TokenTypeRight, Value: "RIGHT"}, {Type: models.TokenTypeOuter, Value: "OUTER"}, {Type: models.TokenTypeJoin, Value: "JOIN"}}
	compoundFullOuterJoin  = []models.Token{{Type: models.TokenTypeFull, Value: "FULL"}, {Type: models.TokenTypeOuter, Value: "OUTER"}, {Type: models.TokenTypeJoin, Value: "JOIN"}}
)

// compoundByValue maps the multi-word Value of a generic keyword token to its
// sub-token table. Matching is ASCII case-insensitive; see compoundParts.
var compoundByValue = [...]struct {
	value string
	parts []models.Token
}{
	{"INNER JOIN", compoundInnerJoin},
	{"LEFT JOIN", compoundLeftJoin},
	{"RIGHT JOIN", compoundRightJoin},
	{"FULL JOIN", compoundFullJoin},
	{"CROSS JOIN", compoundCrossJoin},
	{"LEFT OUTER JOIN", compoundLeftOuterJoin},
	{"RIGHT OUTER JOIN", compoundRightOuterJoin},
	{"FULL OUTER JOIN", compoundFullOuterJoin},
	{"ORDER BY", compoundOrderBy},
	{"GROUP BY", compoundGroupBy},
	{"GROUPING SETS", compoundGroupingSets},
}

// compoundParts returns the read-only sub-token table for a compound token such
// as INNER_JOIN → [INNER, JOIN], or nil if the token is not compound.
// The returned slice is shared package data and must not be modified.
func compoundParts(t *models.TokenWithSpan) []models.Token {
	switch t.Token.Type {
	case models.TokenTypeInnerJoin:
		return compoundInnerJoin
	case models.TokenTypeLeftJoin:
		return compoundLeftJoin
	case models.TokenTypeRightJoin:
		return compoundRightJoin
	case models.TokenTypeOuterJoin:
		return compoundOuterJoin
	case models.TokenTypeFullJoin:
		return compoundFullJoin
	case models.TokenTypeCrossJoin:
		return compoundCrossJoin
	case models.TokenTypeOrderBy:
		return compoundOrderBy
	case models.TokenTypeGroupBy:
		return compoundGroupBy
	case models.TokenTypeGroupingSets:
		return compoundGroupingSets
	}

	// Value-based compound token matching. The tokenizer emits these as
	// TokenTypeKeyword whose Value keeps the source spelling ("cross join",
	// "Grouping Sets"), so the match is case-insensitive (#842). Only keyword
	// tokens qualify: a string literal such as 'CROSS JOIN' is not a join.
	if t.Token.Type != models.TokenTypeKeyword {
		return nil
	}
	v := t.Token.Value
	for i := range compoundByValue {
		if len(v) == len(compoundByValue[i].value) && strings.EqualFold(v, compoundByValue[i].value) {
			return compoundByValue[i].parts
		}
	}
	return nil
}

// appendCompound appends the expansion of compound token t to dst, copying
// t's span onto every sub-token. It reports false (leaving dst unchanged) if t
// is not a compound token. It performs no allocation beyond growing dst.
func appendCompound(dst []models.TokenWithSpan, t *models.TokenWithSpan) ([]models.TokenWithSpan, bool) {
	parts := compoundParts(t)
	if parts == nil {
		return dst, false
	}
	for i := range parts {
		dst = append(dst, models.TokenWithSpan{Token: parts[i], Start: t.Start, End: t.End})
	}
	return dst, true
}

// normalizeToken maps a TokenWithSpan to a canonical form expected by the
// parser. Type mismatches that existed in the tokenizer are corrected here.
func normalizeToken(t models.TokenWithSpan) models.TokenWithSpan {
	// TokenTypeMul (*) is the same symbol as TokenTypeAsterisk for the
	// parser. The parser explicitly checks both types wherever '*' can appear
	// (SELECT list wildcard, table.* qualified wildcard, COUNT(*) argument).
	// No remap is performed here to preserve the distinction for binary multiply.

	// Aggregate-function tokens (COUNT, SUM, AVG, MIN, MAX) must be treated
	// as identifiers so they can be used as function-call names.
	switch t.Token.Type {
	case models.TokenTypeCount, models.TokenTypeSum, models.TokenTypeAvg,
		models.TokenTypeMin, models.TokenTypeMax:
		t.Token.Type = models.TokenTypeIdentifier
		return t
	}

	// Identifier tokens whose *value* is a keyword that the parser dispatches
	// on by type need to be remapped.
	if t.Token.Type == models.TokenTypeIdentifier {
		if remapped := identifierKeywordType(t.Token.Value); remapped != models.TokenTypeUnknown {
			t.Token.Type = remapped
		}
		return t
	}

	// Generic TokenTypeKeyword tokens need a specific type for the parser.
	if t.Token.Type == models.TokenTypeKeyword {
		if remapped := keywordType(t.Token.Value); remapped != models.TokenTypeUnknown {
			t.Token.Type = remapped
		}
		return t
	}

	return t
}

// identifierKeywordType remaps identifiers that carry SQL keyword values to
// their specific models.TokenType. This is conservative: only keywords that
// the parser dispatches on by type are included.
func identifierKeywordType(value string) models.TokenType {
	if len(value) > maxKeywordLen {
		return models.TokenTypeUnknown
	}
	// ASCII upper-case into a local buffer. The loop is intentionally inline
	// (no helper, no &buf): taking the array's address is ~2.4x slower, and
	// switch string(buf[:n]) does not allocate.
	var buf [maxKeywordLen]byte
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		buf[i] = c
	}
	switch string(buf[:len(value)]) {
	case "INSERT":
		return models.TokenTypeInsert
	case "UPDATE":
		return models.TokenTypeUpdate
	case "DELETE":
		return models.TokenTypeDelete
	case "INTO":
		return models.TokenTypeInto
	case "VALUES":
		return models.TokenTypeValues
	case "SET":
		return models.TokenTypeSet
	case "CREATE":
		return models.TokenTypeCreate
	case "ALTER":
		return models.TokenTypeAlter
	case "DROP":
		return models.TokenTypeDrop
	case "TABLE":
		return models.TokenTypeTable
	case "INDEX":
		return models.TokenTypeIndex
	case "VIEW":
		return models.TokenTypeView
	case "WITH":
		return models.TokenTypeWith
	case "RECURSIVE":
		return models.TokenTypeRecursive
	case "UNION":
		return models.TokenTypeUnion
	case "EXCEPT":
		return models.TokenTypeExcept
	case "INTERSECT":
		return models.TokenTypeIntersect
	case "ALL":
		return models.TokenTypeAll
	case "PRIMARY":
		return models.TokenTypePrimary
	case "KEY":
		return models.TokenTypeKey
	case "FOREIGN":
		return models.TokenTypeForeign
	case "REFERENCES":
		return models.TokenTypeReferences
	case "UNIQUE":
		return models.TokenTypeUnique
	case "CHECK":
		return models.TokenTypeCheck
	case "DEFAULT":
		return models.TokenTypeDefault
	case "CONSTRAINT":
		return models.TokenTypeConstraint
	case "AUTO_INCREMENT", "AUTOINCREMENT":
		return models.TokenTypeAutoIncrement
	case "OVER":
		return models.TokenTypeOver
	case "PARTITION":
		return models.TokenTypePartition
	case "ROWS":
		return models.TokenTypeRows
	case "RANGE":
		return models.TokenTypeRange
	case "UNBOUNDED":
		return models.TokenTypeUnbounded
	case "PRECEDING":
		return models.TokenTypePreceding
	case "FOLLOWING":
		return models.TokenTypeFollowing
	case "CURRENT":
		return models.TokenTypeCurrent
	case "ROW":
		return models.TokenTypeRow
	case "CROSS":
		return models.TokenTypeCross
	case "NATURAL":
		return models.TokenTypeNatural
	case "USING":
		return models.TokenTypeUsing
	case "LATERAL":
		return models.TokenTypeLateral
	case "DISTINCT":
		return models.TokenTypeDistinct
	case "EXISTS":
		return models.TokenTypeExists
	case "ANY":
		return models.TokenTypeAny
	case "SOME":
		return models.TokenTypeSome
	case "ROLLUP":
		return models.TokenTypeRollup
	case "CUBE":
		return models.TokenTypeCube
	case "GROUPING":
		return models.TokenTypeGrouping
	case "ADD":
		return models.TokenTypeAdd
	case "NOSUPERUSER":
		return models.TokenTypeNosuperuser
	case "NOCREATEDB":
		return models.TokenTypeNocreatedb
	case "NOCREATEROLE":
		return models.TokenTypeNocreaterole
	case "NOLOGIN":
		return models.TokenTypeNologin
	case "VALID":
		return models.TokenTypeValid
	case "DCPROPERTIES":
		return models.TokenTypeDcproperties
	case "URL":
		return models.TokenTypeUrl
	case "OWNER":
		return models.TokenTypeOwner
	case "MEMBER":
		return models.TokenTypeMember
	case "CONNECTOR":
		return models.TokenTypeConnector
	case "POLICY":
		return models.TokenTypePolicy
	case "UNTIL":
		return models.TokenTypeUntil
	case "RESET":
		return models.TokenTypeReset
	default:
		return models.TokenTypeUnknown
	}
}

// keywordType maps generic TokenTypeKeyword strings to specific token types.
func keywordType(value string) models.TokenType {
	if len(value) > maxKeywordLen {
		return models.TokenTypeUnknown
	}
	// ASCII upper-case into a local buffer. The loop is intentionally inline
	// (no helper, no &buf): taking the array's address is ~2.4x slower, and
	// switch string(buf[:n]) does not allocate.
	var buf [maxKeywordLen]byte
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		buf[i] = c
	}
	switch string(buf[:len(value)]) {
	case "INSERT":
		return models.TokenTypeInsert
	case "UPDATE":
		return models.TokenTypeUpdate
	case "DELETE":
		return models.TokenTypeDelete
	case "INTO":
		return models.TokenTypeInto
	case "VALUES":
		return models.TokenTypeValues
	case "SET":
		return models.TokenTypeSet
	case "CREATE":
		return models.TokenTypeCreate
	case "ALTER":
		return models.TokenTypeAlter
	case "DROP":
		return models.TokenTypeDrop
	case "TABLE":
		return models.TokenTypeTable
	case "INDEX":
		return models.TokenTypeIndex
	case "VIEW":
		return models.TokenTypeView
	case "WITH":
		return models.TokenTypeWith
	case "RECURSIVE":
		return models.TokenTypeRecursive
	case "UNION":
		return models.TokenTypeUnion
	case "EXCEPT":
		return models.TokenTypeExcept
	case "INTERSECT":
		return models.TokenTypeIntersect
	case "ALL":
		return models.TokenTypeAll
	case "PRIMARY":
		return models.TokenTypePrimary
	case "KEY":
		return models.TokenTypeKey
	case "FOREIGN":
		return models.TokenTypeForeign
	case "REFERENCES":
		return models.TokenTypeReferences
	case "UNIQUE":
		return models.TokenTypeUnique
	case "CHECK":
		return models.TokenTypeCheck
	case "DEFAULT":
		return models.TokenTypeDefault
	case "CONSTRAINT":
		return models.TokenTypeConstraint
	case "AUTO_INCREMENT", "AUTOINCREMENT":
		return models.TokenTypeAutoIncrement
	case "OVER":
		return models.TokenTypeOver
	case "PARTITION":
		return models.TokenTypePartition
	case "ROWS":
		return models.TokenTypeRows
	case "RANGE":
		return models.TokenTypeRange
	case "UNBOUNDED":
		return models.TokenTypeUnbounded
	case "PRECEDING":
		return models.TokenTypePreceding
	case "FOLLOWING":
		return models.TokenTypeFollowing
	case "CURRENT":
		return models.TokenTypeCurrent
	case "ROW":
		return models.TokenTypeRow
	case "CROSS":
		return models.TokenTypeCross
	case "NATURAL":
		return models.TokenTypeNatural
	case "USING":
		return models.TokenTypeUsing
	case "LATERAL":
		return models.TokenTypeLateral
	case "DISTINCT":
		return models.TokenTypeDistinct
	case "EXISTS":
		return models.TokenTypeExists
	case "ANY":
		return models.TokenTypeAny
	case "SOME":
		return models.TokenTypeSome
	case "ROLLUP":
		return models.TokenTypeRollup
	case "CUBE":
		return models.TokenTypeCube
	case "GROUPING":
		return models.TokenTypeGrouping
	case "ADD":
		return models.TokenTypeAdd
	case "NOSUPERUSER":
		return models.TokenTypeNosuperuser
	case "NOCREATEDB":
		return models.TokenTypeNocreatedb
	case "NOCREATEROLE":
		return models.TokenTypeNocreaterole
	case "NOLOGIN":
		return models.TokenTypeNologin
	case "VALID":
		return models.TokenTypeValid
	case "DCPROPERTIES":
		return models.TokenTypeDcproperties
	case "URL":
		return models.TokenTypeUrl
	case "OWNER":
		return models.TokenTypeOwner
	case "MEMBER":
		return models.TokenTypeMember
	case "CONNECTOR":
		return models.TokenTypeConnector
	case "POLICY":
		return models.TokenTypePolicy
	case "UNTIL":
		return models.TokenTypeUntil
	case "RESET":
		return models.TokenTypeReset
	case "RENAME":
		return models.TokenTypeRename
	case "COLUMN":
		return models.TokenTypeColumn
	case "CASCADE":
		return models.TokenTypeCascade
	case "RESTRICT":
		return models.TokenTypeRestrict
	case "MATERIALIZED":
		return models.TokenTypeMaterialized
	case "REPLACE":
		return models.TokenTypeReplace
	case "COLLATE":
		return models.TokenTypeCollate
	case "ASC":
		return models.TokenTypeAsc
	case "DESC":
		return models.TokenTypeDesc
	case "JOIN":
		return models.TokenTypeJoin
	case "INNER":
		return models.TokenTypeInner
	case "LEFT":
		return models.TokenTypeLeft
	case "RIGHT":
		return models.TokenTypeRight
	case "FULL":
		return models.TokenTypeFull
	case "OUTER":
		return models.TokenTypeOuter
	case "IS":
		return models.TokenTypeIs
	case "LIKE":
		return models.TokenTypeLike
	case "ILIKE":
		return models.TokenTypeILike
	case "BETWEEN":
		return models.TokenTypeBetween
	case "CASE":
		return models.TokenTypeCase
	case "WHEN":
		return models.TokenTypeWhen
	case "THEN":
		return models.TokenTypeThen
	case "ELSE":
		return models.TokenTypeElse
	case "END":
		return models.TokenTypeEnd
	case "CAST":
		return models.TokenTypeCast
	case "INTERVAL":
		return models.TokenTypeInterval
	case "MERGE":
		return models.TokenTypeMerge
	case "MATCHED":
		return models.TokenTypeMatched
	case "SOURCE":
		return models.TokenTypeSource
	case "TARGET":
		return models.TokenTypeTarget
	case "SETS":
		return models.TokenTypeSets
	case "FETCH":
		return models.TokenTypeFetch
	case "NEXT":
		return models.TokenTypeNext
	case "TIES":
		return models.TokenTypeTies
	case "PERCENT":
		return models.TokenTypePercent
	case "ONLY":
		return models.TokenTypeOnly
	case "SHARE":
		return models.TokenTypeShare
	case "IF":
		return models.TokenTypeIf
	case "REFRESH":
		return models.TokenTypeRefresh
	case "COUNT":
		return models.TokenTypeCount
	case "TO":
		return models.TokenTypeTo
	case "NULLS":
		return models.TokenTypeNulls
	case "FIRST":
		return models.TokenTypeFirst
	case "LAST":
		return models.TokenTypeLast
	case "FILTER":
		return models.TokenTypeFilter
	case "FOR":
		return models.TokenTypeFor
	case "SELECT":
		return models.TokenTypeSelect
	case "FROM":
		return models.TokenTypeFrom
	case "WHERE":
		return models.TokenTypeWhere
	case "AND":
		return models.TokenTypeAnd
	case "OR":
		return models.TokenTypeOr
	case "NOT":
		return models.TokenTypeNot
	case "NULL":
		return models.TokenTypeNull
	case "IN":
		return models.TokenTypeIn
	case "AS":
		return models.TokenTypeAs
	case "ON":
		return models.TokenTypeOn
	case "ORDER":
		return models.TokenTypeOrder
	case "BY":
		return models.TokenTypeBy
	case "GROUP":
		return models.TokenTypeGroup
	case "HAVING":
		return models.TokenTypeHaving
	case "LIMIT":
		return models.TokenTypeLimit
	case "OFFSET":
		return models.TokenTypeOffset
	case "TRUE":
		return models.TokenTypeTrue
	case "FALSE":
		return models.TokenTypeFalse
	case "TRUNCATE":
		return models.TokenTypeTruncate
	case "DATABASE":
		return models.TokenTypeDatabase
	case "SCHEMA":
		return models.TokenTypeSchema
	case "TRIGGER":
		return models.TokenTypeTrigger
	case "INTEGER":
		return models.TokenTypeInteger
	case "VARCHAR":
		return models.TokenTypeVarchar
	case "TEXT":
		return models.TokenTypeText
	case "BOOLEAN":
		return models.TokenTypeBoolean
	case "DATE":
		return models.TokenTypeDate
	case "TIMESTAMP":
		return models.TokenTypeTimestamp
	default:
		return models.TokenTypeUnknown
	}
}
