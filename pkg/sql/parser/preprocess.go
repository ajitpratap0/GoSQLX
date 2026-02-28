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
	"sync"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// kwBufPool is a small byte-buffer pool used to avoid allocations during
// upper-case conversion of short keyword strings.
var kwBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 32)
		return &buf
	},
}

// preprocessTokens normalises a token stream for the parser.
// It expands compound tokens and remaps identifier/keyword types, returning a
// new slice of models.TokenWithSpan that the parser consumes directly.
func preprocessTokens(tokens []models.TokenWithSpan) []models.TokenWithSpan {
	result := make([]models.TokenWithSpan, 0, len(tokens)+4)
	for i := range tokens {
		t := tokens[i]
		if expanded := expandCompoundToken(t); len(expanded) > 0 {
			result = append(result, expanded...)
			continue
		}
		result = append(result, normalizeToken(t))
	}
	return result
}

// expandCompoundToken returns the expansion of a compound token such as
// INNER_JOIN → [INNER, JOIN]. Returns nil if the token is not compound.
func expandCompoundToken(t models.TokenWithSpan) []models.TokenWithSpan {
	makeTwo := func(t1Type models.TokenType, t1Val, t2Val string, t2Type models.TokenType) []models.TokenWithSpan {
		return []models.TokenWithSpan{
			{Token: models.Token{Type: t1Type, Value: t1Val}, Start: t.Start, End: t.End},
			{Token: models.Token{Type: t2Type, Value: t2Val}, Start: t.Start, End: t.End},
		}
	}
	makeThree := func(t1Type models.TokenType, t1Val string, t2Type models.TokenType, t2Val string, t3Type models.TokenType, t3Val string) []models.TokenWithSpan {
		return []models.TokenWithSpan{
			{Token: models.Token{Type: t1Type, Value: t1Val}, Start: t.Start, End: t.End},
			{Token: models.Token{Type: t2Type, Value: t2Val}, Start: t.Start, End: t.End},
			{Token: models.Token{Type: t3Type, Value: t3Val}, Start: t.Start, End: t.End},
		}
	}

	switch t.Token.Type {
	case models.TokenTypeInnerJoin:
		return makeTwo(models.TokenTypeInner, "INNER", "JOIN", models.TokenTypeJoin)
	case models.TokenTypeLeftJoin:
		return makeTwo(models.TokenTypeLeft, "LEFT", "JOIN", models.TokenTypeJoin)
	case models.TokenTypeRightJoin:
		return makeTwo(models.TokenTypeRight, "RIGHT", "JOIN", models.TokenTypeJoin)
	case models.TokenTypeOuterJoin:
		return makeTwo(models.TokenTypeOuter, "OUTER", "JOIN", models.TokenTypeJoin)
	case models.TokenTypeFullJoin:
		return makeTwo(models.TokenTypeFull, "FULL", "JOIN", models.TokenTypeJoin)
	case models.TokenTypeCrossJoin:
		return makeTwo(models.TokenTypeCross, "CROSS", "JOIN", models.TokenTypeJoin)
	case models.TokenTypeOrderBy:
		return makeTwo(models.TokenTypeOrder, "ORDER", "BY", models.TokenTypeBy)
	case models.TokenTypeGroupBy:
		return makeTwo(models.TokenTypeGroup, "GROUP", "BY", models.TokenTypeBy)
	case models.TokenTypeGroupingSets:
		return makeTwo(models.TokenTypeGrouping, "GROUPING", "SETS", models.TokenTypeSets)
	}

	// Value-based compound token matching (tokenizer may produce these as
	// TokenTypeKeyword with a multi-word value).
	switch t.Token.Value {
	case "INNER JOIN":
		return makeTwo(models.TokenTypeInner, "INNER", "JOIN", models.TokenTypeJoin)
	case "LEFT JOIN":
		return makeTwo(models.TokenTypeLeft, "LEFT", "JOIN", models.TokenTypeJoin)
	case "RIGHT JOIN":
		return makeTwo(models.TokenTypeRight, "RIGHT", "JOIN", models.TokenTypeJoin)
	case "FULL JOIN":
		return makeTwo(models.TokenTypeFull, "FULL", "JOIN", models.TokenTypeJoin)
	case "CROSS JOIN":
		return makeTwo(models.TokenTypeCross, "CROSS", "JOIN", models.TokenTypeJoin)
	case "LEFT OUTER JOIN":
		return makeThree(models.TokenTypeLeft, "LEFT", models.TokenTypeOuter, "OUTER", models.TokenTypeJoin, "JOIN")
	case "RIGHT OUTER JOIN":
		return makeThree(models.TokenTypeRight, "RIGHT", models.TokenTypeOuter, "OUTER", models.TokenTypeJoin, "JOIN")
	case "FULL OUTER JOIN":
		return makeThree(models.TokenTypeFull, "FULL", models.TokenTypeOuter, "OUTER", models.TokenTypeJoin, "JOIN")
	case "ORDER BY":
		return makeTwo(models.TokenTypeOrder, "ORDER", "BY", models.TokenTypeBy)
	case "GROUP BY":
		return makeTwo(models.TokenTypeGroup, "GROUP", "BY", models.TokenTypeBy)
	case "GROUPING SETS":
		return makeTwo(models.TokenTypeGrouping, "GROUPING", "SETS", models.TokenTypeSets)
	}

	return nil
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

// toUpper converts s to uppercase using a pooled byte buffer for short strings.
func toUpper(s string) string {
	n := len(s)
	var upper []byte
	if n <= 32 {
		bufPtr := kwBufPool.Get().(*[]byte)
		upper = (*bufPtr)[:n]
		defer kwBufPool.Put(bufPtr)
	} else {
		upper = make([]byte, n)
	}
	for i := 0; i < n; i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			upper[i] = c - 32
		} else {
			upper[i] = c
		}
	}
	return string(upper)
}

// identifierKeywordType remaps identifiers that carry SQL keyword values to
// their specific models.TokenType. This is conservative: only keywords that
// the parser dispatches on by type are included.
func identifierKeywordType(value string) models.TokenType {
	switch toUpper(value) {
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
	switch toUpper(value) {
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
