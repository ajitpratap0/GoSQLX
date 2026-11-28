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

package tokclass

import "github.com/ajitpratap0/GoSQLX/pkg/models"

// MaxKeywordLen is the size of the stack buffer used to upper-case a value
// before matching it against the keyword tables. The longest remapped keyword
// is AUTO_INCREMENT (14 bytes); TestKeywordTypeCaseInsensitive asserts every
// table entry fits. Longer values cannot be keywords and are rejected early.
const MaxKeywordLen = 16

// IdentifierKeywordType remaps identifiers that carry SQL keyword values to
// their specific models.TokenType. This is conservative: only keywords that
// the parser dispatches on by type are included.
func IdentifierKeywordType(value string) models.TokenType {
	if len(value) > MaxKeywordLen {
		return models.TokenTypeUnknown
	}
	// ASCII upper-case into a local buffer. The loop is intentionally inline
	// (no helper, no &buf): taking the array's address is ~2.4x slower, and
	// switch string(buf[:n]) does not allocate.
	var buf [MaxKeywordLen]byte
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

// KeywordType maps generic TokenTypeKeyword strings to specific token types.
func KeywordType(value string) models.TokenType {
	if len(value) > MaxKeywordLen {
		return models.TokenTypeUnknown
	}
	// ASCII upper-case into a local buffer. The loop is intentionally inline
	// (no helper, no &buf): taking the array's address is ~2.4x slower, and
	// switch string(buf[:n]) does not allocate.
	var buf [MaxKeywordLen]byte
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

// identifierRemapKeys is the domain of IdentifierKeywordType: exactly the
// upper-case words for which it returns a type other than Unknown.
// TestIdentifierRemapKeysAreTheDomain keeps it in step with the switch.
var identifierRemapKeys = [...]string{
	"ADD", "ALL", "ALTER", "ANY", "AUTOINCREMENT", "AUTO_INCREMENT", "CHECK",
	"CONNECTOR", "CONSTRAINT", "CREATE", "CROSS", "CUBE", "CURRENT",
	"DCPROPERTIES", "DEFAULT", "DELETE", "DISTINCT", "DROP", "EXCEPT",
	"EXISTS", "FOLLOWING", "FOREIGN", "GROUPING", "INDEX", "INSERT",
	"INTERSECT", "INTO", "KEY", "LATERAL", "MEMBER", "NATURAL", "NOCREATEDB",
	"NOCREATEROLE", "NOLOGIN", "NOSUPERUSER", "OVER", "OWNER", "PARTITION",
	"POLICY", "PRECEDING", "PRIMARY", "RANGE", "RECURSIVE", "REFERENCES",
	"RESET", "ROLLUP", "ROW", "ROWS", "SET", "SOME", "TABLE", "UNBOUNDED",
	"UNION", "UNIQUE", "UNTIL", "UPDATE", "URL", "USING", "VALID", "VALUES",
	"VIEW", "WITH",
}

// IdentifierRemapKeys returns, sorted, every upper-case word that
// IdentifierKeywordType remaps. A keyword table that pre-computes parser
// types (the tokenizer's, in a later change) uses it to insert the words that
// are remapped without being tokenizer keywords. The slice is a fresh copy.
func IdentifierRemapKeys() []string {
	out := make([]string, len(identifierRemapKeys))
	copy(out, identifierRemapKeys[:])
	return out
}
