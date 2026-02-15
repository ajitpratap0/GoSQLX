package parser

// token_conversion.go contains internal token conversion logic from models.TokenWithSpan
// to token.Token. This is an unexported implementation detail used by ParseFromModelTokens.

import (
	"sync"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"

	"fmt"
)

var keywordBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 32)
		return &buf
	},
}

// ConversionResult contains converted tokens and position mappings for error reporting.
type ConversionResult struct {
	Tokens          []token.Token
	PositionMapping []TokenPosition
}

// TokenPosition maps a parser token back to its original source position.
type TokenPosition struct {
	OriginalIndex int
	Start         models.Location
	End           models.Location
	SourceToken   *models.TokenWithSpan
}

type tokenConverter struct {
	buffer []token.Token
}

func newTokenConverter() *tokenConverter {
	return &tokenConverter{
		buffer: make([]token.Token, 0, 256),
	}
}

func (tc *tokenConverter) convert(tokens []models.TokenWithSpan) (*ConversionResult, error) {
	tc.buffer = tc.buffer[:0]
	positions := make([]TokenPosition, 0, len(tokens)*2)

	for originalIndex, t := range tokens {
		t := t
		if expanded := tc.handleCompoundToken(t); len(expanded) > 0 {
			tc.buffer = append(tc.buffer, expanded...)
			for range expanded {
				positions = append(positions, TokenPosition{
					OriginalIndex: originalIndex,
					Start:         t.Start,
					End:           t.End,
					SourceToken:   &t,
				})
			}
			continue
		}

		convertedToken, err := tc.convertSingleToken(t)
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to convert token: %v", err),
				t.Start, "",
			)
		}

		tc.buffer = append(tc.buffer, convertedToken)
		positions = append(positions, TokenPosition{
			OriginalIndex: originalIndex,
			Start:         t.Start,
			End:           t.End,
			SourceToken:   &t,
		})
	}

	result := &ConversionResult{
		Tokens:          make([]token.Token, len(tc.buffer)),
		PositionMapping: positions,
	}
	copy(result.Tokens, tc.buffer)
	return result, nil
}

func (tc *tokenConverter) handleCompoundToken(t models.TokenWithSpan) []token.Token {
	switch t.Token.Type {
	case models.TokenTypeInnerJoin:
		return []token.Token{
			{Type: models.TokenTypeInner, Literal: "INNER"},
			{Type: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case models.TokenTypeLeftJoin:
		return []token.Token{
			{Type: models.TokenTypeLeft, Literal: "LEFT"},
			{Type: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case models.TokenTypeRightJoin:
		return []token.Token{
			{Type: models.TokenTypeRight, Literal: "RIGHT"},
			{Type: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case models.TokenTypeOuterJoin:
		return []token.Token{
			{Type: models.TokenTypeOuter, Literal: "OUTER"},
			{Type: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case models.TokenTypeFullJoin:
		return []token.Token{
			{Type: models.TokenTypeFull, Literal: "FULL"},
			{Type: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case models.TokenTypeCrossJoin:
		return []token.Token{
			{Type: models.TokenTypeCross, Literal: "CROSS"},
			{Type: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case models.TokenTypeOrderBy:
		return []token.Token{
			{Type: models.TokenTypeOrder, Literal: "ORDER"},
			{Type: models.TokenTypeBy, Literal: "BY"},
		}
	case models.TokenTypeGroupBy:
		return []token.Token{
			{Type: models.TokenTypeGroup, Literal: "GROUP"},
			{Type: models.TokenTypeBy, Literal: "BY"},
		}
	case models.TokenTypeGroupingSets:
		return []token.Token{
			{Type: models.TokenTypeGrouping, Literal: "GROUPING"},
			{Type: models.TokenTypeSets, Literal: "SETS"},
		}
	}

	switch t.Token.Value {
	case "INNER JOIN":
		return []token.Token{
			{Type: models.TokenTypeInner, Literal: "INNER"},
			{Type: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case "LEFT JOIN":
		return []token.Token{
			{Type: models.TokenTypeLeft, Literal: "LEFT"},
			{Type: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case "RIGHT JOIN":
		return []token.Token{
			{Type: models.TokenTypeRight, Literal: "RIGHT"},
			{Type: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case "FULL JOIN":
		return []token.Token{
			{Type: models.TokenTypeFull, Literal: "FULL"},
			{Type: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case "CROSS JOIN":
		return []token.Token{
			{Type: models.TokenTypeCross, Literal: "CROSS"},
			{Type: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case "LEFT OUTER JOIN":
		return []token.Token{
			{Type: models.TokenTypeLeft, Literal: "LEFT"},
			{Type: models.TokenTypeOuter, Literal: "OUTER"},
			{Type: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case "RIGHT OUTER JOIN":
		return []token.Token{
			{Type: models.TokenTypeRight, Literal: "RIGHT"},
			{Type: models.TokenTypeOuter, Literal: "OUTER"},
			{Type: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case "FULL OUTER JOIN":
		return []token.Token{
			{Type: models.TokenTypeFull, Literal: "FULL"},
			{Type: models.TokenTypeOuter, Literal: "OUTER"},
			{Type: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case "ORDER BY":
		return []token.Token{
			{Type: models.TokenTypeOrder, Literal: "ORDER"},
			{Type: models.TokenTypeBy, Literal: "BY"},
		}
	case "GROUP BY":
		return []token.Token{
			{Type: models.TokenTypeGroup, Literal: "GROUP"},
			{Type: models.TokenTypeBy, Literal: "BY"},
		}
	}

	return nil
}

func (tc *tokenConverter) convertSingleToken(t models.TokenWithSpan) (token.Token, error) {
	if t.Token.Type == models.TokenTypeMul {
		return token.Token{
			Type: models.TokenTypeAsterisk, Literal: t.Token.Value,
		}, nil
	}

	switch t.Token.Type {
	case models.TokenTypeCount, models.TokenTypeSum, models.TokenTypeAvg,
		models.TokenTypeMin, models.TokenTypeMax:
		return token.Token{
			Type: models.TokenTypeIdentifier, Literal: t.Token.Value,
		}, nil
	}

	if t.Token.Type == models.TokenTypeQuestion {
		return token.Token{Type: models.TokenTypeQuestion, Literal: t.Token.Value}, nil
	}
	if t.Token.Type == models.TokenTypeQuestionPipe {
		return token.Token{Type: models.TokenTypeQuestionPipe, Literal: t.Token.Value}, nil
	}
	if t.Token.Type == models.TokenTypeQuestionAnd {
		return token.Token{Type: models.TokenTypeQuestionAnd, Literal: t.Token.Value}, nil
	}

	if t.Token.Type == models.TokenTypeNumber {
		return token.Token{Type: models.TokenTypeNumber, Literal: t.Token.Value}, nil
	}

	if t.Token.Type == models.TokenTypeIdentifier {
		// Only remap identifiers to well-known SQL keywords that the parser
		// needs as specific types. Data type keywords (VARCHAR, INTEGER, etc.)
		// are intentionally left as identifiers since the parser handles them
		// via isDataTypeKeyword() with literal fallback.
		if modelType := getIdentifierKeywordType(t.Token.Value); modelType != models.TokenTypeUnknown {
			return token.Token{Type: modelType, Literal: t.Token.Value}, nil
		}
		return token.Token{Type: models.TokenTypeIdentifier, Literal: t.Token.Value}, nil
	}

	if t.Token.Type == models.TokenTypeKeyword {
		if modelType := getKeywordModelType(t.Token.Value); modelType != models.TokenTypeUnknown {
			return token.Token{Type: modelType, Literal: t.Token.Value}, nil
		}
		return token.Token{
			Type:    models.TokenTypeKeyword,
			Literal: t.Token.Value,
		}, nil
	}

	// Direct pass-through: the models.TokenType is already the correct type
	return token.Token{Type: t.Token.Type, Literal: t.Token.Value}, nil
}


// getIdentifierKeywordType remaps identifiers that are actually SQL keywords.
// This is conservative — only includes keywords that the parser expects as specific types,
// NOT data type keywords (VARCHAR, etc.) which should stay as identifiers.
func getIdentifierKeywordType(value string) models.TokenType {
	var upper []byte
	n := len(value)
	if n <= 32 {
		bufPtr := keywordBufferPool.Get().(*[]byte)
		upper = (*bufPtr)[:n]
		defer keywordBufferPool.Put(bufPtr)
	} else {
		upper = make([]byte, n)
	}
	for i := 0; i < n; i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' {
			upper[i] = c - 32
		} else {
			upper[i] = c
		}
	}
	switch string(upper) {
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
	case "AUTO_INCREMENT":
		return models.TokenTypeAutoIncrement
	case "AUTOINCREMENT":
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

// getKeywordModelType maps keyword string values to models.TokenType.
// This is comprehensive — used for tokens already typed as TokenTypeKeyword.
func getKeywordModelType(value string) models.TokenType {
	var upper []byte
	n := len(value)
	if n <= 32 {
		bufPtr := keywordBufferPool.Get().(*[]byte)
		upper = (*bufPtr)[:n]
		defer keywordBufferPool.Put(bufPtr)
	} else {
		upper = make([]byte, n)
	}
	for i := 0; i < n; i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' {
			upper[i] = c - 32
		} else {
			upper[i] = c
		}
	}
	switch string(upper) {
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
	case "AUTO_INCREMENT":
		return models.TokenTypeAutoIncrement
	case "AUTOINCREMENT":
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

// convertModelTokens converts tokenizer output to parser tokens.
func convertModelTokens(tokens []models.TokenWithSpan) ([]token.Token, error) {
	tc := newTokenConverter()
	result, err := tc.convert(tokens)
	if err != nil {
		return nil, err
	}
	return result.Tokens, nil
}

// convertModelTokensWithPositions converts tokenizer output with position tracking.
func convertModelTokensWithPositions(tokens []models.TokenWithSpan) (*ConversionResult, error) {
	tc := newTokenConverter()
	return tc.convert(tokens)
}
