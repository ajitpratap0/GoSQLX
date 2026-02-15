package parser

// token_conversion.go contains internal token conversion logic from models.TokenWithSpan
// to token.Token. This is an unexported implementation detail used by ParseFromModelTokens.

import (
	"fmt"
	"sync"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
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
	buffer  []token.Token
	typeMap map[models.TokenType]token.Type //nolint:all // token.Type kept for backward compat during #215 migration
}

func newTokenConverter() *tokenConverter {
	return &tokenConverter{
		buffer:  make([]token.Token, 0, 256),
		typeMap: buildTypeMapping(),
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
			{Type: "INNER", ModelType: models.TokenTypeInner, Literal: "INNER"},
			{Type: "JOIN", ModelType: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case models.TokenTypeLeftJoin:
		return []token.Token{
			{Type: "LEFT", ModelType: models.TokenTypeLeft, Literal: "LEFT"},
			{Type: "JOIN", ModelType: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case models.TokenTypeRightJoin:
		return []token.Token{
			{Type: "RIGHT", ModelType: models.TokenTypeRight, Literal: "RIGHT"},
			{Type: "JOIN", ModelType: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case models.TokenTypeOuterJoin:
		return []token.Token{
			{Type: "OUTER", ModelType: models.TokenTypeOuter, Literal: "OUTER"},
			{Type: "JOIN", ModelType: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case models.TokenTypeFullJoin:
		return []token.Token{
			{Type: "FULL", ModelType: models.TokenTypeFull, Literal: "FULL"},
			{Type: "JOIN", ModelType: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case models.TokenTypeCrossJoin:
		return []token.Token{
			{Type: "CROSS", ModelType: models.TokenTypeCross, Literal: "CROSS"},
			{Type: "JOIN", ModelType: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case models.TokenTypeOrderBy:
		return []token.Token{
			{Type: "ORDER", ModelType: models.TokenTypeOrder, Literal: "ORDER"},
			{Type: "BY", ModelType: models.TokenTypeBy, Literal: "BY"},
		}
	case models.TokenTypeGroupBy:
		return []token.Token{
			{Type: "GROUP", ModelType: models.TokenTypeGroup, Literal: "GROUP"},
			{Type: "BY", ModelType: models.TokenTypeBy, Literal: "BY"},
		}
	case models.TokenTypeGroupingSets:
		return []token.Token{
			{Type: "GROUPING", ModelType: models.TokenTypeGrouping, Literal: "GROUPING"},
			{Type: "SETS", ModelType: models.TokenTypeSets, Literal: "SETS"},
		}
	}

	switch t.Token.Value {
	case "INNER JOIN":
		return []token.Token{
			{Type: "INNER", ModelType: models.TokenTypeInner, Literal: "INNER"},
			{Type: "JOIN", ModelType: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case "LEFT JOIN":
		return []token.Token{
			{Type: "LEFT", ModelType: models.TokenTypeLeft, Literal: "LEFT"},
			{Type: "JOIN", ModelType: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case "RIGHT JOIN":
		return []token.Token{
			{Type: "RIGHT", ModelType: models.TokenTypeRight, Literal: "RIGHT"},
			{Type: "JOIN", ModelType: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case "FULL JOIN":
		return []token.Token{
			{Type: "FULL", ModelType: models.TokenTypeFull, Literal: "FULL"},
			{Type: "JOIN", ModelType: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case "CROSS JOIN":
		return []token.Token{
			{Type: "CROSS", ModelType: models.TokenTypeCross, Literal: "CROSS"},
			{Type: "JOIN", ModelType: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case "LEFT OUTER JOIN":
		return []token.Token{
			{Type: "LEFT", ModelType: models.TokenTypeLeft, Literal: "LEFT"},
			{Type: "OUTER", ModelType: models.TokenTypeOuter, Literal: "OUTER"},
			{Type: "JOIN", ModelType: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case "RIGHT OUTER JOIN":
		return []token.Token{
			{Type: "RIGHT", ModelType: models.TokenTypeRight, Literal: "RIGHT"},
			{Type: "OUTER", ModelType: models.TokenTypeOuter, Literal: "OUTER"},
			{Type: "JOIN", ModelType: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case "FULL OUTER JOIN":
		return []token.Token{
			{Type: "FULL", ModelType: models.TokenTypeFull, Literal: "FULL"},
			{Type: "OUTER", ModelType: models.TokenTypeOuter, Literal: "OUTER"},
			{Type: "JOIN", ModelType: models.TokenTypeJoin, Literal: "JOIN"},
		}
	case "ORDER BY":
		return []token.Token{
			{Type: "ORDER", ModelType: models.TokenTypeOrder, Literal: "ORDER"},
			{Type: "BY", ModelType: models.TokenTypeBy, Literal: "BY"},
		}
	case "GROUP BY":
		return []token.Token{
			{Type: "GROUP", ModelType: models.TokenTypeGroup, Literal: "GROUP"},
			{Type: "BY", ModelType: models.TokenTypeBy, Literal: "BY"},
		}
	}

	return nil
}

func (tc *tokenConverter) convertSingleToken(t models.TokenWithSpan) (token.Token, error) {
	if t.Token.Type == models.TokenTypeMul {
		return token.Token{
			Type: "*", ModelType: models.TokenTypeAsterisk, Literal: t.Token.Value,
		}, nil
	}

	switch t.Token.Type {
	case models.TokenTypeCount, models.TokenTypeSum, models.TokenTypeAvg,
		models.TokenTypeMin, models.TokenTypeMax:
		return token.Token{
			Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: t.Token.Value,
		}, nil
	}

	if t.Token.Type == models.TokenTypeQuestion {
		return token.Token{Type: "QUESTION", ModelType: models.TokenTypeQuestion, Literal: t.Token.Value}, nil
	}
	if t.Token.Type == models.TokenTypeQuestionPipe {
		return token.Token{Type: "QUESTION_PIPE", ModelType: models.TokenTypeQuestionPipe, Literal: t.Token.Value}, nil
	}
	if t.Token.Type == models.TokenTypeQuestionAnd {
		return token.Token{Type: "QUESTION_AND", ModelType: models.TokenTypeQuestionAnd, Literal: t.Token.Value}, nil
	}

	if t.Token.Type == models.TokenTypeNumber {
		if containsDecimalOrExponent(t.Token.Value) {
			return token.Token{Type: "FLOAT", ModelType: models.TokenTypeNumber, Literal: t.Token.Value}, nil
		}
		return token.Token{Type: "INT", ModelType: models.TokenTypeNumber, Literal: t.Token.Value}, nil
	}

	if t.Token.Type == models.TokenTypeIdentifier {
		if keywordType, modelType := getKeywordTokenTypeWithModel(t.Token.Value); keywordType != "" {
			return token.Token{Type: keywordType, ModelType: modelType, Literal: t.Token.Value}, nil
		}
		return token.Token{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: t.Token.Value}, nil
	}

	if t.Token.Type == models.TokenTypeKeyword {
		if keywordType, modelType := getKeywordTokenTypeWithModel(t.Token.Value); keywordType != "" {
			return token.Token{Type: keywordType, ModelType: modelType, Literal: t.Token.Value}, nil
		}
		return token.Token{
			Type:      token.Type(t.Token.Value), //nolint:all // token.Type kept for backward compat during #215 migration
			ModelType: models.TokenTypeKeyword,
			Literal:   t.Token.Value,
		}, nil
	}

	if mappedType, exists := tc.typeMap[t.Token.Type]; exists {
		return token.Token{Type: mappedType, ModelType: t.Token.Type, Literal: t.Token.Value}, nil
	}

	tokenType := token.Type(fmt.Sprintf("%v", t.Token.Type)) //nolint:all // token.Type kept for backward compat during #215 migration
	return token.Token{Type: tokenType, ModelType: t.Token.Type, Literal: t.Token.Value}, nil
}

func containsDecimalOrExponent(s string) bool {
	for _, ch := range s {
		if ch == '.' || ch == 'e' || ch == 'E' {
			return true
		}
	}
	return false
}

func getKeywordTokenTypeWithModel(value string) (token.Type, models.TokenType) { //nolint:all // token.Type kept for backward compat during #215 migration
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
		return "INSERT", models.TokenTypeInsert
	case "UPDATE":
		return "UPDATE", models.TokenTypeUpdate
	case "DELETE":
		return "DELETE", models.TokenTypeDelete
	case "INTO":
		return "INTO", models.TokenTypeInto
	case "VALUES":
		return "VALUES", models.TokenTypeValues
	case "SET":
		return "SET", models.TokenTypeSet
	case "CREATE":
		return "CREATE", models.TokenTypeCreate
	case "ALTER":
		return "ALTER", models.TokenTypeAlter
	case "DROP":
		return "DROP", models.TokenTypeDrop
	case "TABLE":
		return "TABLE", models.TokenTypeTable
	case "INDEX":
		return "INDEX", models.TokenTypeIndex
	case "VIEW":
		return "VIEW", models.TokenTypeView
	case "WITH":
		return "WITH", models.TokenTypeWith
	case "RECURSIVE":
		return "RECURSIVE", models.TokenTypeRecursive
	case "UNION":
		return "UNION", models.TokenTypeUnion
	case "EXCEPT":
		return "EXCEPT", models.TokenTypeExcept
	case "INTERSECT":
		return "INTERSECT", models.TokenTypeIntersect
	case "ALL":
		return "ALL", models.TokenTypeAll
	case "PRIMARY":
		return "PRIMARY", models.TokenTypePrimary
	case "KEY":
		return "KEY", models.TokenTypeKey
	case "FOREIGN":
		return "FOREIGN", models.TokenTypeForeign
	case "REFERENCES":
		return "REFERENCES", models.TokenTypeReferences
	case "UNIQUE":
		return "UNIQUE", models.TokenTypeUnique
	case "CHECK":
		return "CHECK", models.TokenTypeCheck
	case "DEFAULT":
		return "DEFAULT", models.TokenTypeDefault
	case "CONSTRAINT":
		return "CONSTRAINT", models.TokenTypeConstraint
	case "AUTO_INCREMENT":
		return "AUTO_INCREMENT", models.TokenTypeAutoIncrement
	case "AUTOINCREMENT":
		return "AUTOINCREMENT", models.TokenTypeAutoIncrement
	case "OVER":
		return "OVER", models.TokenTypeOver
	case "PARTITION":
		return "PARTITION", models.TokenTypePartition
	case "ROWS":
		return "ROWS", models.TokenTypeRows
	case "RANGE":
		return "RANGE", models.TokenTypeRange
	case "UNBOUNDED":
		return "UNBOUNDED", models.TokenTypeUnbounded
	case "PRECEDING":
		return "PRECEDING", models.TokenTypePreceding
	case "FOLLOWING":
		return "FOLLOWING", models.TokenTypeFollowing
	case "CURRENT":
		return "CURRENT", models.TokenTypeCurrent
	case "ROW":
		return "ROW", models.TokenTypeRow
	case "CROSS":
		return "CROSS", models.TokenTypeCross
	case "NATURAL":
		return "NATURAL", models.TokenTypeNatural
	case "USING":
		return "USING", models.TokenTypeUsing
	case "LATERAL":
		return "LATERAL", models.TokenTypeLateral
	case "DISTINCT":
		return "DISTINCT", models.TokenTypeDistinct
	case "EXISTS":
		return "EXISTS", models.TokenTypeExists
	case "ANY":
		return "ANY", models.TokenTypeAny
	case "SOME":
		return "SOME", models.TokenTypeSome
	case "ROLLUP":
		return "ROLLUP", models.TokenTypeRollup
	case "CUBE":
		return "CUBE", models.TokenTypeCube
	case "GROUPING":
		return "GROUPING", models.TokenTypeGrouping
	default:
		return "", models.TokenTypeUnknown
	}
}

func buildTypeMapping() map[models.TokenType]token.Type { //nolint:all // token.Type kept for backward compat during #215 migration
	return map[models.TokenType]token.Type{ //nolint:all // token.Type kept for backward compat during #215 migration
		models.TokenTypeSelect:  "SELECT",
		models.TokenTypeFrom:    "FROM",
		models.TokenTypeWhere:   "WHERE",
		models.TokenTypeJoin:    "JOIN",
		models.TokenTypeInner:   "INNER",
		models.TokenTypeLeft:    "LEFT",
		models.TokenTypeRight:   "RIGHT",
		models.TokenTypeOuter:   "OUTER",
		models.TokenTypeOn:      "ON",
		models.TokenTypeAs:      "AS",
		models.TokenTypeOrder:   "ORDER",
		models.TokenTypeBy:      "BY",
		models.TokenTypeDesc:    "DESC",
		models.TokenTypeAsc:     "ASC",
		models.TokenTypeGroup:   "GROUP",
		models.TokenTypeHaving:  "HAVING",
		models.TokenTypeLimit:   "LIMIT",
		models.TokenTypeOffset:  "OFFSET",
		models.TokenTypeCase:    "CASE",
		models.TokenTypeWhen:    "WHEN",
		models.TokenTypeThen:    "THEN",
		models.TokenTypeElse:    "ELSE",
		models.TokenTypeEnd:     "END",
		models.TokenTypeIn:      "IN",
		models.TokenTypeBetween: "BETWEEN",
		models.TokenTypeLike:    "LIKE",
		models.TokenTypeILike:   "ILIKE",
		models.TokenTypeIs:      "IS",
		models.TokenTypeNot:     "NOT",
		models.TokenTypeNull:    "NULL",
		models.TokenTypeAnd:     "AND",
		models.TokenTypeOr:      "OR",
		models.TokenTypeTrue:    "TRUE",
		models.TokenTypeFalse:   "FALSE",

		models.TokenTypeInsert: "INSERT",
		models.TokenTypeUpdate: "UPDATE",
		models.TokenTypeDelete: "DELETE",
		models.TokenTypeInto:   "INTO",
		models.TokenTypeValues: "VALUES",
		models.TokenTypeSet:    "SET",

		models.TokenTypeCreate:   "CREATE",
		models.TokenTypeAlter:    "ALTER",
		models.TokenTypeDrop:     "DROP",
		models.TokenTypeTruncate: "TRUNCATE",
		models.TokenTypeTable:    "TABLE",
		models.TokenTypeIndex:    "INDEX",
		models.TokenTypeView:     "VIEW",
		models.TokenTypeColumn:   "COLUMN",
		models.TokenTypeDatabase: "DATABASE",
		models.TokenTypeSchema:   "SCHEMA",
		models.TokenTypeTrigger:  "TRIGGER",

		models.TokenTypeWith:      "WITH",
		models.TokenTypeRecursive: "RECURSIVE",
		models.TokenTypeUnion:     "UNION",
		models.TokenTypeExcept:    "EXCEPT",
		models.TokenTypeIntersect: "INTERSECT",
		models.TokenTypeAll:       "ALL",

		models.TokenTypeOver:      "OVER",
		models.TokenTypePartition: "PARTITION",
		models.TokenTypeRows:      "ROWS",
		models.TokenTypeRange:     "RANGE",
		models.TokenTypeUnbounded: "UNBOUNDED",
		models.TokenTypePreceding: "PRECEDING",
		models.TokenTypeFollowing: "FOLLOWING",
		models.TokenTypeCurrent:   "CURRENT",
		models.TokenTypeRow:       "ROW",
		models.TokenTypeGroups:    "GROUPS",
		models.TokenTypeFilter:    "FILTER",
		models.TokenTypeExclude:   "EXCLUDE",
		models.TokenTypeArray:     "ARRAY",
		models.TokenTypeWithin:    "WITHIN",

		models.TokenTypeCross:   "CROSS",
		models.TokenTypeNatural: "NATURAL",
		models.TokenTypeFull:    "FULL",
		models.TokenTypeUsing:   "USING",
		models.TokenTypeLateral: "LATERAL",

		models.TokenTypePrimary:       "PRIMARY",
		models.TokenTypeKey:           "KEY",
		models.TokenTypeForeign:       "FOREIGN",
		models.TokenTypeReferences:    "REFERENCES",
		models.TokenTypeUnique:        "UNIQUE",
		models.TokenTypeCheck:         "CHECK",
		models.TokenTypeDefault:       "DEFAULT",
		models.TokenTypeAutoIncrement: "AUTO_INCREMENT",
		models.TokenTypeConstraint:    "CONSTRAINT",
		models.TokenTypeNotNull:       "NOT_NULL",
		models.TokenTypeNullable:      "NULLABLE",

		models.TokenTypeDistinct: "DISTINCT",
		models.TokenTypeExists:   "EXISTS",
		models.TokenTypeAny:      "ANY",
		models.TokenTypeSome:     "SOME",
		models.TokenTypeCast:     "CAST",
		models.TokenTypeConvert:  "CONVERT",
		models.TokenTypeCollate:  "COLLATE",
		models.TokenTypeCascade:  "CASCADE",
		models.TokenTypeRestrict: "RESTRICT",
		models.TokenTypeReplace:  "REPLACE",
		models.TokenTypeRename:   "RENAME",
		models.TokenTypeTo:       "TO",
		models.TokenTypeIf:       "IF",
		models.TokenTypeOnly:     "ONLY",
		models.TokenTypeFor:      "FOR",
		models.TokenTypeNulls:    "NULLS",
		models.TokenTypeFirst:    "FIRST",
		models.TokenTypeLast:     "LAST",

		models.TokenTypeMerge:   "MERGE",
		models.TokenTypeMatched: "MATCHED",
		models.TokenTypeTarget:  "TARGET",
		models.TokenTypeSource:  "SOURCE",

		models.TokenTypeMaterialized: "MATERIALIZED",
		models.TokenTypeRefresh:      "REFRESH",

		models.TokenTypeGroupingSets: "GROUPING SETS",
		models.TokenTypeRollup:       "ROLLUP",
		models.TokenTypeCube:         "CUBE",
		models.TokenTypeGrouping:     "GROUPING",

		models.TokenTypeRole:       "ROLE",
		models.TokenTypeUser:       "USER",
		models.TokenTypeGrant:      "GRANT",
		models.TokenTypeRevoke:     "REVOKE",
		models.TokenTypePrivilege:  "PRIVILEGE",
		models.TokenTypePassword:   "PASSWORD",
		models.TokenTypeLogin:      "LOGIN",
		models.TokenTypeSuperuser:  "SUPERUSER",
		models.TokenTypeCreateDB:   "CREATEDB",
		models.TokenTypeCreateRole: "CREATEROLE",

		models.TokenTypeBegin:     "BEGIN",
		models.TokenTypeCommit:    "COMMIT",
		models.TokenTypeRollback:  "ROLLBACK",
		models.TokenTypeSavepoint: "SAVEPOINT",

		models.TokenTypeInt:          "INT",
		models.TokenTypeInteger:      "INTEGER",
		models.TokenTypeBigInt:       "BIGINT",
		models.TokenTypeSmallInt:     "SMALLINT",
		models.TokenTypeFloat:        "FLOAT",
		models.TokenTypeDouble:       "DOUBLE",
		models.TokenTypeDecimal:      "DECIMAL",
		models.TokenTypeNumeric:      "NUMERIC",
		models.TokenTypeVarchar:      "VARCHAR",
		models.TokenTypeCharDataType: "CHAR",
		models.TokenTypeText:         "TEXT",
		models.TokenTypeBoolean:      "BOOLEAN",
		models.TokenTypeDate:         "DATE",
		models.TokenTypeTime:         "TIME",
		models.TokenTypeTimestamp:    "TIMESTAMP",
		models.TokenTypeInterval:     "INTERVAL",
		models.TokenTypeBlob:         "BLOB",
		models.TokenTypeClob:         "CLOB",
		models.TokenTypeJson:         "JSON",
		models.TokenTypeUuid:         "UUID",

		models.TokenTypeCount: "IDENT",
		models.TokenTypeSum:   "IDENT",
		models.TokenTypeAvg:   "IDENT",
		models.TokenTypeMin:   "IDENT",
		models.TokenTypeMax:   "IDENT",

		models.TokenTypeShare:  "SHARE",
		models.TokenTypeNoWait: "NOWAIT",
		models.TokenTypeSkip:   "SKIP",
		models.TokenTypeLocked: "LOCKED",
		models.TokenTypeOf:     "OF",

		models.TokenTypeGroupBy:   "GROUP BY",
		models.TokenTypeOrderBy:   "ORDER BY",
		models.TokenTypeLeftJoin:  "LEFT JOIN",
		models.TokenTypeRightJoin: "RIGHT JOIN",
		models.TokenTypeInnerJoin: "INNER JOIN",
		models.TokenTypeOuterJoin: "OUTER JOIN",
		models.TokenTypeFullJoin:  "FULL JOIN",
		models.TokenTypeCrossJoin: "CROSS JOIN",

		models.TokenTypeIdentifier:         "IDENT",
		models.TokenTypeString:             "STRING",
		models.TokenTypeDollarQuotedString: "STRING",
		models.TokenTypeNumber:             "NUMBER",
		models.TokenTypeWord:               "WORD",
		models.TokenTypeChar:               "CHAR",

		models.TokenTypeEq:          "=",
		models.TokenTypeDoubleEq:    "==",
		models.TokenTypeNeq:         "!=",
		models.TokenTypeLt:          "<",
		models.TokenTypeGt:          ">",
		models.TokenTypeLtEq:        "<=",
		models.TokenTypeGtEq:        ">=",
		models.TokenTypePlus:        "+",
		models.TokenTypeMinus:       "-",
		models.TokenTypeMul:         "*",
		models.TokenTypeDiv:         "/",
		models.TokenTypeMod:         "%",
		models.TokenTypePeriod:      ".",
		models.TokenTypeComma:       ",",
		models.TokenTypeSemicolon:   ";",
		models.TokenTypeLParen:      "(",
		models.TokenTypeRParen:      ")",
		models.TokenTypeLBracket:    "[",
		models.TokenTypeRBracket:    "]",
		models.TokenTypeLBrace:      "{",
		models.TokenTypeRBrace:      "}",
		models.TokenTypeColon:       ":",
		models.TokenTypeDoubleColon: "::",
		models.TokenTypeAssignment:  ":=",

		models.TokenTypeEOF:        "EOF",
		models.TokenTypeUnknown:    "UNKNOWN",
		models.TokenTypeWhitespace: "WHITESPACE",
		models.TokenTypeKeyword:    "KEYWORD",
		models.TokenTypeOperator:   "OPERATOR",
		models.TokenTypeIllegal:    "ILLEGAL",
		models.TokenTypeAsterisk:   "*",
		models.TokenTypeDoublePipe: "||",

		models.TokenTypeQuestion:     "QUESTION",
		models.TokenTypeQuestionPipe: "QUESTION_PIPE",
		models.TokenTypeQuestionAnd:  "QUESTION_AND",

		models.TokenTypeTilde:                        "~",
		models.TokenTypeTildeAsterisk:                "~*",
		models.TokenTypeExclamationMarkTilde:         "!~",
		models.TokenTypeExclamationMarkTildeAsterisk: "!~*",
	}
}

// convertModelTokens converts tokenizer output to parser tokens.
// This is the internal implementation used by ParseFromModelTokens.
func convertModelTokens(tokens []models.TokenWithSpan) ([]token.Token, error) {
	tc := newTokenConverter()
	result, err := tc.convert(tokens)
	if err != nil {
		return nil, err
	}
	return result.Tokens, nil
}

// convertModelTokensWithPositions converts tokenizer output with position tracking.
// Used by ParseFromModelTokensWithPositions for enhanced error reporting.
func convertModelTokensWithPositions(tokens []models.TokenWithSpan) (*ConversionResult, error) {
	tc := newTokenConverter()
	return tc.convert(tokens)
}
