package parser

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// TokenConverter provides centralized, optimized token conversion
// from tokenizer output (models.TokenWithSpan) to parser input (token.Token)
type TokenConverter struct {
	// Pre-allocated buffer to reduce memory allocations
	buffer []token.Token

	// Type mapping cache for performance
	typeMap map[models.TokenType]token.Type
}

// ConversionResult contains the converted tokens and any position mappings
type ConversionResult struct {
	Tokens          []token.Token
	PositionMapping []TokenPosition // Maps parser token index to original position
}

// TokenPosition maps a parser token back to its original source position
type TokenPosition struct {
	OriginalIndex int                   // Index in original token slice
	Start         models.Location       // Original start position
	End           models.Location       // Original end position
	SourceToken   *models.TokenWithSpan // Reference to original token for error reporting
}

// NewTokenConverter creates an optimized token converter
func NewTokenConverter() *TokenConverter {
	return &TokenConverter{
		buffer:  make([]token.Token, 0, 256), // Pre-allocate reasonable buffer
		typeMap: buildTypeMapping(),
	}
}

// Convert converts tokenizer tokens to parser tokens with position tracking
func (tc *TokenConverter) Convert(tokens []models.TokenWithSpan) (*ConversionResult, error) {
	// Reset buffer but keep capacity
	tc.buffer = tc.buffer[:0]
	positions := make([]TokenPosition, 0, len(tokens)*2) // Account for compound token expansion

	for originalIndex, t := range tokens {
		t := t // G601: Create local copy to avoid memory aliasing
		// Handle compound tokens that need to be split
		if expanded := tc.handleCompoundToken(t); len(expanded) > 0 {
			tc.buffer = append(tc.buffer, expanded...)

			// Map all expanded tokens back to original position
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

		// Handle single tokens
		convertedToken, err := tc.convertSingleToken(t)
		if err != nil {
			return nil, fmt.Errorf("failed to convert token at line %d, column %d: %w",
				t.Start.Line, t.Start.Column, err)
		}

		tc.buffer = append(tc.buffer, convertedToken)
		positions = append(positions, TokenPosition{
			OriginalIndex: originalIndex,
			Start:         t.Start,
			End:           t.End,
			SourceToken:   &t,
		})
	}

	// Create result with copied slices to prevent buffer reuse issues
	result := &ConversionResult{
		Tokens:          make([]token.Token, len(tc.buffer)),
		PositionMapping: positions,
	}
	copy(result.Tokens, tc.buffer)

	return result, nil
}

// handleCompoundToken processes compound tokens that need to be split into multiple tokens
// It populates both the string-based Type and int-based ModelType for unified type system
func (tc *TokenConverter) handleCompoundToken(t models.TokenWithSpan) []token.Token {
	// Handle typed compound tokens first (most specific)
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

	// Handle compound tokens that come as string values (fallback)
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

	// Not a compound token
	return nil
}

// convertSingleToken converts a single token using the type mapping
// It populates both the string-based Type and int-based ModelType for unified type system
func (tc *TokenConverter) convertSingleToken(t models.TokenWithSpan) (token.Token, error) {
	// Handle NUMBER tokens - convert to INT or FLOAT based on value
	if t.Token.Type == models.TokenTypeNumber {
		// Check if it's a float (contains decimal point or exponent)
		if containsDecimalOrExponent(t.Token.Value) {
			return token.Token{
				Type:      "FLOAT",
				ModelType: models.TokenTypeNumber, // Preserve original ModelType
				Literal:   t.Token.Value,
			}, nil
		}
		return token.Token{
			Type:      "INT",
			ModelType: models.TokenTypeNumber, // Preserve original ModelType
			Literal:   t.Token.Value,
		}, nil
	}

	// Handle IDENTIFIER tokens that might be keywords
	if t.Token.Type == models.TokenTypeIdentifier {
		// Check if this identifier is actually a SQL keyword that the parser expects
		if keywordType, modelType := getKeywordTokenTypeWithModel(t.Token.Value); keywordType != "" {
			return token.Token{
				Type:      keywordType,
				ModelType: modelType,
				Literal:   t.Token.Value,
			}, nil
		}
		// Regular identifier
		return token.Token{
			Type:      "IDENT",
			ModelType: models.TokenTypeIdentifier,
			Literal:   t.Token.Value,
		}, nil
	}

	// Handle generic KEYWORD tokens - convert based on value
	if t.Token.Type == models.TokenTypeKeyword {
		// Check if this keyword has a specific token type
		if keywordType, modelType := getKeywordTokenTypeWithModel(t.Token.Value); keywordType != "" {
			return token.Token{
				Type:      keywordType,
				ModelType: modelType,
				Literal:   t.Token.Value,
			}, nil
		}
		// Use the keyword value as the type
		return token.Token{
			Type:      token.Type(t.Token.Value),
			ModelType: models.TokenTypeKeyword,
			Literal:   t.Token.Value,
		}, nil
	}

	// Try mapped type first (most efficient)
	if mappedType, exists := tc.typeMap[t.Token.Type]; exists {
		return token.Token{
			Type:      mappedType,
			ModelType: t.Token.Type, // Preserve the original ModelType
			Literal:   t.Token.Value,
		}, nil
	}

	// Fallback to string conversion for unmapped types
	tokenType := token.Type(fmt.Sprintf("%v", t.Token.Type))

	return token.Token{
		Type:      tokenType,
		ModelType: t.Token.Type, // Preserve the original ModelType
		Literal:   t.Token.Value,
	}, nil
}

// containsDecimalOrExponent checks if a number string is a float
func containsDecimalOrExponent(s string) bool {
	for _, ch := range s {
		if ch == '.' || ch == 'e' || ch == 'E' {
			return true
		}
	}
	return false
}

// getKeywordTokenTypeWithModel returns both the parser token type (string) and models.TokenType (int)
// for SQL keywords that come as IDENTIFIER. This enables unified type system support.
func getKeywordTokenTypeWithModel(value string) (token.Type, models.TokenType) {
	// Convert to uppercase for case-insensitive matching
	upper := ""
	for _, r := range value {
		if r >= 'a' && r <= 'z' {
			upper += string(r - 32) // Convert to uppercase
		} else {
			upper += string(r)
		}
	}

	switch upper {
	// DML statements
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

	// DDL statements
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

	// CTE and advanced features
	case "WITH":
		return "WITH", models.TokenTypeWith
	case "RECURSIVE":
		return "RECURSIVE", models.TokenTypeRecursive

	// Set operations
	case "UNION":
		return "UNION", models.TokenTypeUnion
	case "EXCEPT":
		return "EXCEPT", models.TokenTypeExcept
	case "INTERSECT":
		return "INTERSECT", models.TokenTypeIntersect
	case "ALL":
		return "ALL", models.TokenTypeAll

	// Data types and constraints
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

	// Column attributes
	case "AUTO_INCREMENT":
		return "AUTO_INCREMENT", models.TokenTypeAutoIncrement
	case "AUTOINCREMENT":
		return "AUTOINCREMENT", models.TokenTypeAutoIncrement

	// Window function keywords
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

	// Join types (some might come as IDENTIFIER)
	case "CROSS":
		return "CROSS", models.TokenTypeCross
	case "NATURAL":
		return "NATURAL", models.TokenTypeNatural
	case "USING":
		return "USING", models.TokenTypeUsing

	// Other common keywords
	case "DISTINCT":
		return "DISTINCT", models.TokenTypeDistinct
	case "EXISTS":
		return "EXISTS", models.TokenTypeExists
	case "ANY":
		return "ANY", models.TokenTypeAny
	case "SOME":
		return "SOME", models.TokenTypeSome

	// Grouping set keywords
	case "ROLLUP":
		return "ROLLUP", models.TokenTypeRollup
	case "CUBE":
		return "CUBE", models.TokenTypeCube
	case "GROUPING":
		return "GROUPING", models.TokenTypeGrouping

	default:
		// Not a recognized keyword, will be treated as identifier
		return "", models.TokenTypeUnknown
	}
}

// buildTypeMapping creates an optimized lookup table for token type conversion
// Includes all token types defined in models.TokenType for comprehensive coverage
func buildTypeMapping() map[models.TokenType]token.Type {
	return map[models.TokenType]token.Type{
		// SQL Keywords (core)
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
		models.TokenTypeIs:      "IS",
		models.TokenTypeNot:     "NOT",
		models.TokenTypeNull:    "NULL",
		models.TokenTypeAnd:     "AND",
		models.TokenTypeOr:      "OR",
		models.TokenTypeTrue:    "TRUE",
		models.TokenTypeFalse:   "FALSE",

		// DML Keywords
		models.TokenTypeInsert: "INSERT",
		models.TokenTypeUpdate: "UPDATE",
		models.TokenTypeDelete: "DELETE",
		models.TokenTypeInto:   "INTO",
		models.TokenTypeValues: "VALUES",
		models.TokenTypeSet:    "SET",

		// DDL Keywords
		models.TokenTypeCreate:   "CREATE",
		models.TokenTypeAlter:    "ALTER",
		models.TokenTypeDrop:     "DROP",
		models.TokenTypeTable:    "TABLE",
		models.TokenTypeIndex:    "INDEX",
		models.TokenTypeView:     "VIEW",
		models.TokenTypeColumn:   "COLUMN",
		models.TokenTypeDatabase: "DATABASE",
		models.TokenTypeSchema:   "SCHEMA",
		models.TokenTypeTrigger:  "TRIGGER",

		// CTE and Set Operations
		models.TokenTypeWith:      "WITH",
		models.TokenTypeRecursive: "RECURSIVE",
		models.TokenTypeUnion:     "UNION",
		models.TokenTypeExcept:    "EXCEPT",
		models.TokenTypeIntersect: "INTERSECT",
		models.TokenTypeAll:       "ALL",

		// Window Function Keywords
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

		// Additional Join Keywords
		models.TokenTypeCross:   "CROSS",
		models.TokenTypeNatural: "NATURAL",
		models.TokenTypeFull:    "FULL",
		models.TokenTypeUsing:   "USING",

		// Constraint Keywords
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

		// Additional SQL Keywords
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

		// MERGE Statement Keywords
		models.TokenTypeMerge:   "MERGE",
		models.TokenTypeMatched: "MATCHED",
		models.TokenTypeTarget:  "TARGET",
		models.TokenTypeSource:  "SOURCE",

		// Materialized View Keywords
		models.TokenTypeMaterialized: "MATERIALIZED",
		models.TokenTypeRefresh:      "REFRESH",

		// Grouping Set Keywords
		models.TokenTypeGroupingSets: "GROUPING SETS",
		models.TokenTypeRollup:       "ROLLUP",
		models.TokenTypeCube:         "CUBE",
		models.TokenTypeGrouping:     "GROUPING",

		// Role/Permission Keywords
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

		// Transaction Keywords
		models.TokenTypeBegin:     "BEGIN",
		models.TokenTypeCommit:    "COMMIT",
		models.TokenTypeRollback:  "ROLLBACK",
		models.TokenTypeSavepoint: "SAVEPOINT",

		// Data Type Keywords
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

		// Aggregate functions - map to IDENT so they can be used as function names
		models.TokenTypeCount: "IDENT",
		models.TokenTypeSum:   "IDENT",
		models.TokenTypeAvg:   "IDENT",
		models.TokenTypeMin:   "IDENT",
		models.TokenTypeMax:   "IDENT",

		// Compound keywords
		models.TokenTypeGroupBy:   "GROUP BY",
		models.TokenTypeOrderBy:   "ORDER BY",
		models.TokenTypeLeftJoin:  "LEFT JOIN",
		models.TokenTypeRightJoin: "RIGHT JOIN",
		models.TokenTypeInnerJoin: "INNER JOIN",
		models.TokenTypeOuterJoin: "OUTER JOIN",
		models.TokenTypeFullJoin:  "FULL JOIN",
		models.TokenTypeCrossJoin: "CROSS JOIN",

		// Identifiers and Literals
		models.TokenTypeIdentifier: "IDENT",
		models.TokenTypeString:     "STRING",
		models.TokenTypeNumber:     "NUMBER",
		models.TokenTypeWord:       "WORD",
		models.TokenTypeChar:       "CHAR",

		// Operators and Punctuation
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

		// Special tokens
		models.TokenTypeEOF:        "EOF",
		models.TokenTypeUnknown:    "UNKNOWN",
		models.TokenTypeWhitespace: "WHITESPACE",
		models.TokenTypeKeyword:    "KEYWORD",
		models.TokenTypeOperator:   "OPERATOR",
		models.TokenTypeIllegal:    "ILLEGAL",
		models.TokenTypeAsterisk:   "*",
		models.TokenTypeDoublePipe: "||",
	}
}

// ConvertTokensForParser is a convenient function that creates a converter and converts tokens
// This maintains backward compatibility with existing CLI code
func ConvertTokensForParser(tokens []models.TokenWithSpan) ([]token.Token, error) {
	converter := NewTokenConverter()
	result, err := converter.Convert(tokens)
	if err != nil {
		return nil, err
	}
	return result.Tokens, nil
}

// ConvertTokensWithPositions provides both tokens and position mapping for enhanced error reporting
func ConvertTokensWithPositions(tokens []models.TokenWithSpan) (*ConversionResult, error) {
	converter := NewTokenConverter()
	return converter.Convert(tokens)
}
