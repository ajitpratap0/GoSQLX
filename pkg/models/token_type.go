package models

// TokenType represents the type of a SQL token
type TokenType int

// Token range constants for maintainability and clarity.
// These define the boundaries for each category of tokens.
const (
	// TokenRangeBasicStart marks the beginning of basic token types
	TokenRangeBasicStart TokenType = 10
	// TokenRangeBasicEnd marks the end of basic token types (exclusive)
	TokenRangeBasicEnd TokenType = 30

	// TokenRangeStringStart marks the beginning of string literal types
	TokenRangeStringStart TokenType = 30
	// TokenRangeStringEnd marks the end of string literal types (exclusive)
	TokenRangeStringEnd TokenType = 50

	// TokenRangeOperatorStart marks the beginning of operator types
	TokenRangeOperatorStart TokenType = 50
	// TokenRangeOperatorEnd marks the end of operator types (exclusive)
	TokenRangeOperatorEnd TokenType = 150

	// TokenRangeKeywordStart marks the beginning of SQL keyword types
	TokenRangeKeywordStart TokenType = 200
	// TokenRangeKeywordEnd marks the end of SQL keyword types (exclusive)
	TokenRangeKeywordEnd TokenType = 500

	// TokenRangeDataTypeStart marks the beginning of data type keywords
	TokenRangeDataTypeStart TokenType = 430
	// TokenRangeDataTypeEnd marks the end of data type keywords (exclusive)
	TokenRangeDataTypeEnd TokenType = 450
)

// Token type constants with explicit values to avoid collisions
const (
	// Special tokens
	TokenTypeEOF     TokenType = 0
	TokenTypeUnknown TokenType = 1

	// Basic token types (10-29)
	TokenTypeWord        TokenType = 10
	TokenTypeNumber      TokenType = 11
	TokenTypeChar        TokenType = 12
	TokenTypeWhitespace  TokenType = 13
	TokenTypeIdentifier  TokenType = 14
	TokenTypePlaceholder TokenType = 15

	// String literals (30-49)
	TokenTypeString                   TokenType = 30 // Generic string type
	TokenTypeSingleQuotedString       TokenType = 31
	TokenTypeDoubleQuotedString       TokenType = 32
	TokenTypeTripleSingleQuotedString TokenType = 33
	TokenTypeTripleDoubleQuotedString TokenType = 34
	TokenTypeDollarQuotedString       TokenType = 35
	TokenTypeByteStringLiteral        TokenType = 36
	TokenTypeNationalStringLiteral    TokenType = 37
	TokenTypeEscapedStringLiteral     TokenType = 38
	TokenTypeUnicodeStringLiteral     TokenType = 39
	TokenTypeHexStringLiteral         TokenType = 40

	// Operators and punctuation (50-99)
	TokenTypeOperator        TokenType = 50 // Generic operator
	TokenTypeComma           TokenType = 51
	TokenTypeEq              TokenType = 52
	TokenTypeDoubleEq        TokenType = 53
	TokenTypeNeq             TokenType = 54
	TokenTypeLt              TokenType = 55
	TokenTypeGt              TokenType = 56
	TokenTypeLtEq            TokenType = 57
	TokenTypeGtEq            TokenType = 58
	TokenTypeSpaceship       TokenType = 59
	TokenTypePlus            TokenType = 60
	TokenTypeMinus           TokenType = 61
	TokenTypeMul             TokenType = 62
	TokenTypeDiv             TokenType = 63
	TokenTypeDuckIntDiv      TokenType = 64
	TokenTypeMod             TokenType = 65
	TokenTypeStringConcat    TokenType = 66
	TokenTypeLParen          TokenType = 67
	TokenTypeLeftParen       TokenType = 67 // Alias for compatibility
	TokenTypeRParen          TokenType = 68
	TokenTypeRightParen      TokenType = 68 // Alias for compatibility
	TokenTypePeriod          TokenType = 69
	TokenTypeDot             TokenType = 69 // Alias for compatibility
	TokenTypeColon           TokenType = 70
	TokenTypeDoubleColon     TokenType = 71
	TokenTypeAssignment      TokenType = 72
	TokenTypeSemicolon       TokenType = 73
	TokenTypeBackslash       TokenType = 74
	TokenTypeLBracket        TokenType = 75
	TokenTypeRBracket        TokenType = 76
	TokenTypeAmpersand       TokenType = 77
	TokenTypePipe            TokenType = 78
	TokenTypeCaret           TokenType = 79
	TokenTypeLBrace          TokenType = 80
	TokenTypeRBrace          TokenType = 81
	TokenTypeRArrow          TokenType = 82
	TokenTypeSharp           TokenType = 83
	TokenTypeTilde           TokenType = 84
	TokenTypeExclamationMark TokenType = 85
	TokenTypeAtSign          TokenType = 86
	TokenTypeQuestion        TokenType = 87

	// Compound operators (100-149)
	TokenTypeTildeAsterisk                      TokenType = 100
	TokenTypeExclamationMarkTilde               TokenType = 101
	TokenTypeExclamationMarkTildeAsterisk       TokenType = 102
	TokenTypeDoubleTilde                        TokenType = 103
	TokenTypeDoubleTildeAsterisk                TokenType = 104
	TokenTypeExclamationMarkDoubleTilde         TokenType = 105
	TokenTypeExclamationMarkDoubleTildeAsterisk TokenType = 106
	TokenTypeShiftLeft                          TokenType = 107
	TokenTypeShiftRight                         TokenType = 108
	TokenTypeOverlap                            TokenType = 109
	TokenTypeDoubleExclamationMark              TokenType = 110
	TokenTypeCaretAt                            TokenType = 111
	TokenTypePGSquareRoot                       TokenType = 112
	TokenTypePGCubeRoot                         TokenType = 113
	// JSON/JSONB operators (PostgreSQL)
	TokenTypeArrow                TokenType = 114 // -> JSON field access (returns JSON)
	TokenTypeLongArrow            TokenType = 115 // ->> JSON field access (returns text)
	TokenTypeHashArrow            TokenType = 116 // #> JSON path access (returns JSON)
	TokenTypeHashLongArrow        TokenType = 117 // #>> JSON path access (returns text)
	TokenTypeAtArrow              TokenType = 118 // @> JSON contains
	TokenTypeArrowAt              TokenType = 119 // <@ JSON is contained by
	TokenTypeHashMinus            TokenType = 120 // #- Delete at JSON path
	TokenTypeAtQuestion           TokenType = 121 // @? JSON path query
	TokenTypeAtAt                 TokenType = 122 // @@ Full text search
	TokenTypeQuestionAnd          TokenType = 123 // ?& JSON key exists all
	TokenTypeQuestionPipe         TokenType = 124 // ?| JSON key exists any
	TokenTypeCustomBinaryOperator TokenType = 125

	// SQL Keywords (200-399)
	TokenTypeKeyword TokenType = 200 // Generic keyword
	TokenTypeSelect  TokenType = 201
	TokenTypeFrom    TokenType = 202
	TokenTypeWhere   TokenType = 203
	TokenTypeJoin    TokenType = 204
	TokenTypeInner   TokenType = 205
	TokenTypeLeft    TokenType = 206
	TokenTypeRight   TokenType = 207
	TokenTypeOuter   TokenType = 208
	TokenTypeOn      TokenType = 209
	TokenTypeAs      TokenType = 210
	TokenTypeAnd     TokenType = 211
	TokenTypeOr      TokenType = 212
	TokenTypeNot     TokenType = 213
	TokenTypeIn      TokenType = 214
	TokenTypeLike    TokenType = 215
	TokenTypeBetween TokenType = 216
	TokenTypeIs      TokenType = 217
	TokenTypeNull    TokenType = 218
	TokenTypeTrue    TokenType = 219
	TokenTypeFalse   TokenType = 220
	TokenTypeCase    TokenType = 221
	TokenTypeWhen    TokenType = 222
	TokenTypeThen    TokenType = 223
	TokenTypeElse    TokenType = 224
	TokenTypeEnd     TokenType = 225
	TokenTypeGroup   TokenType = 226
	TokenTypeBy      TokenType = 227
	TokenTypeHaving  TokenType = 228
	TokenTypeOrder   TokenType = 229
	TokenTypeAsc     TokenType = 230
	TokenTypeDesc    TokenType = 231
	TokenTypeLimit   TokenType = 232
	TokenTypeOffset  TokenType = 233

	// DML Keywords (234-239)
	TokenTypeInsert TokenType = 234
	TokenTypeUpdate TokenType = 235
	TokenTypeDelete TokenType = 236
	TokenTypeInto   TokenType = 237
	TokenTypeValues TokenType = 238
	TokenTypeSet    TokenType = 239

	// DDL Keywords (240-249)
	TokenTypeCreate   TokenType = 240
	TokenTypeAlter    TokenType = 241
	TokenTypeDrop     TokenType = 242
	TokenTypeTable    TokenType = 243
	TokenTypeIndex    TokenType = 244
	TokenTypeView     TokenType = 245
	TokenTypeColumn   TokenType = 246
	TokenTypeDatabase TokenType = 247
	TokenTypeSchema   TokenType = 248
	TokenTypeTrigger  TokenType = 249

	// Aggregate functions (250-269)
	TokenTypeCount TokenType = 250
	TokenTypeSum   TokenType = 251
	TokenTypeAvg   TokenType = 252
	TokenTypeMin   TokenType = 253
	TokenTypeMax   TokenType = 254

	// Compound keywords (270-279)
	TokenTypeGroupBy   TokenType = 270
	TokenTypeOrderBy   TokenType = 271
	TokenTypeLeftJoin  TokenType = 272
	TokenTypeRightJoin TokenType = 273
	TokenTypeInnerJoin TokenType = 274
	TokenTypeOuterJoin TokenType = 275
	TokenTypeFullJoin  TokenType = 276
	TokenTypeCrossJoin TokenType = 277

	// CTE and Set Operations (280-299)
	TokenTypeWith      TokenType = 280
	TokenTypeRecursive TokenType = 281
	TokenTypeUnion     TokenType = 282
	TokenTypeExcept    TokenType = 283
	TokenTypeIntersect TokenType = 284
	TokenTypeAll       TokenType = 285

	// Window Function Keywords (300-319)
	TokenTypeOver      TokenType = 300
	TokenTypePartition TokenType = 301
	TokenTypeRows      TokenType = 302
	TokenTypeRange     TokenType = 303
	TokenTypeUnbounded TokenType = 304
	TokenTypePreceding TokenType = 305
	TokenTypeFollowing TokenType = 306
	TokenTypeCurrent   TokenType = 307
	TokenTypeRow       TokenType = 308
	TokenTypeGroups    TokenType = 309
	TokenTypeFilter    TokenType = 310
	TokenTypeExclude   TokenType = 311

	// Additional Join Keywords (320-329)
	TokenTypeCross   TokenType = 320
	TokenTypeNatural TokenType = 321
	TokenTypeFull    TokenType = 322
	TokenTypeUsing   TokenType = 323
	TokenTypeLateral TokenType = 324 // LATERAL keyword for correlated subqueries in FROM clause

	// Constraint Keywords (330-349)
	TokenTypePrimary       TokenType = 330
	TokenTypeKey           TokenType = 331
	TokenTypeForeign       TokenType = 332
	TokenTypeReferences    TokenType = 333
	TokenTypeUnique        TokenType = 334
	TokenTypeCheck         TokenType = 335
	TokenTypeDefault       TokenType = 336
	TokenTypeAutoIncrement TokenType = 337
	TokenTypeConstraint    TokenType = 338
	TokenTypeNotNull       TokenType = 339
	TokenTypeNullable      TokenType = 340

	// Additional SQL Keywords (350-399)
	TokenTypeDistinct TokenType = 350
	TokenTypeExists   TokenType = 351
	TokenTypeAny      TokenType = 352
	TokenTypeSome     TokenType = 353
	TokenTypeCast     TokenType = 354
	TokenTypeConvert  TokenType = 355
	TokenTypeCollate  TokenType = 356
	TokenTypeCascade  TokenType = 357
	TokenTypeRestrict TokenType = 358
	TokenTypeReplace  TokenType = 359
	TokenTypeRename   TokenType = 360
	TokenTypeTo       TokenType = 361
	TokenTypeIf       TokenType = 362
	TokenTypeOnly     TokenType = 363
	TokenTypeFor      TokenType = 364
	TokenTypeNulls    TokenType = 365
	TokenTypeFirst    TokenType = 366
	TokenTypeLast     TokenType = 367
	TokenTypeFetch    TokenType = 368 // FETCH keyword for FETCH FIRST/NEXT clause
	TokenTypeNext     TokenType = 369 // NEXT keyword for FETCH NEXT clause

	// MERGE Statement Keywords (370-379)
	TokenTypeMerge   TokenType = 370
	TokenTypeMatched TokenType = 371
	TokenTypeTarget  TokenType = 372
	TokenTypeSource  TokenType = 373

	// Materialized View Keywords (374-379)
	TokenTypeMaterialized TokenType = 374
	TokenTypeRefresh      TokenType = 375
	TokenTypeTies         TokenType = 376 // TIES keyword for WITH TIES in FETCH clause
	TokenTypePercent      TokenType = 377 // PERCENT keyword for FETCH ... PERCENT ROWS
	TokenTypeTruncate     TokenType = 378 // TRUNCATE keyword for TRUNCATE TABLE statement
	TokenTypeReturning    TokenType = 379 // RETURNING keyword for PostgreSQL RETURNING clause

	// Grouping Set Keywords (390-399)
	TokenTypeGroupingSets TokenType = 390
	TokenTypeRollup       TokenType = 391
	TokenTypeCube         TokenType = 392
	TokenTypeGrouping     TokenType = 393
	TokenTypeSets         TokenType = 394 // SETS keyword for GROUPING SETS

	// Role/Permission Keywords (400-419)
	TokenTypeRole       TokenType = 400
	TokenTypeUser       TokenType = 401
	TokenTypeGrant      TokenType = 402
	TokenTypeRevoke     TokenType = 403
	TokenTypePrivilege  TokenType = 404
	TokenTypePassword   TokenType = 405
	TokenTypeLogin      TokenType = 406
	TokenTypeSuperuser  TokenType = 407
	TokenTypeCreateDB   TokenType = 408
	TokenTypeCreateRole TokenType = 409

	// Transaction Keywords (420-429)
	TokenTypeBegin     TokenType = 420
	TokenTypeCommit    TokenType = 421
	TokenTypeRollback  TokenType = 422
	TokenTypeSavepoint TokenType = 423

	// Data Type Keywords (430-449)
	TokenTypeInt          TokenType = 430
	TokenTypeInteger      TokenType = 431
	TokenTypeBigInt       TokenType = 432
	TokenTypeSmallInt     TokenType = 433
	TokenTypeFloat        TokenType = 434
	TokenTypeDouble       TokenType = 435
	TokenTypeDecimal      TokenType = 436
	TokenTypeNumeric      TokenType = 437
	TokenTypeVarchar      TokenType = 438
	TokenTypeCharDataType TokenType = 439 // Char as data type (TokenTypeChar=12 is for single char token)
	TokenTypeText         TokenType = 440
	TokenTypeBoolean      TokenType = 441
	TokenTypeDate         TokenType = 442
	TokenTypeTime         TokenType = 443
	TokenTypeTimestamp    TokenType = 444
	TokenTypeInterval     TokenType = 445
	TokenTypeBlob         TokenType = 446
	TokenTypeClob         TokenType = 447
	TokenTypeJson         TokenType = 448
	TokenTypeUuid         TokenType = 449

	// Special Token Types (500-509)
	TokenTypeIllegal    TokenType = 500 // For parser compatibility with token.ILLEGAL
	TokenTypeAsterisk   TokenType = 501 // Explicit asterisk token type
	TokenTypeDoublePipe TokenType = 502 // || concatenation operator
)

// tokenStringMap provides efficient O(1) lookup for token type to string conversion
var tokenStringMap = map[TokenType]string{
	// Special tokens
	TokenTypeEOF:     "EOF",
	TokenTypeUnknown: "UNKNOWN",

	// Basic token types
	TokenTypeWord:        "WORD",
	TokenTypeNumber:      "NUMBER",
	TokenTypeChar:        "CHAR",
	TokenTypeWhitespace:  "WHITESPACE",
	TokenTypeIdentifier:  "IDENTIFIER",
	TokenTypePlaceholder: "PLACEHOLDER",

	// String literals
	TokenTypeString:                   "STRING",
	TokenTypeSingleQuotedString:       "STRING",
	TokenTypeDoubleQuotedString:       "DOUBLE_QUOTED_STRING",
	TokenTypeTripleSingleQuotedString: "TRIPLE_SINGLE_QUOTED_STRING",
	TokenTypeTripleDoubleQuotedString: "TRIPLE_DOUBLE_QUOTED_STRING",
	TokenTypeDollarQuotedString:       "DOLLAR_QUOTED_STRING",
	TokenTypeByteStringLiteral:        "BYTE_STRING_LITERAL",
	TokenTypeNationalStringLiteral:    "NATIONAL_STRING_LITERAL",
	TokenTypeEscapedStringLiteral:     "ESCAPED_STRING_LITERAL",
	TokenTypeUnicodeStringLiteral:     "UNICODE_STRING_LITERAL",
	TokenTypeHexStringLiteral:         "HEX_STRING_LITERAL",

	// Operators and punctuation
	TokenTypeOperator:        "OPERATOR",
	TokenTypeComma:           "COMMA",
	TokenTypeEq:              "EQ",
	TokenTypeDoubleEq:        "DOUBLE_EQ",
	TokenTypeNeq:             "NEQ",
	TokenTypeLt:              "LT",
	TokenTypeGt:              "GT",
	TokenTypeLtEq:            "LT_EQ",
	TokenTypeGtEq:            "GT_EQ",
	TokenTypeSpaceship:       "SPACESHIP",
	TokenTypePlus:            "PLUS",
	TokenTypeMinus:           "MINUS",
	TokenTypeMul:             "MUL",
	TokenTypeDiv:             "DIV",
	TokenTypeDuckIntDiv:      "DUCK_INT_DIV",
	TokenTypeMod:             "MOD",
	TokenTypeStringConcat:    "STRING_CONCAT",
	TokenTypeLParen:          "LPAREN",
	TokenTypeRParen:          "RPAREN",
	TokenTypePeriod:          "PERIOD",
	TokenTypeColon:           "COLON",
	TokenTypeDoubleColon:     "DOUBLE_COLON",
	TokenTypeAssignment:      "ASSIGNMENT",
	TokenTypeSemicolon:       "SEMICOLON",
	TokenTypeBackslash:       "BACKSLASH",
	TokenTypeLBracket:        "LBRACKET",
	TokenTypeRBracket:        "RBRACKET",
	TokenTypeAmpersand:       "AMPERSAND",
	TokenTypePipe:            "PIPE",
	TokenTypeCaret:           "CARET",
	TokenTypeLBrace:          "LBRACE",
	TokenTypeRBrace:          "RBRACE",
	TokenTypeRArrow:          "R_ARROW",
	TokenTypeSharp:           "SHARP",
	TokenTypeTilde:           "TILDE",
	TokenTypeExclamationMark: "EXCLAMATION_MARK",
	TokenTypeAtSign:          "AT_SIGN",
	TokenTypeQuestion:        "QUESTION",

	// JSON/JSONB operators
	TokenTypeArrow:         "ARROW",           // ->
	TokenTypeLongArrow:     "LONG_ARROW",      // ->>
	TokenTypeHashArrow:     "HASH_ARROW",      // #>
	TokenTypeHashLongArrow: "HASH_LONG_ARROW", // #>>
	TokenTypeAtArrow:       "AT_ARROW",        // @>
	TokenTypeArrowAt:       "ARROW_AT",        // <@
	TokenTypeHashMinus:     "HASH_MINUS",      // #-
	TokenTypeAtQuestion:    "AT_QUESTION",     // @?
	TokenTypeAtAt:          "AT_AT",           // @@
	TokenTypeQuestionAnd:   "QUESTION_AND",    // ?&
	TokenTypeQuestionPipe:  "QUESTION_PIPE",   // ?|

	// SQL Keywords
	TokenTypeKeyword: "KEYWORD",
	TokenTypeSelect:  "SELECT",
	TokenTypeFrom:    "FROM",
	TokenTypeWhere:   "WHERE",
	TokenTypeJoin:    "JOIN",
	TokenTypeInner:   "INNER",
	TokenTypeLeft:    "LEFT",
	TokenTypeRight:   "RIGHT",
	TokenTypeOuter:   "OUTER",
	TokenTypeOn:      "ON",
	TokenTypeAs:      "AS",
	TokenTypeAnd:     "AND",
	TokenTypeOr:      "OR",
	TokenTypeNot:     "NOT",
	TokenTypeIn:      "IN",
	TokenTypeLike:    "LIKE",
	TokenTypeBetween: "BETWEEN",
	TokenTypeIs:      "IS",
	TokenTypeNull:    "NULL",
	TokenTypeTrue:    "TRUE",
	TokenTypeFalse:   "FALSE",
	TokenTypeCase:    "CASE",
	TokenTypeWhen:    "WHEN",
	TokenTypeThen:    "THEN",
	TokenTypeElse:    "ELSE",
	TokenTypeEnd:     "END",
	TokenTypeGroup:   "GROUP",
	TokenTypeBy:      "BY",
	TokenTypeHaving:  "HAVING",
	TokenTypeOrder:   "ORDER",
	TokenTypeAsc:     "ASC",
	TokenTypeDesc:    "DESC",
	TokenTypeLimit:   "LIMIT",
	TokenTypeOffset:  "OFFSET",

	// Aggregate functions
	TokenTypeCount: "COUNT",
	TokenTypeSum:   "SUM",
	TokenTypeAvg:   "AVG",
	TokenTypeMin:   "MIN",
	TokenTypeMax:   "MAX",

	// DML Keywords
	TokenTypeInsert: "INSERT",
	TokenTypeUpdate: "UPDATE",
	TokenTypeDelete: "DELETE",
	TokenTypeInto:   "INTO",
	TokenTypeValues: "VALUES",
	TokenTypeSet:    "SET",

	// DDL Keywords
	TokenTypeCreate:   "CREATE",
	TokenTypeAlter:    "ALTER",
	TokenTypeDrop:     "DROP",
	TokenTypeTable:    "TABLE",
	TokenTypeIndex:    "INDEX",
	TokenTypeView:     "VIEW",
	TokenTypeColumn:   "COLUMN",
	TokenTypeDatabase: "DATABASE",
	TokenTypeSchema:   "SCHEMA",
	TokenTypeTrigger:  "TRIGGER",

	// Compound keywords
	TokenTypeGroupBy:   "GROUP_BY",
	TokenTypeOrderBy:   "ORDER_BY",
	TokenTypeLeftJoin:  "LEFT_JOIN",
	TokenTypeRightJoin: "RIGHT_JOIN",
	TokenTypeInnerJoin: "INNER_JOIN",
	TokenTypeOuterJoin: "OUTER_JOIN",
	TokenTypeFullJoin:  "FULL_JOIN",
	TokenTypeCrossJoin: "CROSS_JOIN",

	// CTE and Set Operations
	TokenTypeWith:      "WITH",
	TokenTypeRecursive: "RECURSIVE",
	TokenTypeUnion:     "UNION",
	TokenTypeExcept:    "EXCEPT",
	TokenTypeIntersect: "INTERSECT",
	TokenTypeAll:       "ALL",

	// Window Function Keywords
	TokenTypeOver:      "OVER",
	TokenTypePartition: "PARTITION",
	TokenTypeRows:      "ROWS",
	TokenTypeRange:     "RANGE",
	TokenTypeUnbounded: "UNBOUNDED",
	TokenTypePreceding: "PRECEDING",
	TokenTypeFollowing: "FOLLOWING",
	TokenTypeCurrent:   "CURRENT",
	TokenTypeRow:       "ROW",
	TokenTypeGroups:    "GROUPS",
	TokenTypeFilter:    "FILTER",
	TokenTypeExclude:   "EXCLUDE",

	// Additional Join Keywords
	TokenTypeCross:   "CROSS",
	TokenTypeNatural: "NATURAL",
	TokenTypeFull:    "FULL",
	TokenTypeUsing:   "USING",
	TokenTypeLateral: "LATERAL",

	// Constraint Keywords
	TokenTypePrimary:       "PRIMARY",
	TokenTypeKey:           "KEY",
	TokenTypeForeign:       "FOREIGN",
	TokenTypeReferences:    "REFERENCES",
	TokenTypeUnique:        "UNIQUE",
	TokenTypeCheck:         "CHECK",
	TokenTypeDefault:       "DEFAULT",
	TokenTypeAutoIncrement: "AUTO_INCREMENT",
	TokenTypeConstraint:    "CONSTRAINT",
	TokenTypeNotNull:       "NOT_NULL",
	TokenTypeNullable:      "NULLABLE",

	// Additional SQL Keywords
	TokenTypeDistinct: "DISTINCT",
	TokenTypeExists:   "EXISTS",
	TokenTypeAny:      "ANY",
	TokenTypeSome:     "SOME",
	TokenTypeCast:     "CAST",
	TokenTypeConvert:  "CONVERT",
	TokenTypeCollate:  "COLLATE",
	TokenTypeCascade:  "CASCADE",
	TokenTypeRestrict: "RESTRICT",
	TokenTypeReplace:  "REPLACE",
	TokenTypeRename:   "RENAME",
	TokenTypeTo:       "TO",
	TokenTypeIf:       "IF",
	TokenTypeOnly:     "ONLY",
	TokenTypeFor:      "FOR",
	TokenTypeNulls:    "NULLS",
	TokenTypeFirst:    "FIRST",
	TokenTypeLast:     "LAST",
	TokenTypeFetch:    "FETCH",
	TokenTypeNext:     "NEXT",

	// MERGE Statement Keywords
	TokenTypeMerge:   "MERGE",
	TokenTypeMatched: "MATCHED",
	TokenTypeTarget:  "TARGET",
	TokenTypeSource:  "SOURCE",

	// Materialized View Keywords
	TokenTypeMaterialized: "MATERIALIZED",
	TokenTypeRefresh:      "REFRESH",
	TokenTypeTies:         "TIES",
	TokenTypePercent:      "PERCENT",
	TokenTypeTruncate:     "TRUNCATE",

	// Grouping Set Keywords
	TokenTypeGroupingSets: "GROUPING_SETS",
	TokenTypeRollup:       "ROLLUP",
	TokenTypeCube:         "CUBE",
	TokenTypeGrouping:     "GROUPING",
	TokenTypeSets:         "SETS",

	// Role/Permission Keywords
	TokenTypeRole:       "ROLE",
	TokenTypeUser:       "USER",
	TokenTypeGrant:      "GRANT",
	TokenTypeRevoke:     "REVOKE",
	TokenTypePrivilege:  "PRIVILEGE",
	TokenTypePassword:   "PASSWORD",
	TokenTypeLogin:      "LOGIN",
	TokenTypeSuperuser:  "SUPERUSER",
	TokenTypeCreateDB:   "CREATEDB",
	TokenTypeCreateRole: "CREATEROLE",

	// Transaction Keywords
	TokenTypeBegin:     "BEGIN",
	TokenTypeCommit:    "COMMIT",
	TokenTypeRollback:  "ROLLBACK",
	TokenTypeSavepoint: "SAVEPOINT",

	// Data Type Keywords
	TokenTypeInt:          "INT",
	TokenTypeInteger:      "INTEGER",
	TokenTypeBigInt:       "BIGINT",
	TokenTypeSmallInt:     "SMALLINT",
	TokenTypeFloat:        "FLOAT",
	TokenTypeDouble:       "DOUBLE",
	TokenTypeDecimal:      "DECIMAL",
	TokenTypeNumeric:      "NUMERIC",
	TokenTypeVarchar:      "VARCHAR",
	TokenTypeCharDataType: "CHAR",
	TokenTypeText:         "TEXT",
	TokenTypeBoolean:      "BOOLEAN",
	TokenTypeDate:         "DATE",
	TokenTypeTime:         "TIME",
	TokenTypeTimestamp:    "TIMESTAMP",
	TokenTypeInterval:     "INTERVAL",
	TokenTypeBlob:         "BLOB",
	TokenTypeClob:         "CLOB",
	TokenTypeJson:         "JSON",
	TokenTypeUuid:         "UUID",

	// Special Token Types
	TokenTypeIllegal:    "ILLEGAL",
	TokenTypeAsterisk:   "*",
	TokenTypeDoublePipe: "||",
}

// String returns a string representation of the token type
func (t TokenType) String() string {
	if str, exists := tokenStringMap[t]; exists {
		return str
	}
	return "TOKEN"
}

// IsKeyword returns true if the token type is a SQL keyword.
// Uses range-based checking for O(1) performance (~0.24ns/op).
//
// Example:
//
//	if token.ModelType.IsKeyword() {
//	    // Handle SQL keyword token
//	}
func (t TokenType) IsKeyword() bool {
	// Use range constants for maintainability
	return (t >= TokenRangeKeywordStart && t < TokenRangeKeywordEnd &&
		t != TokenTypeAsterisk && t != TokenTypeDoublePipe && t != TokenTypeIllegal)
}

// IsOperator returns true if the token type is an operator.
// Uses range-based checking for O(1) performance.
//
// Example:
//
//	if token.ModelType.IsOperator() {
//	    // Handle operator token (e.g., +, -, *, /, etc.)
//	}
func (t TokenType) IsOperator() bool {
	// Use range constants for maintainability
	return (t >= TokenRangeOperatorStart && t < TokenRangeOperatorEnd) ||
		t == TokenTypeAsterisk || t == TokenTypeDoublePipe
}

// IsLiteral returns true if the token type is a literal value.
// Includes identifiers, numbers, strings, and boolean/null literals.
//
// Example:
//
//	if token.ModelType.IsLiteral() {
//	    // Handle literal value (identifier, number, string, true/false/null)
//	}
func (t TokenType) IsLiteral() bool {
	switch t {
	case TokenTypeIdentifier, TokenTypeNumber, TokenTypeString,
		TokenTypeSingleQuotedString, TokenTypeDoubleQuotedString,
		TokenTypeTrue, TokenTypeFalse, TokenTypeNull:
		return true
	}
	return false
}

// IsDMLKeyword returns true if the token type is a DML keyword
func (t TokenType) IsDMLKeyword() bool {
	switch t {
	case TokenTypeSelect, TokenTypeInsert, TokenTypeUpdate, TokenTypeDelete,
		TokenTypeInto, TokenTypeValues, TokenTypeSet, TokenTypeFrom, TokenTypeWhere:
		return true
	}
	return false
}

// IsDDLKeyword returns true if the token type is a DDL keyword
func (t TokenType) IsDDLKeyword() bool {
	switch t {
	case TokenTypeCreate, TokenTypeAlter, TokenTypeDrop, TokenTypeTruncate, TokenTypeTable,
		TokenTypeIndex, TokenTypeView, TokenTypeColumn, TokenTypeDatabase,
		TokenTypeSchema, TokenTypeTrigger:
		return true
	}
	return false
}

// IsJoinKeyword returns true if the token type is a JOIN-related keyword
func (t TokenType) IsJoinKeyword() bool {
	switch t {
	case TokenTypeJoin, TokenTypeInner, TokenTypeLeft, TokenTypeRight,
		TokenTypeOuter, TokenTypeCross, TokenTypeNatural, TokenTypeFull,
		TokenTypeInnerJoin, TokenTypeLeftJoin, TokenTypeRightJoin,
		TokenTypeOuterJoin, TokenTypeFullJoin, TokenTypeCrossJoin,
		TokenTypeOn, TokenTypeUsing:
		return true
	}
	return false
}

// IsWindowKeyword returns true if the token type is a window function keyword
func (t TokenType) IsWindowKeyword() bool {
	switch t {
	case TokenTypeOver, TokenTypePartition, TokenTypeRows, TokenTypeRange,
		TokenTypeUnbounded, TokenTypePreceding, TokenTypeFollowing,
		TokenTypeCurrent, TokenTypeRow, TokenTypeGroups, TokenTypeFilter,
		TokenTypeExclude:
		return true
	}
	return false
}

// IsAggregateFunction returns true if the token type is an aggregate function
func (t TokenType) IsAggregateFunction() bool {
	switch t {
	case TokenTypeCount, TokenTypeSum, TokenTypeAvg, TokenTypeMin, TokenTypeMax:
		return true
	}
	return false
}

// IsDataType returns true if the token type is a SQL data type.
// Uses range-based checking for O(1) performance.
//
// Example:
//
//	if token.ModelType.IsDataType() {
//	    // Handle data type token (INT, VARCHAR, BOOLEAN, etc.)
//	}
func (t TokenType) IsDataType() bool {
	// Use range constants for maintainability
	return t >= TokenRangeDataTypeStart && t < TokenRangeDataTypeEnd
}

// IsConstraint returns true if the token type is a constraint keyword
func (t TokenType) IsConstraint() bool {
	switch t {
	case TokenTypePrimary, TokenTypeKey, TokenTypeForeign, TokenTypeReferences,
		TokenTypeUnique, TokenTypeCheck, TokenTypeDefault, TokenTypeAutoIncrement,
		TokenTypeConstraint, TokenTypeNotNull, TokenTypeNullable:
		return true
	}
	return false
}

// IsSetOperation returns true if the token type is a set operation
func (t TokenType) IsSetOperation() bool {
	switch t {
	case TokenTypeUnion, TokenTypeExcept, TokenTypeIntersect, TokenTypeAll:
		return true
	}
	return false
}
