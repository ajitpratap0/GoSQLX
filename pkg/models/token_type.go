package models

// TokenType represents the type of a SQL token.
//
// TokenType is the core classification system for all lexical units in SQL.
// GoSQLX v1.6.0 supports 500+ distinct token types organized into logical
// ranges for efficient categorization and type checking.
//
// Token Type Organization:
//
//   - Special (0-9): EOF, UNKNOWN
//   - Basic (10-29): WORD, NUMBER, IDENTIFIER, PLACEHOLDER
//   - Strings (30-49): Various string literal formats
//   - Operators (50-149): Arithmetic, comparison, JSON/JSONB operators
//   - Keywords (200-499): SQL keywords by category
//   - Data Types (430-449): SQL data type keywords
//
// v1.6.0 PostgreSQL Extensions:
//
//   - JSON/JSONB Operators: ->, ->>, #>, #>>, @>, <@, #-, @?, @@, ?&, ?|
//   - LATERAL: Correlated subqueries in FROM clause
//   - RETURNING: Return modified rows from DML statements
//   - FILTER: Conditional aggregation in window functions
//   - DISTINCT ON: PostgreSQL-specific row selection
//
// Performance: TokenType is an int with O(1) lookup via range checking.
// All Is* methods use constant-time comparisons.
//
// Example usage:
//
//	// Check token category
//	if tokenType.IsKeyword() {
//	    // Handle SQL keyword
//	}
//	if tokenType.IsOperator() {
//	    // Handle operator (+, -, *, /, ->, etc.)
//	}
//
//	// Check specific categories
//	if tokenType.IsWindowKeyword() {
//	    // Handle OVER, PARTITION BY, ROWS, RANGE
//	}
//	if tokenType.IsDMLKeyword() {
//	    // Handle SELECT, INSERT, UPDATE, DELETE
//	}
//
//	// PostgreSQL JSON operators
//	switch tokenType {
//	case TokenTypeArrow:      // -> (JSON field access)
//	case TokenTypeLongArrow:  // ->> (JSON field as text)
//	    // Handle JSON operations
//	}
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

	// Row Locking Keywords (380-389)
	TokenTypeShare  TokenType = 380 // SHARE keyword for FOR SHARE row locking
	TokenTypeNoWait TokenType = 381 // NOWAIT keyword for FOR UPDATE/SHARE NOWAIT
	TokenTypeSkip   TokenType = 382 // SKIP keyword for FOR UPDATE SKIP LOCKED
	TokenTypeLocked TokenType = 383 // LOCKED keyword for SKIP LOCKED
	TokenTypeOf     TokenType = 384 // OF keyword for FOR UPDATE OF table_name

	// Grouping Set Keywords (390-399)
	TokenTypeGroupingSets TokenType = 390
	TokenTypeRollup       TokenType = 391
	TokenTypeCube         TokenType = 392
	TokenTypeGrouping     TokenType = 393
	TokenTypeSets         TokenType = 394 // SETS keyword for GROUPING SETS
	TokenTypeArray        TokenType = 395 // ARRAY keyword for PostgreSQL array constructor
	TokenTypeWithin       TokenType = 396 // WITHIN keyword for WITHIN GROUP clause

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

// String returns a human-readable string representation of the token type.
//
// Provides names for debugging, error messages, and logging.
// Uses a switch statement for O(1) compiled jump-table lookup.
// Covers ALL defined TokenType constants for completeness.
//
// Example:
//
//	tokenType := models.TokenTypeSelect
//	fmt.Println(tokenType.String()) // Output: "SELECT"
//
//	tokenType = models.TokenTypeLongArrow
//	fmt.Println(tokenType.String()) // Output: "LONG_ARROW"
func (t TokenType) String() string {
	switch t {
	// Special tokens
	case TokenTypeEOF:
		return "EOF"
	case TokenTypeUnknown:
		return "UNKNOWN"

	// Basic token types (10-29)
	case TokenTypeWord:
		return "WORD"
	case TokenTypeNumber:
		return "NUMBER"
	case TokenTypeChar:
		return "CHAR"
	case TokenTypeWhitespace:
		return "WHITESPACE"
	case TokenTypeIdentifier:
		return "IDENTIFIER"
	case TokenTypePlaceholder:
		return "PLACEHOLDER"

	// String literals (30-49)
	case TokenTypeString:
		return "STRING"
	case TokenTypeSingleQuotedString:
		return "STRING"
	case TokenTypeDoubleQuotedString:
		return "DOUBLE_QUOTED_STRING"
	case TokenTypeTripleSingleQuotedString:
		return "TRIPLE_SINGLE_QUOTED_STRING"
	case TokenTypeTripleDoubleQuotedString:
		return "TRIPLE_DOUBLE_QUOTED_STRING"
	case TokenTypeDollarQuotedString:
		return "DOLLAR_QUOTED_STRING"
	case TokenTypeByteStringLiteral:
		return "BYTE_STRING_LITERAL"
	case TokenTypeNationalStringLiteral:
		return "NATIONAL_STRING_LITERAL"
	case TokenTypeEscapedStringLiteral:
		return "ESCAPED_STRING_LITERAL"
	case TokenTypeUnicodeStringLiteral:
		return "UNICODE_STRING_LITERAL"
	case TokenTypeHexStringLiteral:
		return "HEX_STRING_LITERAL"

	// Operators and punctuation (50-99)
	case TokenTypeOperator:
		return "OPERATOR"
	case TokenTypeComma:
		return "COMMA"
	case TokenTypeEq:
		return "EQ"
	case TokenTypeDoubleEq:
		return "DOUBLE_EQ"
	case TokenTypeNeq:
		return "NEQ"
	case TokenTypeLt:
		return "LT"
	case TokenTypeGt:
		return "GT"
	case TokenTypeLtEq:
		return "LT_EQ"
	case TokenTypeGtEq:
		return "GT_EQ"
	case TokenTypeSpaceship:
		return "SPACESHIP"
	case TokenTypePlus:
		return "PLUS"
	case TokenTypeMinus:
		return "MINUS"
	case TokenTypeMul:
		return "MUL"
	case TokenTypeDiv:
		return "DIV"
	case TokenTypeDuckIntDiv:
		return "DUCK_INT_DIV"
	case TokenTypeMod:
		return "MOD"
	case TokenTypeStringConcat:
		return "STRING_CONCAT"
	case TokenTypeLParen:
		return "LPAREN"
	case TokenTypeRParen:
		return "RPAREN"
	case TokenTypePeriod:
		return "PERIOD"
	case TokenTypeColon:
		return "COLON"
	case TokenTypeDoubleColon:
		return "DOUBLE_COLON"
	case TokenTypeAssignment:
		return "ASSIGNMENT"
	case TokenTypeSemicolon:
		return "SEMICOLON"
	case TokenTypeBackslash:
		return "BACKSLASH"
	case TokenTypeLBracket:
		return "LBRACKET"
	case TokenTypeRBracket:
		return "RBRACKET"
	case TokenTypeAmpersand:
		return "AMPERSAND"
	case TokenTypePipe:
		return "PIPE"
	case TokenTypeCaret:
		return "CARET"
	case TokenTypeLBrace:
		return "LBRACE"
	case TokenTypeRBrace:
		return "RBRACE"
	case TokenTypeRArrow:
		return "R_ARROW"
	case TokenTypeSharp:
		return "SHARP"
	case TokenTypeTilde:
		return "TILDE"
	case TokenTypeExclamationMark:
		return "EXCLAMATION_MARK"
	case TokenTypeAtSign:
		return "AT_SIGN"
	case TokenTypeQuestion:
		return "QUESTION"

	// Compound operators (100-149)
	case TokenTypeTildeAsterisk:
		return "TILDE_ASTERISK"
	case TokenTypeExclamationMarkTilde:
		return "EXCLAMATION_MARK_TILDE"
	case TokenTypeExclamationMarkTildeAsterisk:
		return "EXCLAMATION_MARK_TILDE_ASTERISK"
	case TokenTypeDoubleTilde:
		return "DOUBLE_TILDE"
	case TokenTypeDoubleTildeAsterisk:
		return "DOUBLE_TILDE_ASTERISK"
	case TokenTypeExclamationMarkDoubleTilde:
		return "EXCLAMATION_MARK_DOUBLE_TILDE"
	case TokenTypeExclamationMarkDoubleTildeAsterisk:
		return "EXCLAMATION_MARK_DOUBLE_TILDE_ASTERISK"
	case TokenTypeShiftLeft:
		return "SHIFT_LEFT"
	case TokenTypeShiftRight:
		return "SHIFT_RIGHT"
	case TokenTypeOverlap:
		return "OVERLAP"
	case TokenTypeDoubleExclamationMark:
		return "DOUBLE_EXCLAMATION_MARK"
	case TokenTypeCaretAt:
		return "CARET_AT"
	case TokenTypePGSquareRoot:
		return "PG_SQUARE_ROOT"
	case TokenTypePGCubeRoot:
		return "PG_CUBE_ROOT"
	case TokenTypeArrow:
		return "ARROW"
	case TokenTypeLongArrow:
		return "LONG_ARROW"
	case TokenTypeHashArrow:
		return "HASH_ARROW"
	case TokenTypeHashLongArrow:
		return "HASH_LONG_ARROW"
	case TokenTypeAtArrow:
		return "AT_ARROW"
	case TokenTypeArrowAt:
		return "ARROW_AT"
	case TokenTypeHashMinus:
		return "HASH_MINUS"
	case TokenTypeAtQuestion:
		return "AT_QUESTION"
	case TokenTypeAtAt:
		return "AT_AT"
	case TokenTypeQuestionAnd:
		return "QUESTION_AND"
	case TokenTypeQuestionPipe:
		return "QUESTION_PIPE"
	case TokenTypeCustomBinaryOperator:
		return "CUSTOM_BINARY_OPERATOR"

	// SQL Keywords (200-399)
	case TokenTypeKeyword:
		return "KEYWORD"
	case TokenTypeSelect:
		return "SELECT"
	case TokenTypeFrom:
		return "FROM"
	case TokenTypeWhere:
		return "WHERE"
	case TokenTypeJoin:
		return "JOIN"
	case TokenTypeInner:
		return "INNER"
	case TokenTypeLeft:
		return "LEFT"
	case TokenTypeRight:
		return "RIGHT"
	case TokenTypeOuter:
		return "OUTER"
	case TokenTypeOn:
		return "ON"
	case TokenTypeAs:
		return "AS"
	case TokenTypeAnd:
		return "AND"
	case TokenTypeOr:
		return "OR"
	case TokenTypeNot:
		return "NOT"
	case TokenTypeIn:
		return "IN"
	case TokenTypeLike:
		return "LIKE"
	case TokenTypeBetween:
		return "BETWEEN"
	case TokenTypeIs:
		return "IS"
	case TokenTypeNull:
		return "NULL"
	case TokenTypeTrue:
		return "TRUE"
	case TokenTypeFalse:
		return "FALSE"
	case TokenTypeCase:
		return "CASE"
	case TokenTypeWhen:
		return "WHEN"
	case TokenTypeThen:
		return "THEN"
	case TokenTypeElse:
		return "ELSE"
	case TokenTypeEnd:
		return "END"
	case TokenTypeGroup:
		return "GROUP"
	case TokenTypeBy:
		return "BY"
	case TokenTypeHaving:
		return "HAVING"
	case TokenTypeOrder:
		return "ORDER"
	case TokenTypeAsc:
		return "ASC"
	case TokenTypeDesc:
		return "DESC"
	case TokenTypeLimit:
		return "LIMIT"
	case TokenTypeOffset:
		return "OFFSET"

	// DML Keywords
	case TokenTypeInsert:
		return "INSERT"
	case TokenTypeUpdate:
		return "UPDATE"
	case TokenTypeDelete:
		return "DELETE"
	case TokenTypeInto:
		return "INTO"
	case TokenTypeValues:
		return "VALUES"
	case TokenTypeSet:
		return "SET"

	// DDL Keywords
	case TokenTypeCreate:
		return "CREATE"
	case TokenTypeAlter:
		return "ALTER"
	case TokenTypeDrop:
		return "DROP"
	case TokenTypeTable:
		return "TABLE"
	case TokenTypeIndex:
		return "INDEX"
	case TokenTypeView:
		return "VIEW"
	case TokenTypeColumn:
		return "COLUMN"
	case TokenTypeDatabase:
		return "DATABASE"
	case TokenTypeSchema:
		return "SCHEMA"
	case TokenTypeTrigger:
		return "TRIGGER"

	// Aggregate functions
	case TokenTypeCount:
		return "COUNT"
	case TokenTypeSum:
		return "SUM"
	case TokenTypeAvg:
		return "AVG"
	case TokenTypeMin:
		return "MIN"
	case TokenTypeMax:
		return "MAX"

	// Compound keywords
	case TokenTypeGroupBy:
		return "GROUP_BY"
	case TokenTypeOrderBy:
		return "ORDER_BY"
	case TokenTypeLeftJoin:
		return "LEFT_JOIN"
	case TokenTypeRightJoin:
		return "RIGHT_JOIN"
	case TokenTypeInnerJoin:
		return "INNER_JOIN"
	case TokenTypeOuterJoin:
		return "OUTER_JOIN"
	case TokenTypeFullJoin:
		return "FULL_JOIN"
	case TokenTypeCrossJoin:
		return "CROSS_JOIN"

	// CTE and Set Operations
	case TokenTypeWith:
		return "WITH"
	case TokenTypeRecursive:
		return "RECURSIVE"
	case TokenTypeUnion:
		return "UNION"
	case TokenTypeExcept:
		return "EXCEPT"
	case TokenTypeIntersect:
		return "INTERSECT"
	case TokenTypeAll:
		return "ALL"

	// Window Function Keywords
	case TokenTypeOver:
		return "OVER"
	case TokenTypePartition:
		return "PARTITION"
	case TokenTypeRows:
		return "ROWS"
	case TokenTypeRange:
		return "RANGE"
	case TokenTypeUnbounded:
		return "UNBOUNDED"
	case TokenTypePreceding:
		return "PRECEDING"
	case TokenTypeFollowing:
		return "FOLLOWING"
	case TokenTypeCurrent:
		return "CURRENT"
	case TokenTypeRow:
		return "ROW"
	case TokenTypeGroups:
		return "GROUPS"
	case TokenTypeFilter:
		return "FILTER"
	case TokenTypeExclude:
		return "EXCLUDE"

	// Additional Join Keywords
	case TokenTypeCross:
		return "CROSS"
	case TokenTypeNatural:
		return "NATURAL"
	case TokenTypeFull:
		return "FULL"
	case TokenTypeUsing:
		return "USING"
	case TokenTypeLateral:
		return "LATERAL"

	// Constraint Keywords
	case TokenTypePrimary:
		return "PRIMARY"
	case TokenTypeKey:
		return "KEY"
	case TokenTypeForeign:
		return "FOREIGN"
	case TokenTypeReferences:
		return "REFERENCES"
	case TokenTypeUnique:
		return "UNIQUE"
	case TokenTypeCheck:
		return "CHECK"
	case TokenTypeDefault:
		return "DEFAULT"
	case TokenTypeAutoIncrement:
		return "AUTO_INCREMENT"
	case TokenTypeConstraint:
		return "CONSTRAINT"
	case TokenTypeNotNull:
		return "NOT_NULL"
	case TokenTypeNullable:
		return "NULLABLE"

	// Additional SQL Keywords
	case TokenTypeDistinct:
		return "DISTINCT"
	case TokenTypeExists:
		return "EXISTS"
	case TokenTypeAny:
		return "ANY"
	case TokenTypeSome:
		return "SOME"
	case TokenTypeCast:
		return "CAST"
	case TokenTypeConvert:
		return "CONVERT"
	case TokenTypeCollate:
		return "COLLATE"
	case TokenTypeCascade:
		return "CASCADE"
	case TokenTypeRestrict:
		return "RESTRICT"
	case TokenTypeReplace:
		return "REPLACE"
	case TokenTypeRename:
		return "RENAME"
	case TokenTypeTo:
		return "TO"
	case TokenTypeIf:
		return "IF"
	case TokenTypeOnly:
		return "ONLY"
	case TokenTypeFor:
		return "FOR"
	case TokenTypeNulls:
		return "NULLS"
	case TokenTypeFirst:
		return "FIRST"
	case TokenTypeLast:
		return "LAST"
	case TokenTypeFetch:
		return "FETCH"
	case TokenTypeNext:
		return "NEXT"

	// MERGE Statement Keywords
	case TokenTypeMerge:
		return "MERGE"
	case TokenTypeMatched:
		return "MATCHED"
	case TokenTypeTarget:
		return "TARGET"
	case TokenTypeSource:
		return "SOURCE"

	// Materialized View Keywords
	case TokenTypeMaterialized:
		return "MATERIALIZED"
	case TokenTypeRefresh:
		return "REFRESH"
	case TokenTypeTies:
		return "TIES"
	case TokenTypePercent:
		return "PERCENT"
	case TokenTypeTruncate:
		return "TRUNCATE"
	case TokenTypeReturning:
		return "RETURNING"

	// Row Locking Keywords
	case TokenTypeShare:
		return "SHARE"
	case TokenTypeNoWait:
		return "NOWAIT"
	case TokenTypeSkip:
		return "SKIP"
	case TokenTypeLocked:
		return "LOCKED"
	case TokenTypeOf:
		return "OF"

	// Grouping Set Keywords
	case TokenTypeGroupingSets:
		return "GROUPING_SETS"
	case TokenTypeRollup:
		return "ROLLUP"
	case TokenTypeCube:
		return "CUBE"
	case TokenTypeGrouping:
		return "GROUPING"
	case TokenTypeSets:
		return "SETS"
	case TokenTypeArray:
		return "ARRAY"
	case TokenTypeWithin:
		return "WITHIN"

	// Role/Permission Keywords
	case TokenTypeRole:
		return "ROLE"
	case TokenTypeUser:
		return "USER"
	case TokenTypeGrant:
		return "GRANT"
	case TokenTypeRevoke:
		return "REVOKE"
	case TokenTypePrivilege:
		return "PRIVILEGE"
	case TokenTypePassword:
		return "PASSWORD"
	case TokenTypeLogin:
		return "LOGIN"
	case TokenTypeSuperuser:
		return "SUPERUSER"
	case TokenTypeCreateDB:
		return "CREATEDB"
	case TokenTypeCreateRole:
		return "CREATEROLE"

	// Transaction Keywords
	case TokenTypeBegin:
		return "BEGIN"
	case TokenTypeCommit:
		return "COMMIT"
	case TokenTypeRollback:
		return "ROLLBACK"
	case TokenTypeSavepoint:
		return "SAVEPOINT"

	// Data Type Keywords
	case TokenTypeInt:
		return "INT"
	case TokenTypeInteger:
		return "INTEGER"
	case TokenTypeBigInt:
		return "BIGINT"
	case TokenTypeSmallInt:
		return "SMALLINT"
	case TokenTypeFloat:
		return "FLOAT"
	case TokenTypeDouble:
		return "DOUBLE"
	case TokenTypeDecimal:
		return "DECIMAL"
	case TokenTypeNumeric:
		return "NUMERIC"
	case TokenTypeVarchar:
		return "VARCHAR"
	case TokenTypeCharDataType:
		return "CHAR"
	case TokenTypeText:
		return "TEXT"
	case TokenTypeBoolean:
		return "BOOLEAN"
	case TokenTypeDate:
		return "DATE"
	case TokenTypeTime:
		return "TIME"
	case TokenTypeTimestamp:
		return "TIMESTAMP"
	case TokenTypeInterval:
		return "INTERVAL"
	case TokenTypeBlob:
		return "BLOB"
	case TokenTypeClob:
		return "CLOB"
	case TokenTypeJson:
		return "JSON"
	case TokenTypeUuid:
		return "UUID"

	// Special Token Types
	case TokenTypeIllegal:
		return "ILLEGAL"
	case TokenTypeAsterisk:
		return "*"
	case TokenTypeDoublePipe:
		return "||"

	default:
		return "TOKEN"
	}
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
