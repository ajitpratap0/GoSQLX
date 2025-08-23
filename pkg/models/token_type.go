package models

// TokenType represents the type of a SQL token
type TokenType int

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
	TokenTypeArrow                              TokenType = 114
	TokenTypeLongArrow                          TokenType = 115
	TokenTypeHashArrow                          TokenType = 116
	TokenTypeHashLongArrow                      TokenType = 117
	TokenTypeAtArrow                            TokenType = 118
	TokenTypeArrowAt                            TokenType = 119
	TokenTypeHashMinus                          TokenType = 120
	TokenTypeAtQuestion                         TokenType = 121
	TokenTypeAtAt                               TokenType = 122
	TokenTypeQuestionAnd                        TokenType = 123
	TokenTypeQuestionPipe                       TokenType = 124
	TokenTypeCustomBinaryOperator               TokenType = 125

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

	// Aggregate functions (250-269)
	TokenTypeCount TokenType = 250
	TokenTypeSum   TokenType = 251
	TokenTypeAvg   TokenType = 252
	TokenTypeMin   TokenType = 253
	TokenTypeMax   TokenType = 254

	// Compound keywords (270-299)
	TokenTypeGroupBy   TokenType = 270
	TokenTypeOrderBy   TokenType = 271
	TokenTypeLeftJoin  TokenType = 272
	TokenTypeRightJoin TokenType = 273
	TokenTypeInnerJoin TokenType = 274
	TokenTypeOuterJoin TokenType = 275
)

// String returns a string representation of the token type
func (t TokenType) String() string {
	switch t {
	case TokenTypeEOF:
		return "EOF"
	case TokenTypeUnknown:
		return "UNKNOWN"
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
	case TokenTypeString, TokenTypeSingleQuotedString:
		return "STRING"
	case TokenTypeDoubleQuotedString:
		return "DOUBLE_QUOTED_STRING"
	case TokenTypeOperator:
		return "OPERATOR"
	case TokenTypeComma:
		return "COMMA"
	case TokenTypeEq:
		return "EQ"
	case TokenTypeLParen:
		return "LPAREN"
	case TokenTypeRParen:
		return "RPAREN"
	case TokenTypePeriod:
		return "PERIOD"
	case TokenTypeSemicolon:
		return "SEMICOLON"
	case TokenTypeKeyword:
		return "KEYWORD"
	case TokenTypeSelect:
		return "SELECT"
	case TokenTypeFrom:
		return "FROM"
	case TokenTypeWhere:
		return "WHERE"
	case TokenTypeAnd:
		return "AND"
	case TokenTypeOr:
		return "OR"
	default:
		return "TOKEN"
	}
}
