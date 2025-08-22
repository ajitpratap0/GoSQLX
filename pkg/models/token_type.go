package models

// TokenType represents the type of a SQL token
type TokenType int

// These constants define the token types used in the SQL tokenizer
const (
	// Basic token types
	TokenTypeEOF TokenType = iota
	TokenTypeWord
	TokenTypeNumber
	TokenTypeChar
	TokenTypeSingleQuotedString
	TokenTypeDoubleQuotedString
	TokenTypeTripleSingleQuotedString
	TokenTypeTripleDoubleQuotedString
	TokenTypeDollarQuotedString
	TokenTypeByteStringLiteral
	TokenTypeNationalStringLiteral
	TokenTypeEscapedStringLiteral
	TokenTypeUnicodeStringLiteral
	TokenTypeHexStringLiteral
	TokenTypeWhitespace

	// Operators and punctuation
	TokenTypeComma
	TokenTypeDoubleEq
	TokenTypeEq
	TokenTypeNeq
	TokenTypeLt
	TokenTypeGt
	TokenTypeLtEq
	TokenTypeGtEq
	TokenTypeSpaceship
	TokenTypePlus
	TokenTypeMinus
	TokenTypeMul
	TokenTypeDiv
	TokenTypeDuckIntDiv
	TokenTypeMod
	TokenTypeStringConcat
	TokenTypeLParen
	TokenTypeRParen
	TokenTypePeriod
	TokenTypeColon
	TokenTypeDoubleColon
	TokenTypeAssignment
	TokenTypeSemicolon
	TokenTypeBackslash
	TokenTypeLBracket
	TokenTypeRBracket
	TokenTypeAmpersand

	// Keywords
	TokenTypeKeyword
	TokenTypeSelect
	TokenTypeJoin
	TokenTypeInner
	TokenTypeLeft
	TokenTypeRight
	TokenTypeOuter
	TokenTypeGroup
	TokenTypeHaving
	TokenTypeWhere
	TokenTypeOrder
	TokenTypeLimit
	TokenTypeOffset
	TokenTypeOn
	TokenTypeAnd
	TokenTypeLike
	TokenTypeAsc
	TokenTypeFrom
	TokenTypeBy
	TokenTypeOr
	TokenTypeNot
	TokenTypeIn
	TokenTypeCount
	TokenTypeSum
	TokenTypeAvg
	TokenTypeMin
	TokenTypeMax
	TokenTypeBetween
	TokenTypeIs
	TokenTypeNull
	TokenTypeTrue
	TokenTypeFalse
	TokenTypeDesc
	TokenTypeCase
	TokenTypeWhen
	TokenTypeThen
	TokenTypeElse
	TokenTypeEnd
	TokenTypeAs
	TokenTypeGroupBy
	TokenTypeOrderBy
	TokenTypeLeftJoin
	TokenTypeRightJoin
	TokenTypeInnerJoin
	TokenTypeOuterJoin
	TokenTypePipe
	TokenTypeCaret
	TokenTypeLBrace
	TokenTypeRBrace
	TokenTypeRArrow
	TokenTypeSharp
	TokenTypeTilde
	TokenTypeTildeAsterisk
	TokenTypeExclamationMarkTilde
	TokenTypeExclamationMarkTildeAsterisk
	TokenTypeDoubleTilde
	TokenTypeDoubleTildeAsterisk
	TokenTypeExclamationMarkDoubleTilde
	TokenTypeExclamationMarkDoubleTildeAsterisk
	TokenTypeShiftLeft
	TokenTypeShiftRight
	TokenTypeOverlap
	TokenTypeExclamationMark
	TokenTypeDoubleExclamationMark
	TokenTypeAtSign
	TokenTypeCaretAt
	TokenTypePGSquareRoot
	TokenTypePGCubeRoot
	TokenTypePlaceholder
	TokenTypeArrow
	TokenTypeLongArrow
	TokenTypeHashArrow
	TokenTypeHashLongArrow
	TokenTypeAtArrow
	TokenTypeArrowAt
	TokenTypeHashMinus
	TokenTypeAtQuestion
	TokenTypeAtAt
	TokenTypeQuestion
	TokenTypeQuestionAnd
	TokenTypeQuestionPipe
	TokenTypeCustomBinaryOperator

	// Additional token types referenced in tests
	TokenTypeString
	TokenTypeIdentifier
	TokenTypeOperator
	TokenTypeLeftParen
	TokenTypeRightParen
	TokenTypeDot
)
