package models

import (
	"fmt"
	"testing"
)

func TestTokenTypeString_AllConstants(t *testing.T) {
	// Every defined constant should return a non-"TOKEN" string
	tests := []struct {
		tt   TokenType
		want string
	}{
		{TokenTypeEOF, "EOF"},
		{TokenTypeUnknown, "UNKNOWN"},
		{TokenTypeWord, "WORD"},
		{TokenTypeNumber, "NUMBER"},
		{TokenTypeChar, "CHAR"},
		{TokenTypeWhitespace, "WHITESPACE"},
		{TokenTypeIdentifier, "IDENTIFIER"},
		{TokenTypePlaceholder, "PLACEHOLDER"},
		{TokenTypeString, "STRING"},
		{TokenTypeSingleQuotedString, "STRING"},
		{TokenTypeDoubleQuotedString, "DOUBLE_QUOTED_STRING"},
		{TokenTypeDollarQuotedString, "DOLLAR_QUOTED_STRING"},
		{TokenTypeByteStringLiteral, "BYTE_STRING_LITERAL"},
		{TokenTypeNationalStringLiteral, "NATIONAL_STRING_LITERAL"},
		{TokenTypeEscapedStringLiteral, "ESCAPED_STRING_LITERAL"},
		{TokenTypeUnicodeStringLiteral, "UNICODE_STRING_LITERAL"},
		{TokenTypeHexStringLiteral, "HEX_STRING_LITERAL"},
		{TokenTypeComma, "COMMA"},
		{TokenTypeEq, "EQ"},
		{TokenTypeLParen, "LPAREN"},
		{TokenTypeRParen, "RPAREN"},
		{TokenTypeSemicolon, "SEMICOLON"},
		{TokenTypeSelect, "SELECT"},
		{TokenTypeFrom, "FROM"},
		{TokenTypeWhere, "WHERE"},
		{TokenTypeInsert, "INSERT"},
		{TokenTypeUpdate, "UPDATE"},
		{TokenTypeDelete, "DELETE"},
		{TokenTypeCreate, "CREATE"},
		{TokenTypeAlter, "ALTER"},
		{TokenTypeDrop, "DROP"},
		{TokenTypeTable, "TABLE"},
		{TokenTypeGroupBy, "GROUP_BY"},
		{TokenTypeOrderBy, "ORDER_BY"},
		{TokenTypeInnerJoin, "INNER_JOIN"},
		{TokenTypeLeftJoin, "LEFT_JOIN"},
		{TokenTypeWith, "WITH"},
		{TokenTypeUnion, "UNION"},
		{TokenTypeOver, "OVER"},
		{TokenTypePartition, "PARTITION"},
		{TokenTypePrimary, "PRIMARY"},
		{TokenTypeUnique, "UNIQUE"},
		{TokenTypeDistinct, "DISTINCT"},
		{TokenTypeCast, "CAST"},
		{TokenTypeMerge, "MERGE"},
		{TokenTypeMaterialized, "MATERIALIZED"},
		{TokenTypeTruncate, "TRUNCATE"},
		{TokenTypeReturning, "RETURNING"},
		{TokenTypeBegin, "BEGIN"},
		{TokenTypeCommit, "COMMIT"},
		{TokenTypeRollback, "ROLLBACK"},
		{TokenTypeInt, "INT"},
		{TokenTypeVarchar, "VARCHAR"},
		{TokenTypeBoolean, "BOOLEAN"},
		{TokenTypeTimestamp, "TIMESTAMP"},
		{TokenTypeIllegal, "ILLEGAL"},
		{TokenTypeAsterisk, "*"},
		{TokenTypeDoublePipe, "||"},
		// Previously missing from old map
		{TokenTypeShiftLeft, "SHIFT_LEFT"},
		{TokenTypeShiftRight, "SHIFT_RIGHT"},
		{TokenTypeOverlap, "OVERLAP"},
		{TokenTypeDoubleExclamationMark, "DOUBLE_EXCLAMATION_MARK"},
		{TokenTypeCaretAt, "CARET_AT"},
		{TokenTypePGSquareRoot, "PG_SQUARE_ROOT"},
		{TokenTypePGCubeRoot, "PG_CUBE_ROOT"},
		{TokenTypeCustomBinaryOperator, "CUSTOM_BINARY_OPERATOR"},
		{TokenTypeArrow, "ARROW"},
		{TokenTypeLongArrow, "LONG_ARROW"},
		{TokenTypeHashArrow, "HASH_ARROW"},
		{TokenTypeAtArrow, "AT_ARROW"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			got := tc.tt.String()
			if got != tc.want {
				t.Errorf("TokenType(%d).String() = %q, want %q", int(tc.tt), got, tc.want)
			}
		})
	}
}

func TestTokenTypeString_UnknownValue(t *testing.T) {
	unknown := TokenType(9999)
	if got := unknown.String(); got != "TOKEN" {
		t.Errorf("unknown TokenType.String() = %q, want %q", got, "TOKEN")
	}
}

func TestTokenTypeString_FmtStringer(t *testing.T) {
	// Verify it implements fmt.Stringer interface
	var _ fmt.Stringer = TokenType(0)
	s := TokenTypeSelect.String()
	if s != "SELECT" {
		t.Errorf("fmt.Sprintf with TokenTypeSelect = %q, want %q", s, "SELECT")
	}
}
