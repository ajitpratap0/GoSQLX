package models

import "testing"

// TestTokenType_String_AllCases covers all remaining String() cases
func TestTokenType_String_AllCases(t *testing.T) {
	tests := []struct {
		tt   TokenType
		want string
	}{
		// Basic tokens
		{TokenTypeChar, "CHAR"},
		{TokenTypeWhitespace, "WHITESPACE"},
		{TokenTypePlaceholder, "PLACEHOLDER"},

		// String literals
		{TokenTypeString, "STRING"},
		{TokenTypeTripleSingleQuotedString, "TRIPLE_SINGLE_QUOTED_STRING"},
		{TokenTypeTripleDoubleQuotedString, "TRIPLE_DOUBLE_QUOTED_STRING"},
		{TokenTypeDollarQuotedString, "DOLLAR_QUOTED_STRING"},
		{TokenTypeByteStringLiteral, "BYTE_STRING_LITERAL"},
		{TokenTypeNationalStringLiteral, "NATIONAL_STRING_LITERAL"},
		{TokenTypeEscapedStringLiteral, "ESCAPED_STRING_LITERAL"},
		{TokenTypeUnicodeStringLiteral, "UNICODE_STRING_LITERAL"},
		{TokenTypeHexStringLiteral, "HEX_STRING_LITERAL"},

		// Operators
		{TokenTypeOperator, "OPERATOR"},
		{TokenTypeDoubleEq, "DOUBLE_EQ"},
		{TokenTypeLtEq, "LT_EQ"},
		{TokenTypeGtEq, "GT_EQ"},
		{TokenTypeSpaceship, "SPACESHIP"},
		{TokenTypeDuckIntDiv, "DUCK_INT_DIV"},
		{TokenTypeMod, "MOD"},
		{TokenTypeStringConcat, "STRING_CONCAT"},
		{TokenTypePeriod, "PERIOD"},
		{TokenTypeColon, "COLON"},
		{TokenTypeDoubleColon, "DOUBLE_COLON"},
		{TokenTypeAssignment, "ASSIGNMENT"},
		{TokenTypeSemicolon, "SEMICOLON"},
		{TokenTypeBackslash, "BACKSLASH"},
		{TokenTypeLBracket, "LBRACKET"},
		{TokenTypeRBracket, "RBRACKET"},
		{TokenTypeAmpersand, "AMPERSAND"},
		{TokenTypePipe, "PIPE"},
		{TokenTypeCaret, "CARET"},
		{TokenTypeLBrace, "LBRACE"},
		{TokenTypeRBrace, "RBRACE"},
		{TokenTypeRArrow, "R_ARROW"},
		{TokenTypeSharp, "SHARP"},
		{TokenTypeTilde, "TILDE"},
		{TokenTypeExclamationMark, "EXCLAMATION_MARK"},
		{TokenTypeAtSign, "AT_SIGN"},
		{TokenTypeQuestion, "QUESTION"},

		// Compound operators
		{TokenTypeTildeAsterisk, "TILDE_ASTERISK"},
		{TokenTypeExclamationMarkTilde, "EXCLAMATION_MARK_TILDE"},
		{TokenTypeExclamationMarkTildeAsterisk, "EXCLAMATION_MARK_TILDE_ASTERISK"},
		{TokenTypeDoubleTilde, "DOUBLE_TILDE"},
		{TokenTypeDoubleTildeAsterisk, "DOUBLE_TILDE_ASTERISK"},
		{TokenTypeExclamationMarkDoubleTilde, "EXCLAMATION_MARK_DOUBLE_TILDE"},
		{TokenTypeExclamationMarkDoubleTildeAsterisk, "EXCLAMATION_MARK_DOUBLE_TILDE_ASTERISK"},
		{TokenTypeShiftLeft, "SHIFT_LEFT"},
		{TokenTypeShiftRight, "SHIFT_RIGHT"},
		{TokenTypeOverlap, "OVERLAP"},
		{TokenTypeDoubleExclamationMark, "DOUBLE_EXCLAMATION_MARK"},
		{TokenTypeCaretAt, "CARET_AT"},
		{TokenTypePGSquareRoot, "PG_SQUARE_ROOT"},
		{TokenTypePGCubeRoot, "PG_CUBE_ROOT"},
		{TokenTypeArrow, "ARROW"},
		{TokenTypeLongArrow, "LONG_ARROW"},
		{TokenTypeHashArrow, "HASH_ARROW"},
		{TokenTypeHashLongArrow, "HASH_LONG_ARROW"},
		{TokenTypeAtArrow, "AT_ARROW"},
		{TokenTypeArrowAt, "ARROW_AT"},
		{TokenTypeHashMinus, "HASH_MINUS"},
		{TokenTypeAtQuestion, "AT_QUESTION"},
		{TokenTypeAtAt, "AT_AT"},
		{TokenTypeQuestionAnd, "QUESTION_AND"},
		{TokenTypeQuestionPipe, "QUESTION_PIPE"},
		{TokenTypeCustomBinaryOperator, "CUSTOM_BINARY_OPERATOR"},

		// Keywords
		{TokenTypeKeyword, "KEYWORD"},
		{TokenTypeOn, "ON"},
		{TokenTypeAs, "AS"},
		{TokenTypeIn, "IN"},
		{TokenTypeLike, "LIKE"},
		{TokenTypeBetween, "BETWEEN"},
		{TokenTypeIs, "IS"},
		{TokenTypeNull, "NULL"},
		{TokenTypeTrue, "TRUE"},
		{TokenTypeFalse, "FALSE"},
		{TokenTypeCase, "CASE"},
		{TokenTypeWhen, "WHEN"},
		{TokenTypeThen, "THEN"},
		{TokenTypeElse, "ELSE"},
		{TokenTypeEnd, "END"},
		{TokenTypeAsc, "ASC"},
		{TokenTypeDesc, "DESC"},
		{TokenTypeLimit, "LIMIT"},
		{TokenTypeOffset, "OFFSET"},

		// DML
		{TokenTypeInsert, "INSERT"},
		{TokenTypeUpdate, "UPDATE"},
		{TokenTypeDelete, "DELETE"},
		{TokenTypeInto, "INTO"},
		{TokenTypeValues, "VALUES"},
		{TokenTypeSet, "SET"},

		// DDL
		{TokenTypeCreate, "CREATE"},
		{TokenTypeAlter, "ALTER"},
		{TokenTypeDrop, "DROP"},
		{TokenTypeTable, "TABLE"},
		{TokenTypeIndex, "INDEX"},
		{TokenTypeView, "VIEW"},
		{TokenTypeColumn, "COLUMN"},
		{TokenTypeDatabase, "DATABASE"},
		{TokenTypeSchema, "SCHEMA"},
		{TokenTypeTrigger, "TRIGGER"},

		// Compound keywords
		{TokenTypeGroupBy, "GROUP_BY"},
		{TokenTypeOrderBy, "ORDER_BY"},
		{TokenTypeLeftJoin, "LEFT_JOIN"},
		{TokenTypeRightJoin, "RIGHT_JOIN"},
		{TokenTypeInnerJoin, "INNER_JOIN"},
		{TokenTypeOuterJoin, "OUTER_JOIN"},
		{TokenTypeFullJoin, "FULL_JOIN"},
		{TokenTypeCrossJoin, "CROSS_JOIN"},

		// CTE and Set
		{TokenTypeWith, "WITH"},
		{TokenTypeRecursive, "RECURSIVE"},
		{TokenTypeUnion, "UNION"},
		{TokenTypeExcept, "EXCEPT"},
		{TokenTypeIntersect, "INTERSECT"},
		{TokenTypeAll, "ALL"},

		// Window
		{TokenTypeOver, "OVER"},
		{TokenTypePartition, "PARTITION"},
		{TokenTypeRows, "ROWS"},
		{TokenTypeRange, "RANGE"},
		{TokenTypeUnbounded, "UNBOUNDED"},
		{TokenTypePreceding, "PRECEDING"},
		{TokenTypeFollowing, "FOLLOWING"},
		{TokenTypeCurrent, "CURRENT"},
		{TokenTypeRow, "ROW"},
		{TokenTypeGroups, "GROUPS"},
		{TokenTypeFilter, "FILTER"},
		{TokenTypeExclude, "EXCLUDE"},

		// Additional Join
		{TokenTypeCross, "CROSS"},
		{TokenTypeNatural, "NATURAL"},
		{TokenTypeFull, "FULL"},
		{TokenTypeUsing, "USING"},
		{TokenTypeLateral, "LATERAL"},

		// Constraints
		{TokenTypePrimary, "PRIMARY"},
		{TokenTypeKey, "KEY"},
		{TokenTypeForeign, "FOREIGN"},
		{TokenTypeReferences, "REFERENCES"},
		{TokenTypeUnique, "UNIQUE"},
		{TokenTypeCheck, "CHECK"},
		{TokenTypeDefault, "DEFAULT"},
		{TokenTypeAutoIncrement, "AUTO_INCREMENT"},
		{TokenTypeConstraint, "CONSTRAINT"},
		{TokenTypeNotNull, "NOT_NULL"},
		{TokenTypeNullable, "NULLABLE"},

		// Additional SQL Keywords
		{TokenTypeDistinct, "DISTINCT"},
		{TokenTypeExists, "EXISTS"},
		{TokenTypeAny, "ANY"},
		{TokenTypeSome, "SOME"},
		{TokenTypeCast, "CAST"},
		{TokenTypeConvert, "CONVERT"},
		{TokenTypeCollate, "COLLATE"},
		{TokenTypeCascade, "CASCADE"},
		{TokenTypeRestrict, "RESTRICT"},
		{TokenTypeReplace, "REPLACE"},
		{TokenTypeRename, "RENAME"},
		{TokenTypeTo, "TO"},
		{TokenTypeIf, "IF"},
		{TokenTypeOnly, "ONLY"},
		{TokenTypeFor, "FOR"},
		{TokenTypeNulls, "NULLS"},
		{TokenTypeFirst, "FIRST"},
		{TokenTypeLast, "LAST"},
		{TokenTypeFetch, "FETCH"},
		{TokenTypeNext, "NEXT"},

		// MERGE
		{TokenTypeMerge, "MERGE"},
		{TokenTypeMatched, "MATCHED"},
		{TokenTypeTarget, "TARGET"},
		{TokenTypeSource, "SOURCE"},

		// Materialized View
		{TokenTypeMaterialized, "MATERIALIZED"},
		{TokenTypeRefresh, "REFRESH"},
		{TokenTypeTies, "TIES"},
		{TokenTypePercent, "PERCENT"},
		{TokenTypeTruncate, "TRUNCATE"},
		{TokenTypeReturning, "RETURNING"},

		// Row Locking
		{TokenTypeShare, "SHARE"},
		{TokenTypeNoWait, "NOWAIT"},
		{TokenTypeSkip, "SKIP"},
		{TokenTypeLocked, "LOCKED"},
		{TokenTypeOf, "OF"},

		// Grouping Sets
		{TokenTypeGroupingSets, "GROUPING_SETS"},
		{TokenTypeRollup, "ROLLUP"},
		{TokenTypeCube, "CUBE"},
		{TokenTypeGrouping, "GROUPING"},
		{TokenTypeSets, "SETS"},
		{TokenTypeArray, "ARRAY"},
		{TokenTypeWithin, "WITHIN"},

		// Role/Permission
		{TokenTypeRole, "ROLE"},
		{TokenTypeUser, "USER"},
		{TokenTypeGrant, "GRANT"},
		{TokenTypeRevoke, "REVOKE"},
		{TokenTypePrivilege, "PRIVILEGE"},
		{TokenTypePassword, "PASSWORD"},
		{TokenTypeLogin, "LOGIN"},
		{TokenTypeSuperuser, "SUPERUSER"},
		{TokenTypeCreateDB, "CREATEDB"},
		{TokenTypeCreateRole, "CREATEROLE"},

		// Transaction
		{TokenTypeBegin, "BEGIN"},
		{TokenTypeCommit, "COMMIT"},
		{TokenTypeRollback, "ROLLBACK"},
		{TokenTypeSavepoint, "SAVEPOINT"},

		// Data Types
		{TokenTypeInt, "INT"},
		{TokenTypeInteger, "INTEGER"},
		{TokenTypeBigInt, "BIGINT"},
		{TokenTypeSmallInt, "SMALLINT"},
		{TokenTypeFloat, "FLOAT"},
		{TokenTypeDouble, "DOUBLE"},
		{TokenTypeDecimal, "DECIMAL"},
		{TokenTypeNumeric, "NUMERIC"},
		{TokenTypeVarchar, "VARCHAR"},
		{TokenTypeCharDataType, "CHAR"},
		{TokenTypeText, "TEXT"},
		{TokenTypeBoolean, "BOOLEAN"},
		{TokenTypeDate, "DATE"},
		{TokenTypeTime, "TIME"},
		{TokenTypeTimestamp, "TIMESTAMP"},
		{TokenTypeInterval, "INTERVAL"},
		{TokenTypeBlob, "BLOB"},
		{TokenTypeClob, "CLOB"},
		{TokenTypeJson, "JSON"},
		{TokenTypeUuid, "UUID"},

		// Special
		{TokenTypeIllegal, "ILLEGAL"},
		{TokenTypeAsterisk, "*"},
		{TokenTypeDoublePipe, "||"},
		{TokenTypeILike, "TOKEN"}, // no specific case in String()
	}

	for _, tt := range tests {
		got := tt.tt.String()
		if got != tt.want {
			t.Errorf("TokenType(%d).String() = %q, want %q", tt.tt, got, tt.want)
		}
	}
}
