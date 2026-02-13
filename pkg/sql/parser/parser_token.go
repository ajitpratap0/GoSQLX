package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// parserToken is the parser's internal token representation.
// It uses models.TokenType (int) directly for O(1) type comparisons,
// eliminating the need for the string-based token.Type fallback path.
//
// This is the Phase 2 migration target for issue #215: the parser now
// works with models.TokenWithSpan directly via this slim internal type.
type parserToken struct {
	Type    models.TokenType // Int-based type for O(1) comparisons
	Literal string           // The literal text of the token
	Start   models.Location  // Start position in source (for error reporting)
	End     models.Location  // End position in source
}

// containsDecimalOrExponent checks if a number string is a float.
func containsDecimalOrExponentPT(s string) bool {
	for _, ch := range s {
		if ch == '.' || ch == 'e' || ch == 'E' {
			return true
		}
	}
	return false
}

// convertTokensToInternal converts tokenizer output (models.TokenWithSpan) directly
// to the parser's internal token representation, bypassing the legacy token.Token type.
//
// This handles:
//   - Compound token splitting (e.g., INNER JOIN → two tokens)
//   - Aggregate function normalization (COUNT/SUM/etc → Identifier)
//   - Asterisk normalization (Mul → Asterisk)
//   - Number token splitting (Number → Number or FloatLiteral)
//   - Keyword identification for identifiers
func convertTokensToInternal(tokens []models.TokenWithSpan) ([]parserToken, []TokenPosition) {
	result := make([]parserToken, 0, len(tokens)*2)
	positions := make([]TokenPosition, 0, len(tokens)*2)

	for originalIndex, t := range tokens {
		t := t // local copy

		pos := TokenPosition{
			OriginalIndex: originalIndex,
			Start:         t.Start,
			End:           t.End,
			SourceToken:   &t,
		}

		// Handle compound tokens that need splitting
		if expanded := expandCompoundToken(t); len(expanded) > 0 {
			for _, et := range expanded {
				result = append(result, et)
				positions = append(positions, pos)
			}
			continue
		}

		// Handle single token conversion
		pt := convertSingleTokenInternal(t)
		result = append(result, pt)
		positions = append(positions, pos)
	}

	return result, positions
}

// expandCompoundToken splits compound tokens into multiple parser tokens.
func expandCompoundToken(t models.TokenWithSpan) []parserToken {
	switch t.Token.Type {
	case models.TokenTypeInnerJoin:
		return []parserToken{
			{Type: models.TokenTypeInner, Literal: "INNER", Start: t.Start, End: t.End},
			{Type: models.TokenTypeJoin, Literal: "JOIN", Start: t.Start, End: t.End},
		}
	case models.TokenTypeLeftJoin:
		return []parserToken{
			{Type: models.TokenTypeLeft, Literal: "LEFT", Start: t.Start, End: t.End},
			{Type: models.TokenTypeJoin, Literal: "JOIN", Start: t.Start, End: t.End},
		}
	case models.TokenTypeRightJoin:
		return []parserToken{
			{Type: models.TokenTypeRight, Literal: "RIGHT", Start: t.Start, End: t.End},
			{Type: models.TokenTypeJoin, Literal: "JOIN", Start: t.Start, End: t.End},
		}
	case models.TokenTypeOuterJoin:
		return []parserToken{
			{Type: models.TokenTypeOuter, Literal: "OUTER", Start: t.Start, End: t.End},
			{Type: models.TokenTypeJoin, Literal: "JOIN", Start: t.Start, End: t.End},
		}
	case models.TokenTypeFullJoin:
		return []parserToken{
			{Type: models.TokenTypeFull, Literal: "FULL", Start: t.Start, End: t.End},
			{Type: models.TokenTypeJoin, Literal: "JOIN", Start: t.Start, End: t.End},
		}
	case models.TokenTypeCrossJoin:
		return []parserToken{
			{Type: models.TokenTypeCross, Literal: "CROSS", Start: t.Start, End: t.End},
			{Type: models.TokenTypeJoin, Literal: "JOIN", Start: t.Start, End: t.End},
		}
	case models.TokenTypeOrderBy:
		return []parserToken{
			{Type: models.TokenTypeOrder, Literal: "ORDER", Start: t.Start, End: t.End},
			{Type: models.TokenTypeBy, Literal: "BY", Start: t.Start, End: t.End},
		}
	case models.TokenTypeGroupBy:
		return []parserToken{
			{Type: models.TokenTypeGroup, Literal: "GROUP", Start: t.Start, End: t.End},
			{Type: models.TokenTypeBy, Literal: "BY", Start: t.Start, End: t.End},
		}
	case models.TokenTypeGroupingSets:
		return []parserToken{
			{Type: models.TokenTypeGrouping, Literal: "GROUPING", Start: t.Start, End: t.End},
			{Type: models.TokenTypeSets, Literal: "SETS", Start: t.Start, End: t.End},
		}
	}

	// Handle compound tokens from string values (fallback for tokenizer variants)
	switch t.Token.Value {
	case "INNER JOIN":
		return []parserToken{
			{Type: models.TokenTypeInner, Literal: "INNER", Start: t.Start, End: t.End},
			{Type: models.TokenTypeJoin, Literal: "JOIN", Start: t.Start, End: t.End},
		}
	case "LEFT JOIN":
		return []parserToken{
			{Type: models.TokenTypeLeft, Literal: "LEFT", Start: t.Start, End: t.End},
			{Type: models.TokenTypeJoin, Literal: "JOIN", Start: t.Start, End: t.End},
		}
	case "RIGHT JOIN":
		return []parserToken{
			{Type: models.TokenTypeRight, Literal: "RIGHT", Start: t.Start, End: t.End},
			{Type: models.TokenTypeJoin, Literal: "JOIN", Start: t.Start, End: t.End},
		}
	case "FULL JOIN":
		return []parserToken{
			{Type: models.TokenTypeFull, Literal: "FULL", Start: t.Start, End: t.End},
			{Type: models.TokenTypeJoin, Literal: "JOIN", Start: t.Start, End: t.End},
		}
	case "CROSS JOIN":
		return []parserToken{
			{Type: models.TokenTypeCross, Literal: "CROSS", Start: t.Start, End: t.End},
			{Type: models.TokenTypeJoin, Literal: "JOIN", Start: t.Start, End: t.End},
		}
	case "LEFT OUTER JOIN":
		return []parserToken{
			{Type: models.TokenTypeLeft, Literal: "LEFT", Start: t.Start, End: t.End},
			{Type: models.TokenTypeOuter, Literal: "OUTER", Start: t.Start, End: t.End},
			{Type: models.TokenTypeJoin, Literal: "JOIN", Start: t.Start, End: t.End},
		}
	case "RIGHT OUTER JOIN":
		return []parserToken{
			{Type: models.TokenTypeRight, Literal: "RIGHT", Start: t.Start, End: t.End},
			{Type: models.TokenTypeOuter, Literal: "OUTER", Start: t.Start, End: t.End},
			{Type: models.TokenTypeJoin, Literal: "JOIN", Start: t.Start, End: t.End},
		}
	case "FULL OUTER JOIN":
		return []parserToken{
			{Type: models.TokenTypeFull, Literal: "FULL", Start: t.Start, End: t.End},
			{Type: models.TokenTypeOuter, Literal: "OUTER", Start: t.Start, End: t.End},
			{Type: models.TokenTypeJoin, Literal: "JOIN", Start: t.Start, End: t.End},
		}
	case "ORDER BY":
		return []parserToken{
			{Type: models.TokenTypeOrder, Literal: "ORDER", Start: t.Start, End: t.End},
			{Type: models.TokenTypeBy, Literal: "BY", Start: t.Start, End: t.End},
		}
	case "GROUP BY":
		return []parserToken{
			{Type: models.TokenTypeGroup, Literal: "GROUP", Start: t.Start, End: t.End},
			{Type: models.TokenTypeBy, Literal: "BY", Start: t.Start, End: t.End},
		}
	case "GROUPING SETS":
		return []parserToken{
			{Type: models.TokenTypeGrouping, Literal: "GROUPING", Start: t.Start, End: t.End},
			{Type: models.TokenTypeSets, Literal: "SETS", Start: t.Start, End: t.End},
		}
	}

	return nil
}

// convertSingleTokenInternal converts a single tokenizer token to parser internal format.
func convertSingleTokenInternal(t models.TokenWithSpan) parserToken {
	pt := parserToken{
		Type:    t.Token.Type,
		Literal: t.Token.Value,
		Start:   t.Start,
		End:     t.End,
	}

	// Normalize asterisk: TokenTypeMul → TokenTypeAsterisk
	if t.Token.Type == models.TokenTypeMul {
		pt.Type = models.TokenTypeAsterisk
		return pt
	}

	// Normalize aggregate functions to identifiers
	switch t.Token.Type {
	case models.TokenTypeCount, models.TokenTypeSum, models.TokenTypeAvg,
		models.TokenTypeMin, models.TokenTypeMax:
		pt.Type = models.TokenTypeIdentifier
		return pt
	}

	// Split Number into Number (int) and FloatLiteral
	if t.Token.Type == models.TokenTypeNumber {
		if containsDecimalOrExponentPT(t.Token.Value) {
			pt.Type = models.TokenTypeFloatLiteral
		}
		return pt
	}

	// Handle identifiers that are actually keywords
	if t.Token.Type == models.TokenTypeIdentifier {
		if kwType := identifierToKeywordType(t.Token.Value); kwType != 0 {
			pt.Type = kwType
		}
		return pt
	}

	// Handle generic keywords
	if t.Token.Type == models.TokenTypeKeyword {
		if kwType := identifierToKeywordType(t.Token.Value); kwType != 0 {
			pt.Type = kwType
		}
		return pt
	}

	return pt
}

// identifierToKeywordType maps identifier/keyword values to their specific TokenType.
// This replaces the getKeywordTokenTypeWithModel function from the old token converter.
func identifierToKeywordType(value string) models.TokenType {
	// Fast uppercase conversion using ASCII optimization
	n := len(value)
	upper := make([]byte, n)
	for i := 0; i < n; i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' {
			upper[i] = c - 32
		} else {
			upper[i] = c
		}
	}

	switch string(upper) {
	// DML
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

	// DDL
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

	// CTE & Advanced
	case "WITH":
		return models.TokenTypeWith
	case "RECURSIVE":
		return models.TokenTypeRecursive
	case "MERGE":
		return models.TokenTypeMerge
	case "USING":
		return models.TokenTypeUsing
	case "MATCHED":
		return models.TokenTypeMatched
	case "REFRESH":
		return models.TokenTypeRefresh
	case "MATERIALIZED":
		return models.TokenTypeMaterialized
	case "CONCURRENTLY":
		return models.TokenTypeConcurrently
	case "TRUNCATE":
		return models.TokenTypeTruncate
	case "RESTART":
		return models.TokenTypeRestart
	case "CONTINUE":
		return models.TokenTypeContinue
	case "IDENTITY":
		return models.TokenTypeIdentity
	case "CASCADE":
		return models.TokenTypeCascade
	case "RESTRICT":
		return models.TokenTypeRestrict
	case "RETURNING":
		return models.TokenTypeReturning

	// SELECT-related
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
	case "AS":
		return models.TokenTypeAs
	case "ON":
		return models.TokenTypeOn
	case "IN":
		return models.TokenTypeIn
	case "IS":
		return models.TokenTypeIs
	case "NULL":
		return models.TokenTypeNull
	case "LIKE":
		return models.TokenTypeLike
	case "ILIKE":
		return models.TokenTypeILike
	case "BETWEEN":
		return models.TokenTypeBetween
	case "EXISTS":
		return models.TokenTypeExists
	case "HAVING":
		return models.TokenTypeHaving
	case "LIMIT":
		return models.TokenTypeLimit
	case "OFFSET":
		return models.TokenTypeOffset
	case "ORDER":
		return models.TokenTypeOrder
	case "GROUP":
		return models.TokenTypeGroup
	case "BY":
		return models.TokenTypeBy
	case "ASC":
		return models.TokenTypeAsc
	case "DESC":
		return models.TokenTypeDesc
	case "DISTINCT":
		return models.TokenTypeDistinct
	case "ALL":
		return models.TokenTypeAll
	case "ANY":
		return models.TokenTypeAny
	case "SOME":
		return models.TokenTypeSome
	case "UNION":
		return models.TokenTypeUnion
	case "EXCEPT":
		return models.TokenTypeExcept
	case "INTERSECT":
		return models.TokenTypeIntersect
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
	case "TRUE":
		return models.TokenTypeTrue
	case "FALSE":
		return models.TokenTypeFalse

	// JOIN
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
	case "CROSS":
		return models.TokenTypeCross
	case "NATURAL":
		return models.TokenTypeNatural
	case "LATERAL":
		return models.TokenTypeLateral

	// Window
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
	case "WINDOW":
		return models.TokenTypeWindow
	case "FILTER":
		return models.TokenTypeFilter

	// Grouping
	case "GROUPING":
		return models.TokenTypeGrouping
	case "SETS":
		return models.TokenTypeSets
	case "ROLLUP":
		return models.TokenTypeRollup
	case "CUBE":
		return models.TokenTypeCube

	// Constraints & DDL modifiers
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
	case "IF":
		return models.TokenTypeIf
	case "REPLACE":
		return models.TokenTypeReplace
	case "TEMPORARY", "TEMP":
		return models.TokenTypeKeyword
	case "TABLESPACE":
		return models.TokenTypeKeyword

	// FETCH/ROWS
	case "FETCH":
		return models.TokenTypeFetch
	case "FIRST":
		return models.TokenTypeFirst
	case "NEXT":
		return models.TokenTypeNext
	case "ONLY":
		return models.TokenTypeOnly
	case "TIES":
		return models.TokenTypeTies
	case "PERCENT":
		return models.TokenTypePercent

	// ALTER ROLE
	case "SUPERUSER":
		return models.TokenTypeSuperuser
	case "NOSUPERUSER":
		return models.TokenTypeNoSuperuser
	case "CREATEDB":
		return models.TokenTypeCreateDB
	case "NOCREATEDB":
		return models.TokenTypeNoCreateDB
	case "CREATEROLE":
		return models.TokenTypeCreateRole
	case "NOCREATEROLE":
		return models.TokenTypeNoCreateRole
	case "LOGIN":
		return models.TokenTypeLogin
	case "NOLOGIN":
		return models.TokenTypeNoLogin
	case "PASSWORD":
		return models.TokenTypePassword

	// Misc
	case "TO":
		return models.TokenTypeTo
	case "COLUMN":
		return models.TokenTypeColumn
	case "RENAME":
		return models.TokenTypeRename
	case "TYPE":
		return models.TokenTypeKeyword // Keep generic for non-reserved usage

	// NULLS FIRST/LAST
	case "NULLS":
		return models.TokenTypeNulls
	case "LAST":
		return models.TokenTypeLast

	// Window/Frame
	case "WITHIN":
		return models.TokenTypeWithin

	// Additional keywords used in expressions
	case "INTERVAL":
		return models.TokenTypeInterval
	}

	return 0
}
