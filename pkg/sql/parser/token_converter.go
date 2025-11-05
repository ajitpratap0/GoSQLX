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
func (tc *TokenConverter) handleCompoundToken(t models.TokenWithSpan) []token.Token {
	// Handle typed compound tokens first (most specific)
	switch t.Token.Type {
	case models.TokenTypeInnerJoin:
		return []token.Token{
			{Type: "INNER", Literal: "INNER"},
			{Type: "JOIN", Literal: "JOIN"},
		}
	case models.TokenTypeLeftJoin:
		return []token.Token{
			{Type: "LEFT", Literal: "LEFT"},
			{Type: "JOIN", Literal: "JOIN"},
		}
	case models.TokenTypeRightJoin:
		return []token.Token{
			{Type: "RIGHT", Literal: "RIGHT"},
			{Type: "JOIN", Literal: "JOIN"},
		}
	case models.TokenTypeOuterJoin:
		return []token.Token{
			{Type: "OUTER", Literal: "OUTER"},
			{Type: "JOIN", Literal: "JOIN"},
		}
	case models.TokenTypeOrderBy:
		return []token.Token{
			{Type: "ORDER", Literal: "ORDER"},
			{Type: "BY", Literal: "BY"},
		}
	case models.TokenTypeGroupBy:
		return []token.Token{
			{Type: "GROUP", Literal: "GROUP"},
			{Type: "BY", Literal: "BY"},
		}
	}

	// Handle compound tokens that come as string values (fallback)
	switch t.Token.Value {
	case "INNER JOIN":
		return []token.Token{
			{Type: "INNER", Literal: "INNER"},
			{Type: "JOIN", Literal: "JOIN"},
		}
	case "LEFT JOIN":
		return []token.Token{
			{Type: "LEFT", Literal: "LEFT"},
			{Type: "JOIN", Literal: "JOIN"},
		}
	case "RIGHT JOIN":
		return []token.Token{
			{Type: "RIGHT", Literal: "RIGHT"},
			{Type: "JOIN", Literal: "JOIN"},
		}
	case "FULL JOIN":
		return []token.Token{
			{Type: "FULL", Literal: "FULL"},
			{Type: "JOIN", Literal: "JOIN"},
		}
	case "CROSS JOIN":
		return []token.Token{
			{Type: "CROSS", Literal: "CROSS"},
			{Type: "JOIN", Literal: "JOIN"},
		}
	case "LEFT OUTER JOIN":
		return []token.Token{
			{Type: "LEFT", Literal: "LEFT"},
			{Type: "OUTER", Literal: "OUTER"},
			{Type: "JOIN", Literal: "JOIN"},
		}
	case "RIGHT OUTER JOIN":
		return []token.Token{
			{Type: "RIGHT", Literal: "RIGHT"},
			{Type: "OUTER", Literal: "OUTER"},
			{Type: "JOIN", Literal: "JOIN"},
		}
	case "FULL OUTER JOIN":
		return []token.Token{
			{Type: "FULL", Literal: "FULL"},
			{Type: "OUTER", Literal: "OUTER"},
			{Type: "JOIN", Literal: "JOIN"},
		}
	case "ORDER BY":
		return []token.Token{
			{Type: "ORDER", Literal: "ORDER"},
			{Type: "BY", Literal: "BY"},
		}
	case "GROUP BY":
		return []token.Token{
			{Type: "GROUP", Literal: "GROUP"},
			{Type: "BY", Literal: "BY"},
		}
	}

	// Not a compound token
	return nil
}

// convertSingleToken converts a single token using the type mapping
func (tc *TokenConverter) convertSingleToken(t models.TokenWithSpan) (token.Token, error) {
	// Handle NUMBER tokens - convert to INT or FLOAT based on value
	if t.Token.Type == models.TokenTypeNumber {
		// Check if it's a float (contains decimal point or exponent)
		if containsDecimalOrExponent(t.Token.Value) {
			return token.Token{
				Type:    "FLOAT",
				Literal: t.Token.Value,
			}, nil
		}
		return token.Token{
			Type:    "INT",
			Literal: t.Token.Value,
		}, nil
	}

	// Handle IDENTIFIER tokens that might be keywords
	if t.Token.Type == models.TokenTypeIdentifier {
		// Check if this identifier is actually a SQL keyword that the parser expects
		if keywordType := getKeywordTokenType(t.Token.Value); keywordType != "" {
			return token.Token{
				Type:    keywordType,
				Literal: t.Token.Value,
			}, nil
		}
		// Regular identifier
		return token.Token{
			Type:    "IDENT",
			Literal: t.Token.Value,
		}, nil
	}

	// Handle generic KEYWORD tokens - convert based on value
	if t.Token.Type == models.TokenTypeKeyword {
		// Check if this keyword has a specific token type
		if keywordType := getKeywordTokenType(t.Token.Value); keywordType != "" {
			return token.Token{
				Type:    keywordType,
				Literal: t.Token.Value,
			}, nil
		}
		// Use the keyword value as the type
		return token.Token{
			Type:    token.Type(t.Token.Value),
			Literal: t.Token.Value,
		}, nil
	}

	// Try mapped type first (most efficient)
	if mappedType, exists := tc.typeMap[t.Token.Type]; exists {
		return token.Token{
			Type:    mappedType,
			Literal: t.Token.Value,
		}, nil
	}

	// Fallback to string conversion for unmapped types
	tokenType := token.Type(fmt.Sprintf("%v", t.Token.Type))

	return token.Token{
		Type:    tokenType,
		Literal: t.Token.Value,
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

// getKeywordTokenType returns the parser token type for SQL keywords that come as IDENTIFIER
// This handles keywords that the tokenizer doesn't recognize as specific token types
func getKeywordTokenType(value string) token.Type {
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
		return "INSERT"
	case "UPDATE":
		return "UPDATE"
	case "DELETE":
		return "DELETE"
	case "INTO":
		return "INTO"
	case "VALUES":
		return "VALUES"
	case "SET":
		return "SET"

	// DDL statements
	case "CREATE":
		return "CREATE"
	case "ALTER":
		return "ALTER"
	case "DROP":
		return "DROP"
	case "TABLE":
		return "TABLE"
	case "INDEX":
		return "INDEX"
	case "VIEW":
		return "VIEW"

	// CTE and advanced features
	case "WITH":
		return "WITH"
	case "RECURSIVE":
		return "RECURSIVE"

	// Set operations
	case "UNION":
		return "UNION"
	case "EXCEPT":
		return "EXCEPT"
	case "INTERSECT":
		return "INTERSECT"
	case "ALL":
		return "ALL"

	// Data types and constraints
	case "PRIMARY":
		return "PRIMARY"
	case "KEY":
		return "KEY"
	case "FOREIGN":
		return "FOREIGN"
	case "REFERENCES":
		return "REFERENCES"
	case "UNIQUE":
		return "UNIQUE"
	case "CHECK":
		return "CHECK"
	case "DEFAULT":
		return "DEFAULT"
	case "CONSTRAINT":
		return "CONSTRAINT"

	// Column attributes
	case "AUTO_INCREMENT":
		return "AUTO_INCREMENT"
	case "AUTOINCREMENT":
		return "AUTOINCREMENT"

	// Window function keywords
	case "OVER":
		return "OVER"
	case "PARTITION":
		return "PARTITION"
	case "ROWS":
		return "ROWS"
	case "RANGE":
		return "RANGE"
	case "UNBOUNDED":
		return "UNBOUNDED"
	case "PRECEDING":
		return "PRECEDING"
	case "FOLLOWING":
		return "FOLLOWING"
	case "CURRENT":
		return "CURRENT"
	case "ROW":
		return "ROW"

	// Join types (some might come as IDENTIFIER)
	case "CROSS":
		return "CROSS"
	case "NATURAL":
		return "NATURAL"
	case "USING":
		return "USING"

	// Other common keywords
	case "DISTINCT":
		return "DISTINCT"
	case "EXISTS":
		return "EXISTS"
	case "ANY":
		return "ANY"
	case "SOME":
		return "SOME"

	default:
		// Not a recognized keyword, will be treated as identifier
		return ""
	}
}

// buildTypeMapping creates an optimized lookup table for token type conversion
// Only includes token types that actually exist in models.TokenType
func buildTypeMapping() map[models.TokenType]token.Type {
	return map[models.TokenType]token.Type{
		// SQL Keywords (verified to exist in models)
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
