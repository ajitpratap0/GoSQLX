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

		// Aggregate functions
		models.TokenTypeCount: "COUNT",
		models.TokenTypeSum:   "SUM",
		models.TokenTypeAvg:   "AVG",
		models.TokenTypeMin:   "MIN",
		models.TokenTypeMax:   "MAX",

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
