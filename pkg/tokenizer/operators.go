package tokenizer

import "GoSQLX/pkg/models"

// SQLOperator represents a SQL operator with its token type
type SQLOperator struct {
	Symbol string
	Type   models.TokenType
}

var (
	// SingleCharOperators contains single-character SQL operators
	SingleCharOperators = map[byte]models.TokenType{
		'+': models.TokenTypeOperator,
		'-': models.TokenTypeOperator,
		'*': models.TokenTypeOperator,
		'/': models.TokenTypeOperator,
		'%': models.TokenTypeOperator,
		'=': models.TokenTypeEquals,
		'<': models.TokenTypeLessThan,
		'>': models.TokenTypeGreaterThan,
		'|': models.TokenTypeOperator,
		':': models.TokenTypeColon,
		'(': models.TokenTypeLeftParen,
		')': models.TokenTypeRightParen,
		'[': models.TokenTypeLeftBracket,
		']': models.TokenTypeRightBracket,
		'{': models.TokenTypeLeftBrace,
		'}': models.TokenTypeRightBrace,
		',': models.TokenTypeComma,
		';': models.TokenTypeSemicolon,
		'.': models.TokenTypeDot,
	}

	// MultiCharOperators contains multi-character SQL operators, sorted by length
	MultiCharOperators = []SQLOperator{
		// 2-character operators
		{Symbol: ">=", Type: models.TokenTypeGreaterEquals},
		{Symbol: "<=", Type: models.TokenTypeLessEquals},
		{Symbol: "<>", Type: models.TokenTypeNotEquals},
		{Symbol: "!=", Type: models.TokenTypeNotEquals},
		{Symbol: "||", Type: models.TokenTypeConcat},
		{Symbol: "::", Type: models.TokenTypeCast},
		{Symbol: "->", Type: models.TokenTypeArrow},
		{Symbol: "=>", Type: models.TokenTypeDoubleArrow},
		{Symbol: "~~", Type: models.TokenTypeOperator},
		{Symbol: "!~", Type: models.TokenTypeOperator},
	}
)

// isOperatorStart checks if a byte could be the start of an operator
func isOperatorStart(ch byte) bool {
	switch ch {
	case '+', '-', '*', '/', '%', '=', '<', '>', '!', '|', '&', '^', '~', '?', ':', '.', ',', ';', '(', ')', '[', ']', '{', '}':
		return true
	default:
		return false
	}
}

// matchMultiCharOperator tries to match a multi-character operator at the current position
func matchMultiCharOperator(input []byte, pos int) (SQLOperator, bool) {
	// Try to match each operator, starting with the longest ones first
	for _, op := range MultiCharOperators {
		if len(input) >= len(op.Symbol) {
			candidate := string(input[:len(op.Symbol)])
			if candidate == op.Symbol {
				// For operators like ->>, we need to handle them as separate tokens
				if op.Symbol == "->" && len(input) > 2 && input[2] == '>' {
					continue
				}
				if op.Symbol == "=>" && len(input) > 2 && input[2] == '>' {
					continue
				}
				return op, true
			}
		}
	}
	return SQLOperator{}, false
}
