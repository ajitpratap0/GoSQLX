package tokenizer

import "github.com/ajitpratap0/GoSQLX/pkg/models"

// SQLOperator represents a SQL operator with its token type
type SQLOperator struct {
	Symbol string
	Type   models.TokenType
}

var (
	// SingleCharOperators contains single-character SQL operators
	SingleCharOperators = map[byte]models.TokenType{
		'+': models.TokenTypePlus,
		'-': models.TokenTypeMinus,
		'*': models.TokenTypeMul,
		'/': models.TokenTypeDiv,
		'%': models.TokenTypeMod,
		'=': models.TokenTypeEq,
		'<': models.TokenTypeLt,
		'>': models.TokenTypeGt,
		'|': models.TokenTypePipe,
		':': models.TokenTypeColon,
		'(': models.TokenTypeLParen,
		')': models.TokenTypeRParen,
		'[': models.TokenTypeLBracket,
		']': models.TokenTypeRBracket,
		'{': models.TokenTypeLBrace,
		'}': models.TokenTypeRBrace,
		',': models.TokenTypeComma,
		';': models.TokenTypeSemicolon,
		'.': models.TokenTypePeriod,
	}

	// MultiCharOperators contains multi-character SQL operators, sorted by length
	MultiCharOperators = []SQLOperator{
		// 2-character operators
		{Symbol: ">=", Type: models.TokenTypeGtEq},
		{Symbol: "<=", Type: models.TokenTypeLtEq},
		{Symbol: "<>", Type: models.TokenTypeNeq},
		{Symbol: "!=", Type: models.TokenTypeNeq},
		{Symbol: "||", Type: models.TokenTypeStringConcat},
		{Symbol: "::", Type: models.TokenTypeDoubleColon},
		{Symbol: "->", Type: models.TokenTypeArrow},
		{Symbol: "=>", Type: models.TokenTypeLongArrow},
		{Symbol: "~~", Type: models.TokenTypeDoubleTilde},
		{Symbol: "!~", Type: models.TokenTypeExclamationMarkTilde},
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
