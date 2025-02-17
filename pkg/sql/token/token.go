package token

// Type represents a token type
type Type string

// Token represents a lexical token
type Token struct {
	Type    Type
	Literal string
}

// Token types
const (
	// Special tokens
	ILLEGAL = Type("ILLEGAL")
	EOF     = Type("EOF")
	WS      = Type("WS")

	// Identifiers and literals
	IDENT  = Type("IDENT")  // column, table_name
	INT    = Type("INT")    // 12345
	FLOAT  = Type("FLOAT")  // 123.45
	STRING = Type("STRING") // "abc", 'abc'

	// Operators
	EQ  = Type("=")
	NEQ = Type("!=")
	LT  = Type("<")
	LTE = Type("<=")
	GT  = Type(">")
	GTE = Type(">=")

	// Delimiters
	COMMA     = Type(",")
	SEMICOLON = Type(";")
	LPAREN    = Type("(")
	RPAREN    = Type(")")
	DOT       = Type(".")

	// Keywords
	SELECT = Type("SELECT")
	FROM   = Type("FROM")
	WHERE  = Type("WHERE")
	ORDER  = Type("ORDER")
	BY     = Type("BY")
	GROUP  = Type("GROUP")
	HAVING = Type("HAVING")
	LIMIT  = Type("LIMIT")
	OFFSET = Type("OFFSET")
	AS     = Type("AS")
	AND    = Type("AND")
	OR     = Type("OR")
	IN     = Type("IN")
	NOT    = Type("NOT")
	NULL   = Type("NULL")
)

// IsKeyword returns true if the token type is a keyword
func (t Type) IsKeyword() bool {
	switch t {
	case SELECT, FROM, WHERE, ORDER, BY, GROUP, HAVING, LIMIT, OFFSET, AS, AND, OR, IN, NOT, NULL:
		return true
	default:
		return false
	}
}

// IsOperator returns true if the token type is an operator
func (t Type) IsOperator() bool {
	switch t {
	case EQ, NEQ, LT, LTE, GT, GTE:
		return true
	default:
		return false
	}
}

// IsLiteral returns true if the token type is a literal
func (t Type) IsLiteral() bool {
	switch t {
	case IDENT, INT, FLOAT, STRING:
		return true
	default:
		return false
	}
}
