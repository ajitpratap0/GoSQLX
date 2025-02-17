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
	TRUE   = Type("TRUE")   // TRUE
	FALSE  = Type("FALSE")  // FALSE

	// Operators
	EQ       = Type("=")
	NEQ      = Type("!=")
	NOT_EQ   = Type("!=") // Alias for NEQ
	LT       = Type("<")
	LTE      = Type("<=")
	GT       = Type(">")
	GTE      = Type(">=")
	ASTERISK = Type("*")

	// Delimiters
	COMMA     = Type(",")
	SEMICOLON = Type(";")
	LPAREN    = Type("(")
	RPAREN    = Type(")")
	DOT       = Type(".")

	// Keywords
	SELECT = Type("SELECT")
	INSERT = Type("INSERT")
	UPDATE = Type("UPDATE")
	DELETE = Type("DELETE")
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
	ALL    = Type("ALL")
	ON     = Type("ON")
	INTO   = Type("INTO")
	VALUES = Type("VALUES")

	// Role keywords
	SUPERUSER    = Type("SUPERUSER")
	NOSUPERUSER  = Type("NOSUPERUSER")
	CREATEDB     = Type("CREATEDB")
	NOCREATEDB   = Type("NOCREATEDB")
	CREATEROLE   = Type("CREATEROLE")
	NOCREATEROLE = Type("NOCREATEROLE")
	LOGIN        = Type("LOGIN")
	NOLOGIN      = Type("NOLOGIN")

	// ALTER statement keywords
	ALTER        = Type("ALTER")
	TABLE        = Type("TABLE")
	ROLE         = Type("ROLE")
	POLICY       = Type("POLICY")
	CONNECTOR    = Type("CONNECTOR")
	ADD          = Type("ADD")
	DROP         = Type("DROP")
	COLUMN       = Type("COLUMN")
	CONSTRAINT   = Type("CONSTRAINT")
	RENAME       = Type("RENAME")
	TO           = Type("TO")
	SET          = Type("SET")
	RESET        = Type("RESET")
	MEMBER       = Type("MEMBER")
	OWNER        = Type("OWNER")
	USER         = Type("USER")
	URL          = Type("URL")
	DCPROPERTIES = Type("DCPROPERTIES")
	CASCADE      = Type("CASCADE")
	WITH         = Type("WITH")
	CHECK        = Type("CHECK")
	USING        = Type("USING")
	UNTIL        = Type("UNTIL")
	VALID        = Type("VALID")
	PASSWORD     = Type("PASSWORD")
	EQUAL        = Type("=")
)

// IsKeyword returns true if the token type is a keyword
func (t Type) IsKeyword() bool {
	switch t {
	case SELECT, INSERT, UPDATE, DELETE, FROM, WHERE, ORDER, BY, GROUP, HAVING, LIMIT, OFFSET, AS, AND, OR, IN, NOT, NULL, INTO, VALUES, TRUE, FALSE, SET, ALTER, TABLE:
		return true
	default:
		return false
	}
}

// IsOperator returns true if the token type is an operator
func (t Type) IsOperator() bool {
	switch t {
	case EQ, NEQ, LT, LTE, GT, GTE, ASTERISK:
		return true
	default:
		return false
	}
}

// IsLiteral returns true if the token type is a literal
func (t Type) IsLiteral() bool {
	switch t {
	case IDENT, INT, FLOAT, STRING, TRUE, FALSE:
		return true
	default:
		return false
	}
}
