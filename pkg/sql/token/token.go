package token

import "github.com/ajitpratap0/GoSQLX/pkg/models"

// Type represents a token type using string values.
// This is the legacy type system maintained for backward compatibility.
// For new code, prefer using models.TokenType (int-based) for better performance.
type Type string

// Token represents a lexical token in SQL source code.
//
// The Token struct supports a dual type system:
//   - Type: String-based type (backward compatibility, human-readable)
//   - ModelType: Integer-based type (primary, high-performance)
//   - Literal: The actual text value of the token
//
// The ModelType field should be used for type checking in performance-critical code,
// as integer comparisons are significantly faster than string comparisons.
//
// Example:
//
//	tok := Token{
//	    Type:      SELECT,
//	    ModelType: models.TokenTypeSelect,
//	    Literal:   "SELECT",
//	}
//
//	// Prefer fast integer comparison
//	if tok.IsType(models.TokenTypeSelect) {
//	    // Process SELECT token
//	}
type Token struct {
	Type      Type             // String-based type (backward compatibility)
	ModelType models.TokenType // Int-based type (primary, for performance)
	Literal   string           // The literal value of the token
}

// HasModelType returns true if the ModelType field is populated with a valid type.
// Returns false for TokenTypeUnknown or zero value.
//
// Example:
//
//	tok := Token{ModelType: models.TokenTypeSelect, Literal: "SELECT"}
//	if tok.HasModelType() {
//	    // Use fast ModelType-based operations
//	}
func (t Token) HasModelType() bool {
	return t.ModelType != models.TokenTypeUnknown && t.ModelType != 0
}

// IsType checks if the token matches the given models.TokenType.
// This uses fast integer comparison and is the preferred way to check token types.
//
// Example:
//
//	tok := Token{ModelType: models.TokenTypeSelect, Literal: "SELECT"}
//	if tok.IsType(models.TokenTypeSelect) {
//	    fmt.Println("This is a SELECT token")
//	}
func (t Token) IsType(expected models.TokenType) bool {
	return t.ModelType == expected
}

// IsAnyType checks if the token matches any of the given models.TokenType values.
// Returns true if the token's ModelType matches any type in the provided list.
//
// Example:
//
//	tok := Token{ModelType: models.TokenTypeSelect, Literal: "SELECT"}
//	dmlKeywords := []models.TokenType{
//	    models.TokenTypeSelect,
//	    models.TokenTypeInsert,
//	    models.TokenTypeUpdate,
//	    models.TokenTypeDelete,
//	}
//	if tok.IsAnyType(dmlKeywords...) {
//	    fmt.Println("This is a DML statement keyword")
//	}
func (t Token) IsAnyType(types ...models.TokenType) bool {
	for _, typ := range types {
		if t.ModelType == typ {
			return true
		}
	}
	return false
}

// Token type constants define string-based token types for backward compatibility.
// For new code, prefer using models.TokenType (integer-based) for better performance.
//
// These constants are organized into categories:
//   - Special tokens: ILLEGAL, EOF, WS
//   - Identifiers and literals: IDENT, INT, FLOAT, STRING, TRUE, FALSE
//   - Operators: EQ, NEQ, LT, LTE, GT, GTE, ASTERISK
//   - Delimiters: COMMA, SEMICOLON, LPAREN, RPAREN, DOT
//   - SQL keywords: SELECT, INSERT, UPDATE, DELETE, FROM, WHERE, etc.
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

// IsKeyword returns true if the token type is a SQL keyword.
// Checks against common SQL keywords like SELECT, INSERT, FROM, WHERE, etc.
//
// Example:
//
//	typ := SELECT
//	if typ.IsKeyword() {
//	    fmt.Println("This is a keyword token type")
//	}
func (t Type) IsKeyword() bool {
	switch t {
	case SELECT, INSERT, UPDATE, DELETE, FROM, WHERE, ORDER, BY, GROUP, HAVING, LIMIT, OFFSET, AS, AND, OR, IN, NOT, NULL, INTO, VALUES, TRUE, FALSE, SET, ALTER, TABLE:
		return true
	default:
		return false
	}
}

// IsOperator returns true if the token type is an operator.
// Checks for comparison and arithmetic operators.
//
// Example:
//
//	typ := EQ
//	if typ.IsOperator() {
//	    fmt.Println("This is an operator token type")
//	}
func (t Type) IsOperator() bool {
	switch t {
	case EQ, NEQ, LT, LTE, GT, GTE, ASTERISK:
		return true
	default:
		return false
	}
}

// IsLiteral returns true if the token type is a literal value.
// Checks for identifiers, numbers, strings, and boolean literals.
//
// Example:
//
//	typ := STRING
//	if typ.IsLiteral() {
//	    fmt.Println("This is a literal value token type")
//	}
func (t Type) IsLiteral() bool {
	switch t {
	case IDENT, INT, FLOAT, STRING, TRUE, FALSE:
		return true
	default:
		return false
	}
}

// stringToModelType maps string-based token types to models.TokenType for unified type system.
// This enables conversion between the legacy string-based Type and the modern int-based ModelType.
var stringToModelType = map[Type]models.TokenType{
	// Special tokens
	ILLEGAL:    models.TokenTypeIllegal,
	EOF:        models.TokenTypeEOF,
	WS:         models.TokenTypeWhitespace,
	IDENT:      models.TokenTypeIdentifier,
	INT:        models.TokenTypeNumber,
	FLOAT:      models.TokenTypeNumber,
	STRING:     models.TokenTypeString,
	TRUE:       models.TokenTypeTrue,
	FALSE:      models.TokenTypeFalse,
	EQ:         models.TokenTypeEq,
	NEQ:        models.TokenTypeNeq,
	LT:         models.TokenTypeLt,
	LTE:        models.TokenTypeLtEq,
	GT:         models.TokenTypeGt,
	GTE:        models.TokenTypeGtEq,
	ASTERISK:   models.TokenTypeAsterisk,
	COMMA:      models.TokenTypeComma,
	SEMICOLON:  models.TokenTypeSemicolon,
	LPAREN:     models.TokenTypeLParen,
	RPAREN:     models.TokenTypeRParen,
	DOT:        models.TokenTypePeriod,
	SELECT:     models.TokenTypeSelect,
	INSERT:     models.TokenTypeInsert,
	UPDATE:     models.TokenTypeUpdate,
	DELETE:     models.TokenTypeDelete,
	FROM:       models.TokenTypeFrom,
	WHERE:      models.TokenTypeWhere,
	ORDER:      models.TokenTypeOrder,
	BY:         models.TokenTypeBy,
	GROUP:      models.TokenTypeGroup,
	HAVING:     models.TokenTypeHaving,
	LIMIT:      models.TokenTypeLimit,
	OFFSET:     models.TokenTypeOffset,
	AS:         models.TokenTypeAs,
	AND:        models.TokenTypeAnd,
	OR:         models.TokenTypeOr,
	IN:         models.TokenTypeIn,
	NOT:        models.TokenTypeNot,
	NULL:       models.TokenTypeNull,
	ALL:        models.TokenTypeAll,
	ON:         models.TokenTypeOn,
	INTO:       models.TokenTypeInto,
	VALUES:     models.TokenTypeValues,
	ALTER:      models.TokenTypeAlter,
	TABLE:      models.TokenTypeTable,
	ROLE:       models.TokenTypeRole,
	ADD:        models.TokenTypeKeyword, // Generic keyword
	DROP:       models.TokenTypeDrop,
	COLUMN:     models.TokenTypeColumn,
	CONSTRAINT: models.TokenTypeConstraint,
	RENAME:     models.TokenTypeRename,
	TO:         models.TokenTypeTo,
	SET:        models.TokenTypeSet,
	USER:       models.TokenTypeUser,
	CASCADE:    models.TokenTypeCascade,
	WITH:       models.TokenTypeWith,
	CHECK:      models.TokenTypeCheck,
	USING:      models.TokenTypeUsing,
	PASSWORD:   models.TokenTypePassword,
	LOGIN:      models.TokenTypeLogin,
	SUPERUSER:  models.TokenTypeSuperuser,
	CREATEDB:   models.TokenTypeCreateDB,
	CREATEROLE: models.TokenTypeCreateRole,
}

// ToModelType converts a string-based Type to models.TokenType.
// Returns the corresponding integer-based token type, or models.TokenTypeKeyword
// for unknown types.
//
// Example:
//
//	typ := SELECT
//	modelType := typ.ToModelType()  // models.TokenTypeSelect
func (t Type) ToModelType() models.TokenType {
	if mt, ok := stringToModelType[t]; ok {
		return mt
	}
	// For unknown types, try to match by string value
	return models.TokenTypeKeyword // Default to generic keyword
}

// NewTokenWithModelType creates a token with both string and int types populated.
// This is the preferred way to create tokens as it ensures both type systems are
// properly initialized.
//
// Example:
//
//	tok := NewTokenWithModelType(SELECT, "SELECT")
//	// tok.Type = SELECT
//	// tok.ModelType = models.TokenTypeSelect
//	// tok.Literal = "SELECT"
func NewTokenWithModelType(typ Type, literal string) Token {
	return Token{
		Type:      typ,
		ModelType: typ.ToModelType(),
		Literal:   literal,
	}
}
