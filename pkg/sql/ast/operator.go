package ast

import (
	"fmt"
	"strings"
)

// UnaryOperator represents unary operators in SQL expressions
type UnaryOperator int

const (
	// Plus represents unary plus operator, e.g. +9
	Plus UnaryOperator = iota
	// Minus represents unary minus operator, e.g. -9
	Minus
	// Not represents logical NOT operator, e.g. NOT(true)
	Not
	// PGBitwiseNot represents PostgreSQL bitwise NOT operator, e.g. ~9
	PGBitwiseNot
	// PGSquareRoot represents PostgreSQL square root operator, e.g. |/9
	PGSquareRoot
	// PGCubeRoot represents PostgreSQL cube root operator, e.g. ||/27
	PGCubeRoot
	// PGPostfixFactorial represents PostgreSQL postfix factorial operator, e.g. 9!
	PGPostfixFactorial
	// PGPrefixFactorial represents PostgreSQL prefix factorial operator, e.g. !!9
	PGPrefixFactorial
	// PGAbs represents PostgreSQL absolute value operator, e.g. @ -9
	PGAbs
	// BangNot represents Hive-specific logical NOT operator, e.g. ! false
	BangNot
)

// String returns the string representation of the unary operator
func (op UnaryOperator) String() string {
	switch op {
	case Plus:
		return "+"
	case Minus:
		return "-"
	case Not:
		return "NOT"
	case PGBitwiseNot:
		return "~"
	case PGSquareRoot:
		return "|/"
	case PGCubeRoot:
		return "||/"
	case PGPostfixFactorial:
		return "!"
	case PGPrefixFactorial:
		return "!!"
	case PGAbs:
		return "@"
	case BangNot:
		return "!"
	default:
		return "UNKNOWN"
	}
}

// BinaryOperator represents binary operators in SQL expressions
type BinaryOperator int

const (
	// BinaryOpNone represents no operator (zero value)
	BinaryOpNone BinaryOperator = iota
	// BinaryPlus represents addition operator, e.g. a + b
	BinaryPlus
	// BinaryMinus represents subtraction operator, e.g. a - b
	BinaryMinus
	// Multiply represents multiplication operator, e.g. a * b
	Multiply
	// Divide represents division operator, e.g. a / b
	Divide
	// Modulo represents modulo operator, e.g. a % b
	Modulo
	// StringConcat represents string/array concatenation operator, e.g. a || b
	StringConcat
	// Gt represents greater than operator, e.g. a > b
	Gt
	// Lt represents less than operator, e.g. a < b
	Lt
	// GtEq represents greater than or equal operator, e.g. a >= b
	GtEq
	// LtEq represents less than or equal operator, e.g. a <= b
	LtEq
	// Spaceship represents spaceship operator, e.g. a <=> b
	Spaceship
	// Eq represents equality operator, e.g. a = b
	Eq
	// NotEq represents inequality operator, e.g. a <> b
	NotEq
	// And represents logical AND operator, e.g. a AND b
	And
	// Or represents logical OR operator, e.g. a OR b
	Or
	// Xor represents logical XOR operator, e.g. a XOR b
	Xor
	// BitwiseOr represents bitwise OR operator, e.g. a | b
	BitwiseOr
	// BitwiseAnd represents bitwise AND operator, e.g. a & b
	BitwiseAnd
	// BitwiseXor represents bitwise XOR operator, e.g. a ^ b
	BitwiseXor
	// DuckIntegerDivide represents DuckDB integer division operator, e.g. a // b
	DuckIntegerDivide
	// MyIntegerDivide represents MySQL DIV integer division operator
	MyIntegerDivide
	// PGBitwiseXor represents PostgreSQL bitwise XOR operator, e.g. a # b
	PGBitwiseXor
	// PGBitwiseShiftLeft represents PostgreSQL bitwise shift left operator, e.g. a << b
	PGBitwiseShiftLeft
	// PGBitwiseShiftRight represents PostgreSQL bitwise shift right operator, e.g. a >> b
	PGBitwiseShiftRight
	// PGExp represents PostgreSQL exponentiation operator, e.g. a ^ b
	PGExp
	// PGOverlap represents PostgreSQL overlap operator, e.g. a && b
	PGOverlap
	// PGRegexMatch represents PostgreSQL case-sensitive regex match operator, e.g. a ~ b
	PGRegexMatch
	// PGRegexIMatch represents PostgreSQL case-insensitive regex match operator, e.g. a ~* b
	PGRegexIMatch
	// PGRegexNotMatch represents PostgreSQL case-sensitive regex non-match operator, e.g. a !~ b
	PGRegexNotMatch
	// PGRegexNotIMatch represents PostgreSQL case-insensitive regex non-match operator, e.g. a !~* b
	PGRegexNotIMatch
	// PGLikeMatch represents PostgreSQL case-sensitive LIKE match operator, e.g. a ~~ b
	PGLikeMatch
	// PGILikeMatch represents PostgreSQL case-insensitive LIKE match operator, e.g. a ~~* b
	PGILikeMatch
	// PGNotLikeMatch represents PostgreSQL case-sensitive NOT LIKE match operator, e.g. a !~~ b
	PGNotLikeMatch
	// PGNotILikeMatch represents PostgreSQL case-insensitive NOT LIKE match operator, e.g. a !~~* b
	PGNotILikeMatch
	// PGStartsWith represents PostgreSQL starts-with operator, e.g. a ^@ b
	PGStartsWith
	// Arrow represents JSON field/array element access operator, e.g. a -> b
	Arrow
	// LongArrow represents JSON field/array element access with text conversion operator, e.g. a ->> b
	LongArrow
	// HashArrow represents JSON path access operator, e.g. a #> b
	HashArrow
	// HashLongArrow represents JSON path access with text conversion operator, e.g. a #>> b
	HashLongArrow
	// AtAt represents PostgreSQL text/JSON search operator, e.g. a @@ b
	AtAt
	// AtArrow represents PostgreSQL contains operator, e.g. a @> b
	AtArrow
	// ArrowAt represents PostgreSQL contained by operator, e.g. a <@ b
	ArrowAt
	// HashMinus represents PostgreSQL JSON delete operator, e.g. a #- b
	HashMinus
	// AtQuestion represents PostgreSQL JSON path exists operator, e.g. a @? b
	AtQuestion
	// Question represents PostgreSQL JSON key exists operator, e.g. a ? b
	Question
	// QuestionAnd represents PostgreSQL JSON all keys exist operator, e.g. a ?& b
	QuestionAnd
	// QuestionPipe represents PostgreSQL JSON any key exists operator, e.g. a ?| b
	QuestionPipe
	// Overlaps represents SQL OVERLAPS operator for datetime periods
	Overlaps
)

// String returns the string representation of the binary operator
func (op BinaryOperator) String() string {
	switch op {
	case BinaryPlus:
		return "+"
	case BinaryMinus:
		return "-"
	case Multiply:
		return "*"
	case Divide:
		return "/"
	case Modulo:
		return "%"
	case StringConcat:
		return "||"
	case Gt:
		return ">"
	case Lt:
		return "<"
	case GtEq:
		return ">="
	case LtEq:
		return "<="
	case Spaceship:
		return "<=>"
	case Eq:
		return "="
	case NotEq:
		return "<>"
	case And:
		return "AND"
	case Or:
		return "OR"
	case Xor:
		return "XOR"
	case BitwiseOr:
		return "|"
	case BitwiseAnd:
		return "&"
	case BitwiseXor:
		return "^"
	case DuckIntegerDivide:
		return "//"
	case MyIntegerDivide:
		return "DIV"
	case PGBitwiseXor:
		return "#"
	case PGBitwiseShiftLeft:
		return "<<"
	case PGBitwiseShiftRight:
		return ">>"
	case PGExp:
		return "^"
	case PGOverlap:
		return "&&"
	case PGRegexMatch:
		return "~"
	case PGRegexIMatch:
		return "~*"
	case PGRegexNotMatch:
		return "!~"
	case PGRegexNotIMatch:
		return "!~*"
	case PGLikeMatch:
		return "~~"
	case PGILikeMatch:
		return "~~*"
	case PGNotLikeMatch:
		return "!~~"
	case PGNotILikeMatch:
		return "!~~*"
	case PGStartsWith:
		return "^@"
	case Arrow:
		return "->"
	case LongArrow:
		return "->>"
	case HashArrow:
		return "#>"
	case HashLongArrow:
		return "#>>"
	case AtAt:
		return "@@"
	case AtArrow:
		return "@>"
	case ArrowAt:
		return "<@"
	case HashMinus:
		return "#-"
	case AtQuestion:
		return "@?"
	case Question:
		return "?"
	case QuestionAnd:
		return "?&"
	case QuestionPipe:
		return "?|"
	case Overlaps:
		return "OVERLAPS"
	default:
		return "UNKNOWN"
	}
}

// CustomBinaryOperator represents a custom binary operator (PostgreSQL-specific)
type CustomBinaryOperator struct {
	Parts []string
}

// String returns the string representation of the custom binary operator
func (op *CustomBinaryOperator) String() string {
	return fmt.Sprintf("OPERATOR(%s)", strings.Join(op.Parts, "."))
}
