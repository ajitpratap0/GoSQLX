package ast

import "testing"

// Test UnaryOperator String() method
func TestUnaryOperator(t *testing.T) {
	tests := []struct {
		name       string
		op         UnaryOperator
		wantString string
	}{
		{
			name:       "Plus operator",
			op:         Plus,
			wantString: "+",
		},
		{
			name:       "Minus operator",
			op:         Minus,
			wantString: "-",
		},
		{
			name:       "Not operator",
			op:         Not,
			wantString: "NOT",
		},
		{
			name:       "PG Bitwise Not",
			op:         PGBitwiseNot,
			wantString: "~",
		},
		{
			name:       "PG Square Root",
			op:         PGSquareRoot,
			wantString: "|/",
		},
		{
			name:       "PG Cube Root",
			op:         PGCubeRoot,
			wantString: "||/",
		},
		{
			name:       "PG Postfix Factorial",
			op:         PGPostfixFactorial,
			wantString: "!",
		},
		{
			name:       "PG Prefix Factorial",
			op:         PGPrefixFactorial,
			wantString: "!!",
		},
		{
			name:       "PG Absolute Value",
			op:         PGAbs,
			wantString: "@",
		},
		{
			name:       "Bang Not",
			op:         BangNot,
			wantString: "!",
		},
		{
			name:       "Unknown operator",
			op:         UnaryOperator(999),
			wantString: "UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.op.String(); got != tt.wantString {
				t.Errorf("UnaryOperator.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test BinaryOperator String() method
func TestBinaryOperator(t *testing.T) {
	tests := []struct {
		name       string
		op         BinaryOperator
		wantString string
	}{
		{
			name:       "Binary Plus",
			op:         BinaryPlus,
			wantString: "+",
		},
		{
			name:       "Binary Minus",
			op:         BinaryMinus,
			wantString: "-",
		},
		{
			name:       "Multiply",
			op:         Multiply,
			wantString: "*",
		},
		{
			name:       "Divide",
			op:         Divide,
			wantString: "/",
		},
		{
			name:       "Modulo",
			op:         Modulo,
			wantString: "%",
		},
		{
			name:       "String Concat",
			op:         StringConcat,
			wantString: "||",
		},
		{
			name:       "Greater Than",
			op:         Gt,
			wantString: ">",
		},
		{
			name:       "Less Than",
			op:         Lt,
			wantString: "<",
		},
		{
			name:       "Greater Than or Equal",
			op:         GtEq,
			wantString: ">=",
		},
		{
			name:       "Less Than or Equal",
			op:         LtEq,
			wantString: "<=",
		},
		{
			name:       "Spaceship",
			op:         Spaceship,
			wantString: "<=>",
		},
		{
			name:       "Equal",
			op:         Eq,
			wantString: "=",
		},
		{
			name:       "Not Equal",
			op:         NotEq,
			wantString: "<>",
		},
		{
			name:       "AND",
			op:         And,
			wantString: "AND",
		},
		{
			name:       "OR",
			op:         Or,
			wantString: "OR",
		},
		{
			name:       "XOR",
			op:         Xor,
			wantString: "XOR",
		},
		{
			name:       "Bitwise OR",
			op:         BitwiseOr,
			wantString: "|",
		},
		{
			name:       "Bitwise AND",
			op:         BitwiseAnd,
			wantString: "&",
		},
		{
			name:       "Bitwise XOR",
			op:         BitwiseXor,
			wantString: "^",
		},
		{
			name:       "DuckDB Integer Divide",
			op:         DuckIntegerDivide,
			wantString: "//",
		},
		{
			name:       "MySQL Integer Divide",
			op:         MyIntegerDivide,
			wantString: "DIV",
		},
		{
			name:       "PG Bitwise XOR",
			op:         PGBitwiseXor,
			wantString: "#",
		},
		{
			name:       "PG Bitwise Shift Left",
			op:         PGBitwiseShiftLeft,
			wantString: "<<",
		},
		{
			name:       "PG Bitwise Shift Right",
			op:         PGBitwiseShiftRight,
			wantString: ">>",
		},
		{
			name:       "PG Exponentiation",
			op:         PGExp,
			wantString: "^",
		},
		{
			name:       "PG Overlap",
			op:         PGOverlap,
			wantString: "&&",
		},
		{
			name:       "PG Regex Match",
			op:         PGRegexMatch,
			wantString: "~",
		},
		{
			name:       "PG Regex IMatch",
			op:         PGRegexIMatch,
			wantString: "~*",
		},
		{
			name:       "PG Regex Not Match",
			op:         PGRegexNotMatch,
			wantString: "!~",
		},
		{
			name:       "PG Regex Not IMatch",
			op:         PGRegexNotIMatch,
			wantString: "!~*",
		},
		{
			name:       "PG Like Match",
			op:         PGLikeMatch,
			wantString: "~~",
		},
		{
			name:       "PG ILike Match",
			op:         PGILikeMatch,
			wantString: "~~*",
		},
		{
			name:       "PG Not Like Match",
			op:         PGNotLikeMatch,
			wantString: "!~~",
		},
		{
			name:       "PG Not ILike Match",
			op:         PGNotILikeMatch,
			wantString: "!~~*",
		},
		{
			name:       "PG Starts With",
			op:         PGStartsWith,
			wantString: "^@",
		},
		{
			name:       "Arrow (JSON)",
			op:         Arrow,
			wantString: "->",
		},
		{
			name:       "Long Arrow (JSON)",
			op:         LongArrow,
			wantString: "->>",
		},
		{
			name:       "Hash Arrow (JSON path)",
			op:         HashArrow,
			wantString: "#>",
		},
		{
			name:       "Hash Long Arrow (JSON path)",
			op:         HashLongArrow,
			wantString: "#>>",
		},
		{
			name:       "At At (text search)",
			op:         AtAt,
			wantString: "@@",
		},
		{
			name:       "At Arrow (contains)",
			op:         AtArrow,
			wantString: "@>",
		},
		{
			name:       "Arrow At (contained by)",
			op:         ArrowAt,
			wantString: "<@",
		},
		{
			name:       "Hash Minus (JSON delete)",
			op:         HashMinus,
			wantString: "#-",
		},
		{
			name:       "At Question (JSON path exists)",
			op:         AtQuestion,
			wantString: "@?",
		},
		{
			name:       "Question (JSON key exists)",
			op:         Question,
			wantString: "?",
		},
		{
			name:       "Question And (JSON all keys)",
			op:         QuestionAnd,
			wantString: "?&",
		},
		{
			name:       "Question Pipe (JSON any key)",
			op:         QuestionPipe,
			wantString: "?|",
		},
		{
			name:       "OVERLAPS",
			op:         Overlaps,
			wantString: "OVERLAPS",
		},
		{
			name:       "Unknown operator",
			op:         BinaryOperator(9999),
			wantString: "UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.op.String(); got != tt.wantString {
				t.Errorf("BinaryOperator.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test CustomBinaryOperator String() method
func TestCustomBinaryOperator(t *testing.T) {
	tests := []struct {
		name       string
		op         *CustomBinaryOperator
		wantString string
	}{
		{
			name: "simple custom operator",
			op: &CustomBinaryOperator{
				Parts: []string{"pg_catalog", "==="},
			},
			wantString: "OPERATOR(pg_catalog.===)",
		},
		{
			name: "custom operator with schema",
			op: &CustomBinaryOperator{
				Parts: []string{"myschema", "myop"},
			},
			wantString: "OPERATOR(myschema.myop)",
		},
		{
			name: "custom operator single part",
			op: &CustomBinaryOperator{
				Parts: []string{"@@@"},
			},
			wantString: "OPERATOR(@@@)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.op.String(); got != tt.wantString {
				t.Errorf("CustomBinaryOperator.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}
