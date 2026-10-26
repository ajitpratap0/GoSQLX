// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package parser - expressions_datatype.go
// Data type names for CAST(expr AS type) and expr::type.

package parser

import (
	"fmt"
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// parseDataType parses a SQL data type for CAST or :: expressions.
//
// It handles simple types (INTEGER, TEXT), schema-qualified types
// (public.mood), parameterized types (VARCHAR(100), NUMERIC(10,2)),
// multi-word types (DOUBLE PRECISION, CHARACTER VARYING, TIMESTAMP WITH TIME
// ZONE, MySQL SIGNED INTEGER and UNSIGNED), a MySQL CHARACTER SET suffix
// (CHAR(10) CHARACTER SET utf8mb4) and array dimensions (int[], text[][3]).
// The result is the type text with single spaces between words.
func (p *Parser) parseDataType() (string, error) {
	return p.parseDataTypeHint("Use TYPE(precision[, scale]) syntax")
}

// parseDataTypeHint is parseDataType with the hint attached to a malformed
// type parameter error.
func (p *Parser) parseDataTypeHint(paramHint string) (string, error) {
	// Data type can be an identifier or a keyword like INT, VARCHAR, etc.
	if !p.isIdentifier() && !p.isDataTypeKeyword() {
		return "", p.expectedError("data type")
	}

	first := p.currentToken.Token.Value
	p.advance() // Consume type name

	// Fast path: a single plain word, as in x::int or CAST(x AS text).
	switch p.currentToken.Token.Type {
	case models.TokenTypeLParen, models.TokenTypeLBracket, models.TokenTypePeriod:
	default:
		if p.dataTypeWordClass(first) == typeWordNone {
			return first, nil
		}
	}

	// Use strings.Builder for efficient string concatenation
	var sb strings.Builder
	sb.WriteString(first)

	// Schema-qualified type: public.my_enum, pg_catalog.int4.
	for p.isType(models.TokenTypePeriod) && (p.peekTypeAt(1) == models.TokenTypeIdentifier || p.peekTypeAt(1) == models.TokenTypeDoubleQuotedString) {
		p.advance() // Consume .
		sb.WriteByte('.')
		sb.WriteString(p.currentToken.Token.Value)
		p.advance()
	}

	class := p.dataTypeWordClass(first)
	national := equalsUpper(first, "NATIONAL")

	// Words that follow the type name directly (DOUBLE PRECISION,
	// CHARACTER VARYING, SIGNED INTEGER) and, for the temporal types, come
	// after the precision (TIMESTAMP(3) WITH TIME ZONE).
	if class != typeWordTemporal {
		p.writeTypeWords(&sb, class, national)
	}

	// Check for type parameters (e.g., VARCHAR(100), DECIMAL(10,2))
	if p.isType(models.TokenTypeLParen) {
		p.advance() // Consume (
		sb.WriteByte('(')

		paramCount := 0
		for !p.isType(models.TokenTypeRParen) {
			if paramCount > 0 {
				if !p.isType(models.TokenTypeComma) {
					return "", p.expectedError(", or )")
				}
				sb.WriteString(p.currentToken.Token.Value)
				p.advance() // Consume comma
			}

			// Parse parameter (should be a number or identifier)
			// Use token type constants for consistency
			if !p.isType(models.TokenTypeNumber) && !p.isType(models.TokenTypeIdentifier) && !p.isNumericLiteral() {
				return "", goerrors.InvalidSyntaxError(
					fmt.Sprintf("expected numeric type parameter, got '%s'", p.currentToken.Token.Value),
					p.currentLocation(),
					"",
				).WithHint(paramHint)
			}

			sb.WriteString(p.currentToken.Token.Value)
			p.advance()
			paramCount++
		}

		sb.WriteByte(')')

		if !p.isType(models.TokenTypeRParen) {
			return "", p.expectedError(")")
		}
		p.advance() // Consume )
	}

	if class == typeWordTemporal || class == typeWordChar {
		p.writeTypeWords(&sb, class, false)
	}

	// Check for array type suffixes (e.g., INTEGER[], TEXT[][], INT[3])
	for p.isType(models.TokenTypeLBracket) {
		p.advance() // Consume [
		sb.WriteByte('[')
		if p.isType(models.TokenTypeNumber) {
			sb.WriteString(p.currentToken.Token.Value)
			p.advance()
		}
		if !p.isType(models.TokenTypeRBracket) {
			return "", p.expectedError("]")
		}
		p.advance() // Consume ]
		sb.WriteByte(']')
	}

	return sb.String(), nil
}

// typeWordClass groups first words of a data type by the words that may
// follow them.
type typeWordClass int

const (
	typeWordNone     typeWordClass = iota
	typeWordDouble                 // DOUBLE [PRECISION]
	typeWordChar                   // CHAR, CHARACTER, VARCHAR, NCHAR, NATIONAL: [VARYING] [CHARACTER SET x]
	typeWordTemporal               // TIMESTAMP, TIME: [(p)] WITH|WITHOUT TIME ZONE
	typeWordSigned                 // SIGNED, UNSIGNED: [INTEGER | INT]
	typeWordBit                    // BIT [VARYING]
)

// dataTypeWordClass classifies the first word of a data type. It allocates
// nothing and is a no-op for most words.
func (p *Parser) dataTypeWordClass(first string) typeWordClass {
	switch len(first) {
	case 3:
		if equalsUpper(first, "BIT") {
			return typeWordBit
		}
	case 4:
		switch {
		case equalsUpper(first, "CHAR"):
			return typeWordChar
		case equalsUpper(first, "TIME"):
			return typeWordTemporal
		}
	case 5:
		if equalsUpper(first, "NCHAR") {
			return typeWordChar
		}
	case 6:
		switch {
		case equalsUpper(first, "DOUBLE"):
			return typeWordDouble
		case equalsUpper(first, "SIGNED"):
			return typeWordSigned
		}
	case 7:
		if equalsUpper(first, "VARCHAR") {
			return typeWordChar
		}
	case 8:
		switch {
		case equalsUpper(first, "UNSIGNED"):
			return typeWordSigned
		case equalsUpper(first, "NATIONAL"):
			return typeWordChar
		}
	case 9:
		switch {
		case equalsUpper(first, "CHARACTER"):
			return typeWordChar
		case equalsUpper(first, "TIMESTAMP"):
			return typeWordTemporal
		}
	}
	return typeWordNone
}

// writeTypeWords appends the words that follow a type name of the given
// class, consuming them. Each word is matched only in the position where it
// is part of a type, so an alias or keyword after the type is left alone.
func (p *Parser) writeTypeWords(sb *strings.Builder, class typeWordClass, national bool) {
	write := func() {
		sb.WriteByte(' ')
		sb.WriteString(p.currentToken.Token.Value)
		p.advance()
	}
	cur := func(upper string) bool { return equalsUpper(p.currentToken.Token.Value, upper) }

	switch class {
	case typeWordDouble:
		if cur("PRECISION") {
			write()
		}
	case typeWordBit:
		if cur("VARYING") {
			write()
		}
	case typeWordSigned:
		if cur("INTEGER") || cur("INT") {
			write()
		}
	case typeWordChar:
		// MySQL: CHAR(10) CHARACTER SET utf8mb4 / CHARSET utf8mb4. The charset
		// name follows. This runs again after the length is parsed, so it only
		// fires when the next tokens really are CHARACTER SET or CHARSET.
		switch {
		case cur("CHARACTER") && p.peekValueIs(1, "SET") && p.peekAt(2).Token.Value != "":
			write() // CHARACTER
			write() // SET
			write() // charset name
			return
		case cur("CHARSET") && p.peekAt(1).Token.Value != "":
			write() // CHARSET
			write() // charset name
			return
		}
		// NATIONAL CHARACTER [VARYING], CHARACTER VARYING
		if national && (cur("CHARACTER") || cur("CHAR")) {
			write()
		}
		if cur("VARYING") {
			write()
		}
	case typeWordTemporal:
		// TIMESTAMP [(p)] WITH|WITHOUT TIME ZONE; WITH is a keyword token.
		if (cur("WITH") || cur("WITHOUT")) && p.peekValueIs(1, "TIME") && p.peekValueIs(2, "ZONE") {
			write() // WITH / WITHOUT
			write() // TIME
			write() // ZONE
		}
	}
}
