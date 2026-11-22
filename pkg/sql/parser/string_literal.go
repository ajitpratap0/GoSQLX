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

package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
)

// newStringLiteral builds the AST node for a string literal whose decoded text
// is value. The node records whether the dialect treats a backslash as an
// ordinary character, so the formatter writes the text back under the same
// rules instead of doubling every backslash on each pass.
func (p *Parser) newStringLiteral(value string) *ast.LiteralValue {
	lit := &ast.LiteralValue{Value: value, Type: "string"}
	if p.rawStringLiterals {
		lit.SetRawBackslash(true)
	}
	return lit
}

// mayStartPrefixedString is an inlinable screen for parsePrefixedStringLiteral:
// it is true at every token where parsePrefixedStringLiteral can succeed.
func (p *Parser) mayStartPrefixedString() bool {
	tok := &p.currentToken.Token
	switch tok.Type {
	case models.TokenTypeIdentifier:
		return len(tok.Value) >= 2 && tok.Value[0] == '_'
	case models.TokenTypeSingleQuotedString:
		return tok.Quote == 'q'
	}
	return prefixedStringTypes.has(tok.Type)
}

// prefixedStringTypes holds the token types of the string literals whose
// introducer the tokenizer has already recognised.
var prefixedStringTypes = newTokenTypeSet(models.TokenTypeNationalStringLiteral, models.TokenTypeHexStringLiteral,
	models.TokenTypeByteStringLiteral, models.TokenTypeEscapedStringLiteral)

// parsePrefixedStringLiteral parses a string literal that carries an
// introducer: N'..' (national), X'..' (hex), B'..' (bit), a PostgreSQL E'..'
// escape string and a MySQL character-set introducer such as _utf8mb4'..'.
// ok is false, with nothing consumed, when the current token starts no such
// literal.
//
// The introducer is kept in ast.LiteralExtras.Prefix so the formatter writes it
// back: dropping X or N would change the value's type, and E and q keep the
// quoting the author chose. The tokenizer has already decoded the text.
func (p *Parser) parsePrefixedStringLiteral() (expr ast.Expression, ok bool) {
	tok := p.currentToken.Token
	switch tok.Type {
	case models.TokenTypeNationalStringLiteral:
		p.advance()
		lit := p.newStringLiteral(tok.Value)
		lit.EnsureExtras().Prefix = "N"
		return lit, true
	case models.TokenTypeHexStringLiteral:
		p.advance()
		lit := p.newStringLiteral(tok.Value)
		lit.EnsureExtras().Prefix = "X"
		return lit, true
	case models.TokenTypeByteStringLiteral:
		p.advance()
		lit := p.newStringLiteral(tok.Value)
		lit.EnsureExtras().Prefix = "B"
		return lit, true
	case models.TokenTypeEscapedStringLiteral:
		p.advance()
		lit := p.newStringLiteral(tok.Value)
		lit.EnsureExtras().Prefix = "E"
		lit.SetRawBackslash(false) // an E-string is written with escapes
		return lit, true
	case models.TokenTypeSingleQuotedString:
		// Oracle q'[text]': the tokenizer marks it with Quote 'q'.
		if tok.Quote != 'q' {
			return nil, false
		}
		p.advance()
		lit := p.newStringLiteral(tok.Value)
		lit.EnsureExtras().Prefix = "q"
		return lit, true
	case models.TokenTypeIdentifier:
		// _charset'text': an underscore word directly followed by a string.
		if len(tok.Value) < 2 || tok.Value[0] != '_' || tok.Quote != 0 ||
			(p.dialectTyped != dialect.MySQL && p.dialectTyped != dialect.MariaDB) {
			return nil, false
		}
		next := p.peekToken()
		if next.Token.Type != models.TokenTypeSingleQuotedString || next.Start != p.currentToken.End {
			return nil, false
		}
		p.advance() // charset name
		str := p.currentToken.Token.Value
		p.advance() // string
		lit := p.newStringLiteral(str)
		lit.EnsureExtras().Prefix = tok.Value
		return lit, true
	}
	return nil, false
}
