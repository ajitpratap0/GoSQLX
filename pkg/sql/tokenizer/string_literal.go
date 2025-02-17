package tokenizer

import (
	"bytes"
	"fmt"
	"unicode/utf8"

	"github.com/ajitpratapsingh/GoSQLX/pkg/models"
)

// StringLiteralReader handles reading of string literals with proper escape sequence handling
type StringLiteralReader struct {
	input []byte
	pos   *Position
	quote rune
}

// NewStringLiteralReader creates a new StringLiteralReader
func NewStringLiteralReader(input []byte, pos *Position, quote rune) *StringLiteralReader {
	return &StringLiteralReader{
		input: input,
		pos:   pos,
		quote: quote,
	}
}

// ReadStringLiteral reads a string literal with proper escape sequence handling
func (r *StringLiteralReader) ReadStringLiteral() (models.Token, error) {
	// Normalize the quote character
	r.quote = normalizeQuote(r.quote)
	var buf bytes.Buffer
	startPos := r.pos.Clone()

	// Skip the opening quote
	r.pos.Index++
	r.pos.Column++

	for r.pos.Index < len(r.input) {
		ch, size := utf8.DecodeRune(r.input[r.pos.Index:])
		ch = normalizeQuote(ch)

		if ch == '\\' {
			// Handle escape sequences
			if err := r.handleEscapeSequence(&buf); err != nil {
				return models.Token{}, TokenizerError{
					Message:  fmt.Sprintf("invalid escape sequence at line %d, column %d", r.pos.Line, r.pos.Column),
					Location: models.Location{Line: r.pos.Line, Column: r.pos.Column},
				}
			}
			continue
		}

		if ch == '\n' {
			return models.Token{}, TokenizerError{
				Message:  fmt.Sprintf("unterminated string literal starting at line %d, column %d", startPos.Line, startPos.Column),
				Location: models.Location{Line: startPos.Line, Column: startPos.Column},
			}
		}

		if ch == r.quote {
			// Check for double quotes (escaped quotes)
			if r.pos.Index+size < len(r.input) {
				nextR, nextSize := utf8.DecodeRune(r.input[r.pos.Index+size:])
				nextR = normalizeQuote(nextR)
				if nextR == r.quote {
					// Include one quote and skip the other
					buf.WriteRune(ch)
					r.pos.Index += size + nextSize
					r.pos.Column += 2
					continue
				}
			}
			// End of string
			r.pos.Index += size
			r.pos.Column++
			return models.Token{
				Type:  models.TokenTypeString,
				Value: buf.String(),
			}, nil
		}

		// Handle regular characters
		buf.WriteRune(ch)
		r.pos.Index += size
		r.pos.Column++
	}

	return models.Token{}, TokenizerError{
		Message:  fmt.Sprintf("unterminated string literal starting at line %d, column %d", startPos.Line, startPos.Column),
		Location: models.Location{Line: startPos.Line, Column: startPos.Column},
	}
}

// handleEscapeSequence processes escape sequences in string literals
func (r *StringLiteralReader) handleEscapeSequence(buf *bytes.Buffer) error {
	// Skip the backslash
	r.pos.Index++
	r.pos.Column++

	if r.pos.Index >= len(r.input) {
		return fmt.Errorf("unexpected end of input after escape character")
	}

	ch := r.input[r.pos.Index]
	r.pos.Index++
	r.pos.Column++

	switch ch {
	case 'n':
		buf.WriteByte('\n')
	case 'r':
		buf.WriteByte('\r')
	case 't':
		buf.WriteByte('\t')
	case '\\':
		buf.WriteByte('\\')
	case '\'':
		buf.WriteByte('\'')
	case '"':
		buf.WriteByte('"')
	case 'u':
		return r.handleUnicodeEscape(buf)
	default:
		return fmt.Errorf("invalid escape sequence '\\%c'", ch)
	}

	return nil
}

// handleUnicodeEscape handles \uXXXX Unicode escape sequences
func (r *StringLiteralReader) handleUnicodeEscape(buf *bytes.Buffer) error {
	if r.pos.Index+4 > len(r.input) {
		return fmt.Errorf("incomplete Unicode escape sequence")
	}

	var value rune
	for i := 0; i < 4; i++ {
		ch := r.input[r.pos.Index+i]
		var digit rune
		switch {
		case ch >= '0' && ch <= '9':
			digit = rune(ch - '0')
		case ch >= 'a' && ch <= 'f':
			digit = rune(ch-'a') + 10
		case ch >= 'A' && ch <= 'F':
			digit = rune(ch-'A') + 10
		default:
			return fmt.Errorf("invalid Unicode escape sequence")
		}
		value = value*16 + digit
	}

	buf.WriteRune(value)
	r.pos.Index += 4
	r.pos.Column += 4
	return nil
}
