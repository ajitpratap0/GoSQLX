package tokenizer

import "unicode"

// Character classification bit flags
const (
	_LETTER = 1 << iota
	_DIGIT
	_IDENT
	_SPACE
	_PUNCT
	_OPERATOR
	_HEX
	_QUOTE
	_ESCAPE = 1 << 8
)

var charClass [256]uint16

func init() {
	for i := 0; i < 256; i++ {
		ch := byte(i)
		// letters
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			charClass[i] |= _LETTER | _IDENT
		}
		// digits
		if ch >= '0' && ch <= '9' {
			charClass[i] |= _DIGIT | _IDENT | _HEX
		}
		// hex
		if (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
			charClass[i] |= _HEX
		}
		// underscore, $, >= 0x80
		if ch == '_' || ch == '$' || ch >= 0x80 {
			charClass[i] |= _IDENT
		}
		// whitespace
		if ch <= 32 {
			charClass[i] |= _SPACE
		}
		// quotes
		if ch == '\'' || ch == '"' || ch == '`' {
			charClass[i] |= _QUOTE
		}
		// escape
		if ch == '\\' {
			charClass[i] |= _ESCAPE
		}
		// punctuation
		if ch == '.' || ch == ',' || ch == ';' || ch == '(' || ch == ')' ||
			ch == '[' || ch == ']' || ch == '{' || ch == '}' {
			charClass[i] |= _PUNCT
		}
		// operators
		if ch == '=' || ch == '<' || ch == '>' || ch == '+' || ch == '-' ||
			ch == '*' || ch == '/' || ch == '%' || ch == '!' || ch == '|' ||
			ch == '&' || ch == '^' || ch == '~' {
			charClass[i] |= _OPERATOR
		}
	}
}

func isLetter(ch byte) bool      { return (charClass[ch] & _LETTER) != 0 }
func isDigit(r rune) bool {
	if r < 128 {
		return (charClass[byte(r)] & _DIGIT) != 0
	}
	return unicode.IsDigit(r)
}
func isHexDigit(ch byte) bool    { return (charClass[ch] & _HEX) != 0 }
func isIdentifier(ch byte) bool  { return (charClass[ch] & _IDENT) != 0 }
func isSpace(ch byte) bool       { return (charClass[ch] & _SPACE) != 0 }
func isQuote(ch byte) bool       { return (charClass[ch] & _QUOTE) != 0 }
func isEscape(ch byte) bool      { return (charClass[ch] & _ESCAPE) != 0 }
func isPunctuation(r rune) bool {
	if r < 128 {
		return (charClass[byte(r)] & _PUNCT) != 0
	}
	switch r {
	case '.', ',', ';', '(', ')', '[', ']', '{', '}', ':', '?':
		return true
	default:
		return false
	}
}
func isOperator(r rune) bool {
	if r < 128 {
		return (charClass[byte(r)] & _OPERATOR) != 0
	}
	switch r {
	case '+', '-', '*', '/', '%', '=', '<', '>', '!', '|', '&', '^', '~':
		return true
	default:
		return false
	}
}

// isWhitespace returns true if ch is any "space" (including tab, newline, etc.)
func isWhitespace(ch byte) bool {
	return (charClass[ch] & _SPACE) != 0
}
