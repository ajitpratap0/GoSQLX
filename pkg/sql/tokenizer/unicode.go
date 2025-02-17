package tokenizer

import "unicode"

// isUnicodeIdentifierStart checks if a rune can start a Unicode identifier
func isUnicodeIdentifierStart(r rune) bool {
	return unicode.IsLetter(r) || r == '_'
}

// isUnicodeIdentifierPart checks if a rune can be part of a Unicode identifier
func isUnicodeIdentifierPart(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' ||
		unicode.Is(unicode.Mn, r) || // Non-spacing marks
		unicode.Is(unicode.Mc, r) || // Spacing combining marks
		unicode.Is(unicode.Nd, r) || // Decimal numbers
		unicode.Is(unicode.Pc, r) // Connector punctuation
}

// isUnicodeWhitespace checks if a rune is a Unicode whitespace character
func isUnicodeWhitespace(r rune) bool {
	return unicode.IsSpace(r)
}

// isUnicodeQuote checks if a rune is a Unicode quote character
func isUnicodeQuote(r rune) bool {
	return r == '"' || r == '\u2018' || r == '\u201C' || r == '\u2019' || r == '\u00AB' || r == '\u00BB'
}

// normalizeQuote converts fancy Unicode quotes to standard ASCII quotes
func normalizeQuote(r rune) rune {
	switch r {
	case '\u2018', '\u2019': // Left and right single quotes
		return '\''
	case '\u201C', '\u201D', '\u00AB', '\u00BB': // Left and right double quotes, guillemets
		return '"'
	default:
		return r
	}
}
