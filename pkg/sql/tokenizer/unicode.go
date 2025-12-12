package tokenizer

import "unicode"

// isUnicodeIdentifierStart checks if a rune can start a Unicode identifier.
//
// SQL identifiers in GoSQLX follow Unicode identifier rules, allowing:
//   - Any Unicode letter (Lu, Ll, Lt, Lm, Lo categories)
//   - Underscore (_)
//
// This enables international SQL processing with identifiers in any language.
//
// Examples:
//   - English: "users", "_temp"
//   - Japanese: "ユーザー"
//   - Chinese: "用户表"
//   - Russian: "пользователи"
//   - Arabic: "المستخدمين"
//
// Returns true if the rune can start an identifier, false otherwise.
func isUnicodeIdentifierStart(r rune) bool {
	return unicode.IsLetter(r) || r == '_'
}

// isUnicodeIdentifierPart checks if a rune can be part of a Unicode identifier.
//
// After the initial character, identifiers can contain:
//   - Any Unicode letter (Lu, Ll, Lt, Lm, Lo)
//   - Any Unicode digit (Nd category)
//   - Underscore (_)
//   - Non-spacing marks (Mn category) - diacritics, accents
//   - Spacing combining marks (Mc category)
//   - Connector punctuation (Pc category)
//
// This comprehensive support enables identifiers with combining characters,
// digits in various scripts, and proper Unicode normalization.
//
// Examples:
//   - "user123" (ASCII letters + digits)
//   - "用户123" (Chinese letters + ASCII digits)
//   - "café" (letter + combining accent)
//   - "संख्या१" (Devanagari letters + Devanagari digit)
//
// Returns true if the rune can be part of an identifier, false otherwise.
func isUnicodeIdentifierPart(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' ||
		unicode.Is(unicode.Mn, r) || // Non-spacing marks
		unicode.Is(unicode.Mc, r) || // Spacing combining marks
		unicode.Is(unicode.Nd, r) || // Decimal numbers
		unicode.Is(unicode.Pc, r) // Connector punctuation
}

// isUnicodeQuote checks if a rune is a Unicode quote character for identifiers.
//
// In SQL, double quotes (and their Unicode equivalents) are used for
// quoted identifiers, while single quotes are for string literals.
//
// Recognized Unicode double quote characters:
//   - U+201C (") LEFT DOUBLE QUOTATION MARK
//   - U+201D (") RIGHT DOUBLE QUOTATION MARK
//
// These are normalized to ASCII double quote (") during processing.
//
// Returns true for Unicode double quote characters, false otherwise.
func isUnicodeQuote(r rune) bool {
	// Only double quotes and their Unicode equivalents are for identifiers
	return r == '\u201C' || r == '\u201D'
}

// normalizeQuote converts Unicode quote characters to standard ASCII quotes.
//
// This normalization ensures consistent quote handling across different text
// encodings and input sources (e.g., copy-paste from documents, web forms).
//
// Normalization mappings:
//   - U+2018 (') LEFT SINGLE QUOTATION MARK → '
//   - U+2019 (') RIGHT SINGLE QUOTATION MARK → '
//   - U+00AB («) LEFT-POINTING DOUBLE ANGLE QUOTATION MARK → '
//   - U+00BB (») RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK → '
//   - U+201C (") LEFT DOUBLE QUOTATION MARK → "
//   - U+201D (") RIGHT DOUBLE QUOTATION MARK → "
//
// This allows SQL written with "smart quotes" from word processors or
// copied from formatted documents to be processed correctly.
//
// Returns the normalized ASCII quote character, or the original rune if
// it's not a Unicode quote.
func normalizeQuote(r rune) rune {
	switch r {
	case '\u2018', '\u2019', '\u00AB', '\u00BB': // Single quotes and guillemets
		return '\''
	case '\u201C', '\u201D': // Left and right double quotes
		return '"'
	default:
		return r
	}
}
