package tokenizer

import (
	"bytes"
	"unicode/utf8"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// isDollarTagChar returns true if the rune is valid inside a dollar-quote tag.
// Tags follow identifier rules: letters, digits, underscore (but cannot start with digit).
func isDollarTagChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' ||
		(r >= '0' && r <= '9')
}

// readDollarQuotedString reads a PostgreSQL dollar-quoted string: $$...$$ or $tag$...$tag$.
// Called after the initial '$' has been consumed. startPos points to that '$'.
func (t *Tokenizer) readDollarQuotedString(startPos Position) (models.Token, error) {
	// We are positioned right after the first '$'.
	// Read the tag (may be empty for $$).
	tagStart := t.pos.Index
	for t.pos.Index < len(t.input) {
		r, size := utf8.DecodeRune(t.input[t.pos.Index:])
		if r == '$' {
			// End of tag
			break
		}
		if !isDollarTagChar(r) {
			// Invalid tag character — not a dollar-quoted string.
			// Restore position to right after first '$' and return placeholder.
			// Actually, we need to restore to tagStart and return just '$'.
			t.pos.Index = tagStart
			t.pos.Line = startPos.Line
			t.pos.Column = startPos.Column + 1
			return models.Token{Type: models.TokenTypePlaceholder, Value: "$"}, nil
		}
		// Tag chars that start with a digit are invalid as tag start
		if t.pos.Index == tagStart && r >= '0' && r <= '9' {
			t.pos.Index = tagStart
			t.pos.Line = startPos.Line
			t.pos.Column = startPos.Column + 1
			return models.Token{Type: models.TokenTypePlaceholder, Value: "$"}, nil
		}
		t.pos.AdvanceRune(r, size)
	}

	if t.pos.Index >= len(t.input) {
		// No closing '$' for the tag — not a dollar-quoted string
		t.pos.Index = tagStart
		t.pos.Line = startPos.Line
		t.pos.Column = startPos.Column + 1
		return models.Token{Type: models.TokenTypePlaceholder, Value: "$"}, nil
	}

	tag := string(t.input[tagStart:t.pos.Index])

	// Consume the closing '$' of the opening tag
	r, size := utf8.DecodeRune(t.input[t.pos.Index:])
	t.pos.AdvanceRune(r, size)

	// Build the closing delimiter: $tag$
	closingTag := "$" + tag + "$"
	closingBytes := []byte(closingTag)

	// Now read the body until we find the closing tag
	var buf bytes.Buffer
	for t.pos.Index < len(t.input) {
		// Check if we're at the closing tag
		if t.input[t.pos.Index] == '$' && t.pos.Index+len(closingBytes) <= len(t.input) {
			if bytes.Equal(t.input[t.pos.Index:t.pos.Index+len(closingBytes)], closingBytes) {
				// Found closing tag — consume it
				for i := 0; i < len(closingBytes); i++ {
					cr, cs := utf8.DecodeRune(t.input[t.pos.Index:])
					if cr == '\n' {
						t.pos.Line++
						t.pos.Column = 0
					}
					t.pos.AdvanceRune(cr, cs)
				}
				return models.Token{
					Type:  models.TokenTypeDollarQuotedString,
					Value: buf.String(),
				}, nil
			}
		}

		// Regular character
		cr, cs := utf8.DecodeRune(t.input[t.pos.Index:])
		if cr == '\n' {
			t.pos.Line++
			t.pos.Column = 0
		}
		buf.WriteRune(cr)
		t.pos.AdvanceRune(cr, cs)
	}

	// Unterminated dollar-quoted string
	return models.Token{}, errors.UnterminatedStringError(
		t.toSQLPosition(startPos),
		string(t.input),
	)
}
