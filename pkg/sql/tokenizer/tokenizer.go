// Package tokenizer provides a high-performance SQL tokenizer with zero-copy operations
package tokenizer

import (
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/ajitpratapsingh/GoSQLX/pkg/models"
	"github.com/ajitpratapsingh/GoSQLX/pkg/sql/keywords"
)

// Tokenizer provides high-performance SQL tokenization with zero-copy operations
type Tokenizer struct {
	input      []byte
	pos        Position
	lineStart  Position
	lineStarts []int
	line       int
	keywords   *keywords.Keywords
	debugLog   DebugLogger
}

// TokenizerError is a simple error wrapper
type TokenizerError struct {
	Message  string
	Location models.Location
}

func (e TokenizerError) Error() string {
	return e.Message
}

// SetDebugLogger sets a debug logger for verbose tracing
func (t *Tokenizer) SetDebugLogger(logger DebugLogger) {
	t.debugLog = logger
}

// New creates a new Tokenizer with default configuration
func New() (*Tokenizer, error) {
	kw, err := keywords.NewKeywords()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize keywords: %w", err)
	}
	return &Tokenizer{
		keywords:   kw,
		pos:        NewPosition(1, 0),
		lineStarts: []int{0},
	}, nil
}

// NewWithKeywords initializes a Tokenizer with custom keywords
func NewWithKeywords(kw *keywords.Keywords) (*Tokenizer, error) {
	if kw == nil {
		return nil, fmt.Errorf("keywords cannot be nil")
	}

	return &Tokenizer{
		keywords:   kw,
		pos:        NewPosition(1, 0),
		lineStarts: []int{0},
	}, nil
}

// Tokenize processes the input and returns tokens
func (t *Tokenizer) Tokenize(input []byte) ([]models.TokenWithSpan, error) {
	// Reset state
	t.Reset()
	t.input = input

	// Pre-allocate line starts slice
	t.lineStarts = make([]int, 0, len(input)/50) // Estimate 50 chars per line
	t.lineStarts = append(t.lineStarts, 0)

	// Pre-scan input to build line start indices
	for i := 0; i < len(t.input); i++ {
		if t.input[i] == '\n' {
			t.lineStarts = append(t.lineStarts, i+1)
		}
	}

	// Pre-allocate token slice with estimated capacity
	estimatedTokens := len(input) / 5 // Rough estimate: 1 token per 5 bytes
	tokens := make([]models.TokenWithSpan, 0, estimatedTokens)

	// Get a buffer from the pool for string operations
	buf := getBuffer()
	defer putBuffer(buf)

	var tokenErr error
	func() {
		// Ensure proper cleanup even if we panic
		defer func() {
			if r := recover(); r != nil {
				tokenErr = fmt.Errorf("panic during tokenization: %v", r)
			}
		}()

		for t.pos.Index < len(t.input) {
			t.skipWhitespace()

			if t.pos.Index >= len(t.input) {
				break
			}

			startPos := t.pos

			token, err := t.nextToken()
			if err != nil {
				tokenErr = TokenizerError{
					Message:  err.Error(),
					Location: t.toSQLPosition(startPos),
				}
				return
			}

			tokens = append(tokens, models.TokenWithSpan{
				Token: token,
				Start: t.toSQLPosition(startPos),
				End:   t.getCurrentPosition(),
			})
		}
	}()

	if tokenErr != nil {
		return nil, tokenErr
	}

	// Add EOF token
	tokens = append(tokens, models.TokenWithSpan{
		Token: models.Token{Type: models.TokenTypeEOF},
		Start: t.getCurrentPosition(),
		End:   t.getCurrentPosition(),
	})

	return tokens, nil
}

// skipWhitespace advances past any whitespace
func (t *Tokenizer) skipWhitespace() {
	for t.pos.Index < len(t.input) {
		r, size := utf8.DecodeRune(t.input[t.pos.Index:])
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			t.pos.AdvanceRune(r, size)
			continue
		}
		break
	}
}

// nextToken picks out the next token from the input
func (t *Tokenizer) nextToken() (models.Token, error) {
	if t.pos.Index >= len(t.input) {
		return models.Token{Type: models.TokenTypeEOF}, nil
	}

	// Fast path for common cases
	r, _ := utf8.DecodeRune(t.input[t.pos.Index:])
	switch {
	case isIdentifierStart(r):
		return t.readIdentifier()
	case r >= '0' && r <= '9':
		return t.readNumber(nil)
	case r == '"' || isUnicodeQuote(r):
		return t.readQuotedIdentifier()
	case r == '\'':
		return t.readQuotedString('\'')
	}

	// Slower path for punctuation and operators
	return t.readPunctuation()
}

// isIdentifierStart checks if a rune can start an identifier
func isIdentifierStart(r rune) bool {
	return isUnicodeIdentifierStart(r)
}

// readIdentifier reads an identifier (e.g. foo or foo.bar)
func (t *Tokenizer) readIdentifier() (models.Token, error) {
	start := t.pos.Index
	r, size := utf8.DecodeRune(t.input[t.pos.Index:])
	t.pos.AdvanceRune(r, size)

	// Read until we hit a non-identifier character
	for t.pos.Index < len(t.input) {
		r, size = utf8.DecodeRune(t.input[t.pos.Index:])
		if !isIdentifierChar(r) {
			break
		}
		t.pos.AdvanceRune(r, size)
	}

	// Check for compound keywords (e.g., ORDER BY)
	if t.pos.Index < len(t.input) {
		ident := string(t.input[start:t.pos.Index])
		if strings.ToUpper(ident) == "ORDER" || strings.ToUpper(ident) == "GROUP" {
			// Skip whitespace
			oldPos := t.pos
			t.skipWhitespace()
			if t.pos.Index < len(t.input) {
				nextStart := t.pos.Index
				for t.pos.Index < len(t.input) {
					r, size = utf8.DecodeRune(t.input[t.pos.Index:])
					if !isIdentifierChar(r) {
						break
					}
					t.pos.AdvanceRune(r, size)
				}
				nextIdent := string(t.input[nextStart:t.pos.Index])
				if strings.ToUpper(nextIdent) == "BY" {
					compound := ident + " " + nextIdent
					if strings.ToUpper(ident) == "ORDER" {
						return models.Token{
							Type:  models.TokenTypeOrderBy,
							Value: compound,
						}, nil
					} else {
						return models.Token{
							Type:  models.TokenTypeGroupBy,
							Value: compound,
						}, nil
					}
				}
			}
			t.pos = oldPos // Restore position if not a compound keyword
		}
	}

	// Check if this is a keyword
	ident := string(t.input[start:t.pos.Index])
	identUpper := strings.ToUpper(ident)

	// Handle special keywords
	switch identUpper {
	case "AND":
		return models.Token{Type: models.TokenTypeAnd, Value: ident}, nil
	case "LIKE":
		return models.Token{Type: models.TokenTypeLike, Value: ident}, nil
	case "ASC":
		return models.Token{Type: models.TokenTypeAsc, Value: ident}, nil
	}

	tokenType := t.keywords.GetTokenType(identUpper)
	if tokenType == models.TokenTypeUnknown {
		tokenType = models.TokenTypeIdentifier
	}
	return models.Token{
		Type:  tokenType,
		Value: ident,
	}, nil
}

// readQuotedIdentifier reads something like "MyColumn" with support for Unicode quotes
func (t *Tokenizer) readQuotedIdentifier() (models.Token, error) {
	// Get and normalize opening quote
	r, size := utf8.DecodeRune(t.input[t.pos.Index:])
	quote := normalizeQuote(r)
	startPos := t.pos.Clone()

	// Skip opening quote
	t.pos.AdvanceRune(r, size)

	var buf bytes.Buffer
	for t.pos.Index < len(t.input) {
		r, size := utf8.DecodeRune(t.input[t.pos.Index:])
		r = normalizeQuote(r)

		if r == quote {
			// Check for escaped quote
			if t.pos.Index+size < len(t.input) {
				nextR, nextSize := utf8.DecodeRune(t.input[t.pos.Index+size:])
				nextR = normalizeQuote(nextR)
				if nextR == quote {
					// Include one quote and skip the other
					buf.WriteRune(r)
					t.pos.Index += size + nextSize
					t.pos.Column += 2
					continue
				}
			}

			// End of quoted identifier
			t.pos.Index += size
			t.pos.Column++

			// Return as string if it was started with a single quote or guillemet
			if quote == '\'' || quote == '"' {
				return models.Token{
					Type:  models.TokenTypeString,
					Value: buf.String(),
				}, nil
			}

			return models.Token{
				Type:  models.TokenTypeIdentifier,
				Value: buf.String(),
			}, nil
		}

		if r == '\n' {
			return models.Token{}, TokenizerError{
				Message:  fmt.Sprintf("unterminated quoted identifier starting at line %d, column %d", startPos.Line, startPos.Column),
				Location: models.Location{Line: startPos.Line, Column: startPos.Column},
			}
		}

		// Handle regular characters
		buf.WriteRune(r)
		t.pos.Index += size
		t.pos.Column++
	}

	return models.Token{}, TokenizerError{
		Message:  fmt.Sprintf("unterminated quoted identifier starting at line %d, column %d", startPos.Line, startPos.Column),
		Location: models.Location{Line: startPos.Line, Column: startPos.Column},
	}
}

// readQuotedString handles the actual scanning of a single/double-quoted string
func (t *Tokenizer) readQuotedString(quote rune) (models.Token, error) {
	// Store start position for error reporting
	startPos := t.pos

	// Get and normalize opening quote
	r, size := utf8.DecodeRune(t.input[t.pos.Index:])
	quote = normalizeQuote(r)

	// Skip opening quote
	t.pos.AdvanceRune(r, size)

	var buf bytes.Buffer
	for t.pos.Index < len(t.input) {
		r, size := utf8.DecodeRune(t.input[t.pos.Index:])
		r = normalizeQuote(r)

		if r == quote {
			// Check for escaped quote
			if t.pos.Index+size < len(t.input) {
				nextR, nextSize := utf8.DecodeRune(t.input[t.pos.Index+size:])
				nextR = normalizeQuote(nextR)
				if nextR == quote {
					// Include one quote and skip the other
					buf.WriteRune(r)
					t.pos.Index += size + nextSize
					t.pos.Column += 2
					continue
				}
			}

			// End of string
			t.pos.Index += size
			t.pos.Column++
			return models.Token{
				Type:  models.TokenTypeString,
				Value: buf.String(),
			}, nil
		}

		if r == '\\' {
			// Handle escape sequences
			if err := t.handleEscapeSequence(&buf); err != nil {
				return models.Token{}, TokenizerError{
					Message:  fmt.Sprintf("invalid escape sequence at line %d, column %d", t.pos.Line, t.pos.Column),
					Location: models.Location{Line: t.pos.Line, Column: startPos.Column},
				}
			}
			continue
		}

		if r == '\n' {
			buf.WriteRune(r)
			t.pos.Index += size
			t.pos.Line++
			t.pos.Column = 1
			continue
		}

		// Handle regular characters
		buf.WriteRune(r)
		t.pos.Index += size
		t.pos.Column++
	}

	return models.Token{}, TokenizerError{
		Message:  fmt.Sprintf("unterminated string literal starting at line %d, column %d", startPos.Line, startPos.Column),
		Location: models.Location{Line: startPos.Line, Column: startPos.Column},
	}
}

// handleEscapeSequence handles escape sequences in string literals
func (t *Tokenizer) handleEscapeSequence(buf *bytes.Buffer) error {
	t.pos.Index++
	t.pos.Column++

	if t.pos.Index >= len(t.input) {
		return fmt.Errorf("unexpected end of input after escape character")
	}

	r, size := utf8.DecodeRune(t.input[t.pos.Index:])
	switch r {
	case '\\', '"', '\'', '`':
		buf.WriteRune(r)
	case 'n':
		buf.WriteRune('\n')
	case 'r':
		buf.WriteRune('\r')
	case 't':
		buf.WriteRune('\t')
	default:
		return fmt.Errorf("invalid escape sequence '\\%c'", r)
	}

	t.pos.Index += size
	t.pos.Column++
	return nil
}

// readNumber reads an integer/float
func (t *Tokenizer) readNumber(buf []byte) (models.Token, error) {
	var start int
	if buf == nil {
		start = t.pos.Index
	} else {
		start = t.pos.Index - len(buf)
	}

	// Read integer part
	for t.pos.Index < len(t.input) {
		r, size := utf8.DecodeRune(t.input[t.pos.Index:])
		if r < '0' || r > '9' {
			break
		}
		t.pos.AdvanceRune(r, size)
	}

	if t.pos.Index >= len(t.input) {
		return models.Token{
			Type:  models.TokenTypeNumber,
			Value: string(t.input[start:t.pos.Index]),
		}, nil
	}

	// Look for decimal point
	r, size := utf8.DecodeRune(t.input[t.pos.Index:])
	if r == '.' {
		t.pos.AdvanceRune(r, size)

		// Must have at least one digit after decimal
		if t.pos.Index >= len(t.input) {
			return models.Token{}, fmt.Errorf("expected digit after decimal point")
		}

		r, size = utf8.DecodeRune(t.input[t.pos.Index:])
		if r < '0' || r > '9' {
			return models.Token{}, fmt.Errorf("expected digit after decimal point")
		}

		// Read fractional part
		for t.pos.Index < len(t.input) {
			r, size = utf8.DecodeRune(t.input[t.pos.Index:])
			if r < '0' || r > '9' {
				break
			}
			t.pos.AdvanceRune(r, size)
		}
	}

	// Look for exponent
	if t.pos.Index < len(t.input) {
		r, size = utf8.DecodeRune(t.input[t.pos.Index:])
		if r == 'e' || r == 'E' {
			t.pos.AdvanceRune(r, size)

			// Optional sign
			if t.pos.Index < len(t.input) {
				r, size = utf8.DecodeRune(t.input[t.pos.Index:])
				if r == '+' || r == '-' {
					t.pos.AdvanceRune(r, size)
				}
			}

			// Must have at least one digit
			if t.pos.Index >= len(t.input) {
				return models.Token{}, fmt.Errorf("expected digit in exponent")
			}

			r, size = utf8.DecodeRune(t.input[t.pos.Index:])
			if r < '0' || r > '9' {
				return models.Token{}, fmt.Errorf("expected digit in exponent")
			}

			// Read exponent part
			for t.pos.Index < len(t.input) {
				r, size = utf8.DecodeRune(t.input[t.pos.Index:])
				if r < '0' || r > '9' {
					break
				}
				t.pos.AdvanceRune(r, size)
			}
		}
	}

	return models.Token{
		Type:  models.TokenTypeNumber,
		Value: string(t.input[start:t.pos.Index]),
	}, nil
}

// readPunctuation picks out punctuation or operator tokens
func (t *Tokenizer) readPunctuation() (models.Token, error) {
	if t.pos.Index >= len(t.input) {
		return models.Token{}, fmt.Errorf("unexpected end of input")
	}
	r, size := utf8.DecodeRune(t.input[t.pos.Index:])
	switch r {
	case '(':
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeLeftParen, Value: "("}, nil
	case ')':
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeRightParen, Value: ")"}, nil
	case ',':
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeComma, Value: ","}, nil
	case ';':
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeSemicolon, Value: ";"}, nil
	case '.':
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeDot, Value: "."}, nil
	case '+':
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeOperator, Value: "+"}, nil
	case '-':
		t.pos.AdvanceRune(r, size)
		if t.pos.Index < len(t.input) {
			nxtR, nxtSize := utf8.DecodeRune(t.input[t.pos.Index:])
			if nxtR == '>' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeArrow, Value: "->"}, nil
			}
		}
		return models.Token{Type: models.TokenTypeOperator, Value: "-"}, nil
	case '*':
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeOperator, Value: "*"}, nil
	case '/':
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeOperator, Value: "/"}, nil
	case '=':
		t.pos.AdvanceRune(r, size)
		if t.pos.Index < len(t.input) {
			nxtR, nxtSize := utf8.DecodeRune(t.input[t.pos.Index:])
			if nxtR == '>' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeDoubleArrow, Value: "=>"}, nil
			}
		}
		return models.Token{Type: models.TokenTypeOperator, Value: "="}, nil
	case '<':
		t.pos.AdvanceRune(r, size)
		if t.pos.Index < len(t.input) {
			nxtR, nxtSize := utf8.DecodeRune(t.input[t.pos.Index:])
			if nxtR == '=' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeLessEquals, Value: "<="}, nil
			} else if nxtR == '>' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeNotEquals, Value: "<>"}, nil
			}
		}
		return models.Token{Type: models.TokenTypeLessThan, Value: "<"}, nil
	case '>':
		t.pos.AdvanceRune(r, size)
		if t.pos.Index < len(t.input) {
			nxtR, nxtSize := utf8.DecodeRune(t.input[t.pos.Index:])
			if nxtR == '=' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeGreaterEquals, Value: ">="}, nil
			}
		}
		return models.Token{Type: models.TokenTypeOperator, Value: ">"}, nil
	case '!':
		t.pos.AdvanceRune(r, size)
		if t.pos.Index < len(t.input) {
			nxtR, nxtSize := utf8.DecodeRune(t.input[t.pos.Index:])
			if nxtR == '=' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeNotEquals, Value: "!="}, nil
			}
		}
		return models.Token{Type: models.TokenTypeExclamation, Value: "!"}, nil
	case ':':
		t.pos.AdvanceRune(r, size)
		if t.pos.Index < len(t.input) {
			nxtR, nxtSize := utf8.DecodeRune(t.input[t.pos.Index:])
			if nxtR == ':' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeCast, Value: "::"}, nil
			}
		}
		return models.Token{Type: models.TokenTypeColon, Value: ":"}, nil
	case '%':
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeOperator, Value: "%"}, nil
	case '|':
		t.pos.AdvanceRune(r, size)
		if t.pos.Index < len(t.input) {
			nxtR, nxtSize := utf8.DecodeRune(t.input[t.pos.Index:])
			if nxtR == '|' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeConcat, Value: "||"}, nil
			}
		}
		return models.Token{Type: models.TokenTypePipe, Value: "|"}, nil
	case '\'':
		return t.readQuotedString('\'')
	}

	if isIdentifierStart(r) {
		return t.readIdentifier()
	}

	return models.Token{}, fmt.Errorf("invalid character: %c", r)
}

// toSQLPosition converts an internal Position => a models.Location
func (t *Tokenizer) toSQLPosition(pos Position) models.Location {
	// Find the line containing pos
	line := 1
	lineStart := 0

	// Find the line number using lineStarts
	for i := 0; i < len(t.lineStarts); i++ {
		if t.lineStarts[i] > pos.Index {
			break
		}
		line = i + 1
		lineStart = t.lineStarts[i]
	}

	// Calculate column by counting characters from line start
	column := 0
	for i := lineStart; i < pos.Index && i < len(t.input); i++ {
		if t.input[i] == '\t' {
			column += 4 // Treat tab as 4 spaces
		} else if t.input[i] == ' ' {
			column++
		} else if t.input[i] == '\'' {
			// For string literals, point to the opening quote
			if i < pos.Index-1 {
				column--
			}
			column++
		} else {
			column++
		}
	}

	return models.Location{
		Line:   line,
		Column: column - 2, // Adjust for indentation
	}
}

// getCurrentPosition returns the Location of the tokenizer's current byte index
func (t *Tokenizer) getCurrentPosition() models.Location {
	return t.toSQLPosition(t.pos)
}

// getLocation produces 1-based {Line, Column} for a given byte offset
func (t *Tokenizer) getLocation(pos int) models.Location {
	// Find the line containing pos
	line := 1
	column := 1
	lineStart := 0

	// Find the line number and start of the line
	for i := 0; i < pos && i < len(t.input); i++ {
		if t.input[i] == '\n' {
			line++
			lineStart = i + 1
		}
	}

	// Calculate column as offset from line start
	if pos >= lineStart {
		column = pos - lineStart + 1
	}

	return models.Location{
		Line:   line,
		Column: column,
	}
}

func isIdentifierChar(r rune) bool {
	return isUnicodeIdentifierPart(r)
}
