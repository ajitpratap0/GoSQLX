package tokenizer

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Position tracks the scanning cursor position during tokenization.
// It maintains both absolute byte offset and human-readable line/column
// coordinates for precise error reporting and token span tracking.
//
// Coordinate System:
//   - Line: 1-based (first line is line 1)
//   - Column: 1-based (first column is column 1)
//   - Index: 0-based byte offset into input (first byte is index 0)
//   - LastNL: Byte offset of most recent newline (for column calculation)
//
// Zero-Copy Design:
// Position operates on byte indices rather than rune indices for performance.
// UTF-8 decoding happens only when needed during character scanning.
//
// Thread Safety:
// Position is not thread-safe. Each Tokenizer instance should have its own
// Position that is not shared across goroutines.
type Position struct {
	Line   int // Current line number (1-based)
	Index  int // Current byte offset into input (0-based)
	Column int // Current column number (1-based)
	LastNL int // Byte offset of last newline (for efficient column calculation)
}

// NewPosition creates a new Position with the specified line and byte index.
// The column is initialized to 1 (first column).
//
// Parameters:
//   - line: Line number (1-based, typically starts at 1)
//   - index: Byte offset into input (0-based, typically starts at 0)
//
// Returns a Position ready for use in tokenization.
func NewPosition(line, index int) Position {
	return Position{
		Line:   line,
		Index:  index,
		Column: 1,
	}
}

// Location converts this Position to a models.Location using the tokenizer's
// line tracking information for accurate column calculation.
//
// This method uses the tokenizer's lineStarts slice to calculate the exact
// column position, accounting for variable-width UTF-8 characters and tabs.
//
// Returns a models.Location with 1-based line and column numbers.
func (p Position) Location(t *Tokenizer) models.Location {
	return t.getLocation(p.Index)
}

// AdvanceRune moves the position forward by one UTF-8 rune.
// This updates the byte index, line number, and column number appropriately.
//
// Newline Handling: When r is '\n', the line number increments and the
// column resets to 1.
//
// Parameters:
//   - r: The rune being consumed (used to detect newlines)
//   - size: The byte size of the rune in UTF-8 encoding
//
// Performance: O(1) operation, no string allocations.
//
// Example:
//
//	r, size := utf8.DecodeRune(input[pos.Index:])
//	pos.AdvanceRune(r, size)  // Move past this rune
func (p *Position) AdvanceRune(r rune, size int) {
	if size == 0 {
		size = 1 // fallback to single byte
	}

	// Move forward by the rune's size
	p.Index += size

	// Handle newlines
	if r == '\n' {
		p.Line++
		p.LastNL = p.Index
		p.Column = 1
	} else {
		p.Column++
	}
}

// AdvanceN moves the position forward by n bytes and recalculates the line
// and column numbers using the provided line start indices.
//
// This is used when jumping forward in the input (e.g., after skipping a
// comment block) where individual rune tracking would be inefficient.
//
// Parameters:
//   - n: Number of bytes to advance
//   - lineStarts: Slice of byte offsets where each line starts (from tokenizer)
//
// Performance: O(L) where L is the number of lines in lineStarts.
// For typical SQL queries with few lines, this is effectively O(1).
//
// If n <= 0, this is a no-op.
func (p *Position) AdvanceN(n int, lineStarts []int) {
	if n <= 0 {
		return
	}

	// Update index
	p.Index += n

	// Find which line we're on
	for i := len(lineStarts) - 1; i >= 0; i-- {
		if p.Index >= lineStarts[i] {
			p.Line = i + 1
			p.Column = p.Index - lineStarts[i] + 1
			break
		}
	}
}

// Clone creates a copy of this Position.
// The returned Position is independent and can be modified without
// affecting the original.
//
// This is useful when you need to save a position (e.g., for backtracking
// during compound keyword parsing) and then potentially restore it.
//
// Returns a new Position with identical values.
func (p Position) Clone() Position {
	return Position{
		Line:   p.Line,
		Index:  p.Index,
		Column: p.Column,
	}
}
