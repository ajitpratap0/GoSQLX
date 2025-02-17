package tokenizer

import (
	"GoSQLX/pkg/models"
)

// Position tracks our scanning cursor with optimized tracking
// - Line is 1-based
// - Index is 0-based
// - Column is 1-based
// - LastNL tracks the last newline for efficient column calculation
type Position struct {
	Line   int
	Index  int
	Column int
	LastNL int // byte offset of last newline
}

// NewPosition builds a Position from raw info
func NewPosition(line, index int) Position {
	return Position{
		Line:   line,
		Index:  index,
		Column: 1,
	}
}

// Location gives the models.Location for this position
func (p Position) Location(t *Tokenizer) models.Location {
	return t.getLocation(p.Index)
}

// Advance moves us forward by the given rune, updating line/col efficiently
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

// AdvanceN moves forward by n bytes
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

// Clone makes a copy of Position
func (p Position) Clone() Position {
	return Position{
		Line:   p.Line,
		Index:  p.Index,
		Column: p.Column,
	}
}
