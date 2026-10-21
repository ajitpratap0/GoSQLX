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

package models

// Location represents a position in the source code using 1-based indexing.
//
// Location is used throughout GoSQLX for precise error reporting and IDE integration.
// Both Line and Column use 1-based indexing to match SQL standards and editor conventions.
//
// Fields:
//   - Line: Line number in source code (starts at 1)
//   - Column: Byte column within the line (starts at 1)
//
// Example:
//
//	loc := models.Location{Line: 5, Column: 20}
//	// Represents line 5, byte column 20: the position 19 bytes after the
//	// start of the 5th line. A multi-byte UTF-8 character before it counts
//	// all of its bytes, so this is not necessarily the 20th character.
//
// Usage in error reporting:
//
//	err := errors.NewError(
//	    errors.ErrCodeUnexpectedToken,
//	    "unexpected token",
//	    models.Location{Line: 1, Column: 15},
//	)
//
// Integration with LSP (Language Server Protocol):
//
// LSP positions are 0-based and, by default, count UTF-16 code units, so the
// line converts directly but the column must be re-measured against the line
// text. Subtracting 1 from Column is only correct for ASCII-only lines:
//
//	lineText := lines[location.Line-1]
//	prefix := lineText[:location.Column-1] // bytes before the position
//	lspPos := lsp.Position{
//	    Line:      location.Line - 1,
//	    Character: len(utf16.Encode([]rune(prefix))),
//	}
//
// Columns produced by the tokenizer count bytes: every byte of the line before
// the position, a tab included, is one column. A token's Start is the location
// of the token itself, not of the whitespace or comments before it.
//
// Performance: Location is a lightweight value type (2 ints) that is
// stack-allocated and has no memory overhead.
type Location struct {
	Line   int // Line number (1-based)
	Column int // Column number (1-based, counted in bytes; a tab is one column)
}

// IsZero reports whether the location is the zero value (i.e., no position information).
// A zero Location has both Line and Column equal to 0.
//
// Example:
//
//	loc := models.Location{}
//	if loc.IsZero() {
//	    // no position info available
//	}
func (l Location) IsZero() bool { return l == (Location{}) }

// Span represents a range in the source code.
//
// Span defines a contiguous region of source code from a Start location
// to an End location. Used for highlighting ranges in error messages,
// LSP diagnostics, and code formatting.
//
// Fields:
//   - Start: Beginning location of the span (inclusive)
//   - End: Ending location of the span (exclusive)
//
// Example:
//
//	span := models.Span{
//	    Start: models.Location{Line: 1, Column: 1},
//	    End:   models.Location{Line: 1, Column: 7},
//	}
//	// Represents "SELECT" token spanning columns 1-6 on line 1
//
// Usage with TokenWithSpan:
//
//	token := models.TokenWithSpan{
//	    Token: models.Token{Type: models.TokenTypeSelect, Value: "SELECT"},
//	    Start: models.Location{Line: 1, Column: 1},
//	    End:   models.Location{Line: 1, Column: 7},
//	}
//
// Helper functions:
//
//	span := models.NewSpan(startLoc, endLoc)  // Create new span
//	emptySpan := models.EmptySpan()            // Create empty span
type Span struct {
	Start Location // Start of the span (inclusive)
	End   Location // End of the span (exclusive)
}

// NewSpan creates a new span from start to end locations.
//
// Parameters:
//   - start: Beginning location (inclusive)
//   - end: Ending location (exclusive)
//
// Returns a Span covering the range [start, end).
//
// Example:
//
//	start := models.Location{Line: 1, Column: 1}
//	end := models.Location{Line: 1, Column: 7}
//	span := models.NewSpan(start, end)
func NewSpan(start, end Location) Span {
	return Span{Start: start, End: end}
}

// EmptySpan returns an empty span with zero values.
//
// Used as a default/placeholder when span information is not available.
//
// Example:
//
//	span := models.EmptySpan()
//	// Equivalent to: Span{Start: Location{}, End: Location{}}
func EmptySpan() Span {
	return Span{}
}
