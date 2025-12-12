package models

// Location represents a position in the source code using 1-based indexing.
//
// Location is used throughout GoSQLX for precise error reporting and IDE integration.
// Both Line and Column use 1-based indexing to match SQL standards and editor conventions.
//
// Fields:
//   - Line: Line number in source code (starts at 1)
//   - Column: Column number within the line (starts at 1)
//
// Example:
//
//	loc := models.Location{Line: 5, Column: 20}
//	// Represents position: line 5, column 20 (5th line, 20th character)
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
//	// Convert to LSP Position (0-based)
//	lspPos := lsp.Position{
//	    Line:      location.Line - 1,      // Convert to 0-based
//	    Character: location.Column - 1,    // Convert to 0-based
//	}
//
// Performance: Location is a lightweight value type (2 ints) that is
// stack-allocated and has no memory overhead.
type Location struct {
	Line   int // Line number (1-based)
	Column int // Column number (1-based)
}

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
