package models

// Location represents a position in the source code using 1-based indexing.
// Both Line and Column are 1-based to match SQL standards.
type Location struct {
    Line   int
    Column int
}

// Span represents a range in the source code
type Span struct {
    Start Location
    End   Location
}

// NewSpan creates a new span from start to end locations
func NewSpan(start, end Location) Span {
    return Span{Start: start, End: end}
}

// Empty returns an empty span
func EmptySpan() Span {
    return Span{}
}
