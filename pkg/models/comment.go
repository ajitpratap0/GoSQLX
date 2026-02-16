// Package models provides the Comment type for SQL comment preservation.
package models

// CommentStyle indicates the type of SQL comment.
type CommentStyle int

const (
	// LineComment represents a -- single-line comment.
	LineComment CommentStyle = iota
	// BlockComment represents a /* multi-line */ comment.
	BlockComment
)

// Comment represents a SQL comment captured during tokenization.
type Comment struct {
	Text   string       // The comment text including delimiters (e.g., "-- foo" or "/* bar */")
	Style  CommentStyle // Line or block comment
	Start  Location     // Start position in source
	End    Location     // End position in source
	Inline bool         // True if the comment is on the same line as code (trailing)
}
