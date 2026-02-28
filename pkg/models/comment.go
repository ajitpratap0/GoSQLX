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

// CommentStyle indicates the type of SQL comment syntax used.
//
// There are two styles of SQL comments: single-line comments introduced with --
// and multi-line block comments delimited by /* and */.
//
// Example:
//
//	// Single-line comment
//	-- This is a line comment
//
//	// Multi-line block comment
//	/* This is a
//	   block comment */
type CommentStyle int

const (
	// LineComment represents a -- single-line comment that extends to the end of the line.
	LineComment CommentStyle = iota
	// BlockComment represents a /* multi-line */ comment that can span multiple lines.
	BlockComment
)

// Comment represents a SQL comment captured during tokenization.
//
// Comments are preserved by the tokenizer for use by formatters, LSP servers,
// and other tools that need to maintain the original SQL structure. Both
// single-line (--) and multi-line (/* */) comment styles are supported.
//
// Fields:
//   - Text: Complete comment text including delimiters (e.g., "-- foo" or "/* bar */")
//   - Style: Whether this is a line or block comment
//   - Start: Source position where the comment begins (inclusive, 1-based)
//   - End: Source position where the comment ends (exclusive, 1-based)
//   - Inline: True when the comment appears on the same line as SQL code (trailing comment)
//
// Example:
//
//	// Trailing line comment
//	comment := models.Comment{
//	    Text:   "-- filter active users",
//	    Style:  models.LineComment,
//	    Start:  models.Location{Line: 3, Column: 30},
//	    End:    models.Location{Line: 3, Column: 52},
//	    Inline: true,
//	}
//
//	// Stand-alone block comment
//	comment := models.Comment{
//	    Text:   "/* Returns all active users */",
//	    Style:  models.BlockComment,
//	    Start:  models.Location{Line: 1, Column: 1},
//	    End:    models.Location{Line: 1, Column: 30},
//	    Inline: false,
//	}
type Comment struct {
	// Text is the full comment text including its delimiters.
	// For line comments: includes the leading "--" (e.g., "-- my comment").
	// For block comments: includes "/*" and "*/" delimiters (e.g., "/* my comment */").
	Text string
	// Style indicates whether this is a LineComment (--) or BlockComment (/* */).
	Style CommentStyle
	// Start is the 1-based source location where the comment begins (inclusive).
	Start Location
	// End is the 1-based source location where the comment ends (exclusive).
	End Location
	// Inline is true when the comment appears on the same source line as SQL code,
	// i.e., it is a trailing comment following a statement or clause.
	Inline bool
}
