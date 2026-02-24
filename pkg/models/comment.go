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
