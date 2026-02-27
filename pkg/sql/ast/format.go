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

// Package ast provides SQL formatting option types shared between the AST and
// the formatter package.
//
// Rendering logic lives in pkg/formatter — AST nodes are pure data structures
// (no Format() methods). This separation mirrors the go/ast + go/printer split.
package ast

// KeywordCase controls how SQL keywords are emitted.
type KeywordCase int

const (
	// KeywordUpper converts keywords to uppercase (SELECT, FROM, WHERE).
	KeywordUpper KeywordCase = iota
	// KeywordLower converts keywords to lowercase (select, from, where).
	KeywordLower
	// KeywordPreserve keeps keywords in their original case.
	KeywordPreserve
)

// IndentStyle controls the indentation character.
type IndentStyle int

const (
	// IndentSpaces uses spaces for indentation.
	IndentSpaces IndentStyle = iota
	// IndentTabs uses tabs for indentation.
	IndentTabs
)

// FormatOptions configures SQL formatting behavior.
type FormatOptions struct {
	// IndentStyle selects spaces or tabs.
	IndentStyle IndentStyle
	// IndentWidth is the number of spaces (or tabs) per indent level.
	IndentWidth int
	// KeywordCase controls keyword casing.
	KeywordCase KeywordCase
	// LineWidth is the target max line width. 0 means no limit (compact).
	LineWidth int
	// NewlinePerClause puts each major clause (FROM, WHERE, etc.) on its own line.
	NewlinePerClause bool
	// AddSemicolon appends a semicolon to each statement.
	AddSemicolon bool
}

// CompactStyle returns formatting options for minimal whitespace output.
func CompactStyle() FormatOptions {
	return FormatOptions{
		IndentStyle:      IndentSpaces,
		IndentWidth:      0,
		KeywordCase:      KeywordPreserve,
		LineWidth:        0,
		NewlinePerClause: false,
		AddSemicolon:     false,
	}
}

// ReadableStyle returns formatting options for human-readable output.
func ReadableStyle() FormatOptions {
	return FormatOptions{
		IndentStyle:      IndentSpaces,
		IndentWidth:      2,
		KeywordCase:      KeywordUpper,
		LineWidth:        80,
		NewlinePerClause: true,
		AddSemicolon:     true,
	}
}

// ─── Backward-compatibility hooks ────────────────────────────────────────────
//
// pkg/formatter registers these hooks via its init() function so that the
// deprecated Format() shim methods below can delegate to the new renderer
// without creating an import cycle (ast ← formatter ← ast is forbidden).
//
// If pkg/formatter is not imported, the shims fall back to SQL() output.

// FormatStatementFunc is set by pkg/formatter.init() to enable deprecated
// Statement.Format() wrappers.
//
// Deprecated: internal bridge — use pkg/formatter.FormatStatement() directly.
var FormatStatementFunc func(Statement, FormatOptions) string

// FormatExpressionFunc is set by pkg/formatter.init() to enable deprecated
// Expression.Format() wrappers.
//
// Deprecated: internal bridge — use pkg/formatter.FormatExpression() directly.
var FormatExpressionFunc func(Expression, FormatOptions) string

// FormatASTFunc is set by pkg/formatter.init() to enable the deprecated
// AST.Format() wrapper.
//
// Deprecated: internal bridge — use pkg/formatter.FormatAST() directly.
var FormatASTFunc func(*AST, FormatOptions) string
