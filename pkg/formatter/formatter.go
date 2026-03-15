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

// Package formatter provides a public API for formatting and pretty-printing SQL strings.
//
// The formatter parses SQL using the GoSQLX tokenizer and parser, then renders
// the resulting AST back to text using a visitor-based renderer. This approach
// guarantees that output is syntactically valid and consistently styled. The
// package follows the same separation of concerns as go/ast and go/printer:
// AST nodes carry no formatting logic; all rendering is handled here.
//
// # Key Types and Functions
//
// The primary entry point is the Formatter type, configured with Options:
//
//   - Formatter - stateful formatter created with New(Options); call Format(sql) to reformat a query.
//   - Options - controls IndentSize (spaces per level), Uppercase (keyword case), and Compact (single-line output).
//   - FormatString - convenience function for one-shot formatting with default options (2-space indent, lowercase keywords, readable multi-line output).
//   - FormatAST - low-level renderer that accepts a parsed *ast.AST and ast.FormatOptions directly.
//   - FormatStatement / FormatExpression - render individual AST nodes; used by the LSP formatter and linter auto-fix.
//
// # Formatting Styles
//
// Two preset styles from the ast package drive the renderer:
//
//   - ast.ReadableStyle() - multi-line output with uppercase keywords, 2-space indentation, and a trailing semicolon per statement. This is the default style used by Formatter when Compact is false.
//   - ast.CompactStyle() - single-line output with no indentation, suitable for logging or wire transmission.
//
// Custom styles can be built by constructing an ast.FormatOptions value directly
// and calling FormatAST.
//
// # Basic Usage
//
//	import "github.com/ajitpratap0/GoSQLX/pkg/formatter"
//
//	// One-shot formatting with default options
//	out, err := formatter.FormatString("select id,name from users where id=1")
//	// out: "select id, name\nfrom users\nwhere id = 1"
//
//	// Configurable formatting
//	f := formatter.New(formatter.Options{IndentSize: 4, Uppercase: true})
//	out, err := f.Format("select id,name from users where id=1")
//	// out: "SELECT id, name\nFROM users\nWHERE id = 1"
//
//	// Compact single-line output
//	f := formatter.New(formatter.Options{Compact: true, Uppercase: true})
//	out, err := f.Format("SELECT id, name FROM users WHERE id = 1")
//	// out: "SELECT id, name FROM users WHERE id = 1"
//
// # Supported Statement Types
//
// The renderer handles all GoSQLX-supported statement types:
//
//   - DML: SELECT (including CTEs, window functions, set operations), INSERT, UPDATE, DELETE
//   - DDL: CREATE TABLE, CREATE INDEX, CREATE VIEW, CREATE MATERIALIZED VIEW, ALTER TABLE, DROP, TRUNCATE
//   - Advanced: MERGE, REFRESH MATERIALIZED VIEW
//
// # Comment Preservation
//
// Comments captured by the tokenizer are attached to the AST and re-emitted
// by FormatAST. Leading (non-inline) comments appear before the query; inline
// comments are appended after the last statement.
//
// # Backward Compatibility
//
// Importing this package automatically wires the visitor-based renderer into
// the ast package's FormatStatementFunc, FormatExpressionFunc, and FormatASTFunc
// variables via an init() function in compat.go. This allows deprecated
// Format(FormatOptions) methods on AST nodes to delegate here without creating
// an import cycle. Callers that import only pkg/sql/ast receive a fallback
// SQL() string output from those deprecated shims.
//
// # Object Pool Usage
//
// Format internally uses the GoSQLX tokenizer and parser object pools for
// efficient memory reuse. The Formatter type is safe for reuse but not for
// concurrent use from multiple goroutines; create one Formatter per goroutine
// or protect shared access with a mutex.
package formatter

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Options configures SQL formatting behaviour.
type Options struct {
	IndentSize int  // spaces per indent level (default 2)
	Uppercase  bool // uppercase SQL keywords
	Compact    bool // single-line output
}

// Formatter formats SQL strings.
type Formatter struct {
	opts Options
}

// New creates a Formatter with the given options.
func New(opts Options) *Formatter {
	if opts.IndentSize <= 0 {
		opts.IndentSize = 2
	}
	return &Formatter{opts: opts}
}

// Format parses and re-formats a SQL string.
func (f *Formatter) Format(sql string) (string, error) {
	if strings.TrimSpace(sql) == "" {
		return "", nil
	}

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return "", fmt.Errorf("tokenization failed: %w", err)
	}

	if len(tokens) == 0 {
		return "", nil
	}

	// Capture comments from tokenizer before parsing
	comments := tkz.Comments

	p := parser.GetParser()
	defer parser.PutParser(p)
	parsedAST, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		return "", fmt.Errorf("parsing failed: %w", err)
	}
	defer ast.ReleaseAST(parsedAST)

	// Attach captured comments to AST
	if len(comments) > 0 {
		parsedAST.Comments = make([]models.Comment, len(comments))
		copy(parsedAST.Comments, comments)
	}

	// Build format options and delegate to the visitor-based renderer.
	style := ast.ReadableStyle()
	if f.opts.Compact {
		style = ast.CompactStyle()
	}
	if f.opts.IndentSize > 0 {
		style.IndentWidth = f.opts.IndentSize
	}
	if f.opts.Uppercase {
		style.KeywordCase = ast.KeywordUpper
	}

	return FormatAST(parsedAST, style), nil
}

// FormatString is a convenience function that formats SQL with default options.
func FormatString(sql string) (string, error) {
	return New(Options{}).Format(sql)
}
