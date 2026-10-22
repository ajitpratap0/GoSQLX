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

package cmd

import (
	"errors"
	"strings"

	pkgformatter "github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// SQLFormatter renders a parsed AST as SQL text for the format command.
//
// It is a thin adapter over pkg/formatter: every statement is rendered with
// pkgformatter.FormatStatement, so the CLI and the library share a single
// renderer and the CLI has no renderer of its own to fall out of sync (#599).
// Rendering gaps in pkg/formatter are caught, where detectable, by
// verifyFormattedSQL.
type SQLFormatter struct {
	style   ast.FormatOptions
	compact bool
}

// FormatterOptions configures the SQL formatter behavior.
type FormatterOptions struct {
	Indent      string // Indentation unit for readable output: "  " for 2 spaces, "\t" for a tab, etc.
	Compact     bool   // Single-line formatting
	UppercaseKw bool   // Uppercase SQL keywords (lowercase otherwise)
	// AlignColumns is retained for compatibility; it is ignored because the
	// layout now comes from pkg/formatter.
	AlignColumns bool
	Dialect      string // SQL dialect passed to pkg/formatter (empty for the default)
}

// NewSQLFormatter creates a formatter that renders through pkg/formatter with
// options mapped from opts.
func NewSQLFormatter(opts FormatterOptions) *SQLFormatter {
	style := ast.ReadableStyle()
	if opts.Compact {
		style = ast.CompactStyle()
	} else {
		indent := opts.Indent
		if indent == "" {
			indent = "  " // Default to 2 spaces
		}
		if strings.Contains(indent, "\t") {
			style.IndentStyle = ast.IndentTabs
			style.IndentWidth = strings.Count(indent, "\t")
		} else {
			style.IndentWidth = len(indent)
		}
	}
	if opts.UppercaseKw {
		style.KeywordCase = ast.KeywordUpper
	} else {
		style.KeywordCase = ast.KeywordLower
	}
	// Statement separators are added by Format; pkg/formatter's readable
	// semicolons would also be emitted inside subqueries.
	style.AddSemicolon = false
	style.Dialect = opts.Dialect
	return &SQLFormatter{style: style, compact: opts.Compact}
}

// Format renders every statement of astObj, separated by "; " in compact mode
// and ";\n\n" otherwise. No trailing semicolon is added.
func (f *SQLFormatter) Format(astObj *ast.AST) (string, error) {
	stmts, err := f.formatStatements(astObj)
	if err != nil {
		return "", err
	}
	return pkgformatter.JoinWithComments(stmts, nil, nil, f.layout())
}

// FormatWithComments is Format for input that had comments: tokens and
// comments are those of the source text, and the comments are put back around
// the statements they belonged to (see pkgformatter.JoinWithComments).
func (f *SQLFormatter) FormatWithComments(astObj *ast.AST, tokens []models.TokenWithSpan, comments []models.Comment) (string, error) {
	stmts, err := f.formatStatements(astObj)
	if err != nil {
		return "", err
	}
	return pkgformatter.JoinWithComments(stmts, tokens, comments, f.layout())
}

func (f *SQLFormatter) formatStatements(astObj *ast.AST) ([]string, error) {
	if astObj == nil {
		return nil, errors.New("cannot format a nil AST")
	}
	stmts := make([]string, len(astObj.Statements))
	for i, stmt := range astObj.Statements {
		stmts[i] = pkgformatter.FormatStatement(stmt, f.style)
	}
	return stmts, nil
}

func (f *SQLFormatter) layout() pkgformatter.CommentLayout {
	if f.compact {
		return pkgformatter.CommentLayout{Terminator: ";", Gap: " ", Dialect: f.style.Dialect}
	}
	return pkgformatter.CommentLayout{Terminator: ";", Gap: "\n\n", Dialect: f.style.Dialect}
}
