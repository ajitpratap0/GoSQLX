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

// Package formatter provides a public API for formatting SQL strings.
//
// Usage:
//
//	f := formatter.New(formatter.Options{IndentSize: 2, Uppercase: true})
//	formatted, err := f.Format("select id,name from users where id=1")
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

	p := parser.NewParser()
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

	// Use AST's built-in Format method
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

	return parsedAST.Format(style), nil
}

// FormatString is a convenience function that formats SQL with default options.
func FormatString(sql string) (string, error) {
	return New(Options{}).Format(sql)
}
