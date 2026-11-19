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

package formatter

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// LegacyFormatForScratchTest freezes the public-tokenizer pipeline as a differential oracle.
func LegacyFormatForScratchTest(sql string, opts Options) (string, error) {
	f := New(opts)
	if strings.TrimSpace(sql) == "" {
		return "", nil
	}

	// The dialect selects the tokenizer and parser rules (string escapes,
	// quoting, dialect-only syntax) as well as the rendering. An unknown
	// dialect name is ignored for tokenizing and parsing, as before.
	dialect := keywords.SQLDialect(strings.ToLower(f.opts.Dialect))
	useDialect := dialect != "" && keywords.IsValidDialect(string(dialect))

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	if useDialect {
		tkz.SetDialect(dialect)
	}

	tokens, err := tkz.TokenizeString(sql)
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
	if useDialect {
		p.ApplyOptions(parser.WithDialect(string(dialect)))
	}
	var parsedAST *ast.AST
	if useDialect && dialect == keywords.DialectOracle {
		parsedAST, err = parser.ParseWithDialect(sql, dialect)
	} else {
		parsedAST, err = p.ParseFromModelTokens(tokens)
	}
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
	style.Dialect = f.opts.Dialect

	return formatASTCheckedWithTokens(parsedAST, style, tokens)
}
