// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// Test-only exports that let the external parser_test package time the stages
// of ParseFromModelTokens (preprocess, then parseTokens) on their own.

// BenchPreprocess runs the pooled preprocess path (tokenBuf reuse) and returns
// the preprocessed token count.
func BenchPreprocess(p *Parser, toks []models.TokenWithSpan) int {
	return len(p.preprocess(toks))
}

// BenchPreprocessOwned returns an owned preprocessed copy of toks.
func BenchPreprocessOwned(toks []models.TokenWithSpan) []models.TokenWithSpan {
	return preprocessTokens(toks)
}

// BenchParseTokens parses an already preprocessed token stream.
func BenchParseTokens(p *Parser, toks []models.TokenWithSpan) (*ast.AST, error) {
	return p.parseTokens(toks)
}

// EOFSentinelClean reports whether p's EOF sentinel is still the zero token.
func EOFSentinelClean(p *Parser) bool { return p.eof == (models.TokenWithSpan{}) }

// CursorRepointed reports whether p holds no pointer into a token slice, i.e.
// currentToken is its own EOF sentinel (the state after Reset or Release).
func CursorRepointed(p *Parser) bool { return p.currentToken == &p.eof && p.tokens == nil }
