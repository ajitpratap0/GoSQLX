// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
)

// parseWithSource supplies the original text for SQL*Plus line recognition.
// Other dialects retain their usual preprocessing path. Oracle preprocesses
// directly here so the token-only hook cannot discard a commented slash first.
func (p *Parser) parseWithSource(tokens []models.TokenWithSpan, in sqlText) (*ast.AST, error) {
	if p.DialectTyped() != dialect.Oracle {
		return p.ParseFromModelTokens(tokens)
	}
	clear(p.tokenBuf)
	p.tokenBuf = preprocessTokensInto(p.tokenBuf, tokens)
	p.oracleExecuteLines(in.source())
	return p.parseTokens(p.tokenBuf)
}

// oracleExecuteLines normalizes SQL*Plus execute commands to terminators before
// expression parsing can consume them as division. SQL*Plus requires '/' alone
// on its line: '/ -- comment', '/ /* c */' and '/* c */ /' are SQL, not execute
// commands. ParseWithDialect checks the original line, matching SplitStatements.
// Token-only entry points have only SQL token positions, so they cannot resolve
// comment-only neighbours; positionless streams cannot represent commands at all.
// A slash after ';' remains a marked terminator, not an extra statement (also
// in strict mode). Its spelling lets the parser retain execute-line metadata.
// Only the parser-owned buffer changes, and source lines are scanned once.
func (p *Parser) oracleExecuteLines(source string) {
	if p.DialectTyped() != dialect.Oracle {
		return
	}
	line, offset, n := 1, 0, 0
	for i := range p.tokenBuf {
		t := p.tokenBuf[i]
		alone := t.Token.Type == models.TokenTypeDiv && t.Start.Line > 0 && t.Start.Line == t.End.Line &&
			(i == 0 || p.tokenBuf[i-1].End.Line < t.Start.Line) &&
			(i+1 == len(p.tokenBuf) || p.tokenBuf[i+1].Token.Type == models.TokenTypeEOF || p.tokenBuf[i+1].Start.Line > t.End.Line)
		if alone && source != "" {
			for line < t.Start.Line && offset < len(source) {
				end := strings.IndexByte(source[offset:], '\n')
				if end < 0 {
					offset = len(source)
					break
				}
				offset += end + 1
				line++
			}
			end := strings.IndexByte(source[offset:], '\n')
			if end < 0 {
				end = len(source) - offset
			}
			text := source[offset : offset+end]
			if line == 1 {
				text = strings.TrimPrefix(text, "\xef\xbb\xbf")
			}
			alone = strings.Trim(text, " \t\r") == "/"
		}
		if alone {
			t.Token.Type = models.TokenTypeSemicolon
			t.Token.Value = "/"
		}
		p.tokenBuf[n] = t
		n++
	}
	clear(p.tokenBuf[n:])
	p.tokenBuf = p.tokenBuf[:n]
}

// markExecuteSlash records a normalized execute command without changing the
// statement list. Allocate only for Oracle scripts containing execute lines.
func (p *Parser) markExecuteSlash(result *ast.AST) bool {
	if !p.isType(models.TokenTypeSemicolon) || p.currentToken.Token.Value != "/" || p.DialectTyped() != dialect.Oracle {
		return false
	}
	if len(result.Statements) > 0 {
		if len(result.ExecuteSlash) < len(result.Statements) {
			result.ExecuteSlash = append(result.ExecuteSlash, make([]bool, len(result.Statements)-len(result.ExecuteSlash))...)
			result.ExecuteSlashPositions = append(result.ExecuteSlashPositions, make([]models.Location, len(result.Statements)-len(result.ExecuteSlashPositions))...)
		}
		result.ExecuteSlash[len(result.Statements)-1] = true
		result.ExecuteSlashPositions[len(result.Statements)-1] = p.currentToken.Start
	}
	return true
}
