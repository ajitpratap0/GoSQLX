// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"sort"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// JoinASTWithComments places comments using the parser's statement spans.
// stmts contains one rendered part per AST statement, without execute lines.
// Execute lines are inserted here without changing AST statement counts.
// tokens, when available, allow optimizer hints inside statements to be placed.
func JoinASTWithComments(tree *ast.AST, stmts []string, tokens []models.TokenWithSpan, comments []models.Comment, layout CommentLayout) (string, error) {
	if layout.Dialect == "" && len(BatchPositions(tree)) > 0 {
		// The AST already identifies the source's GO lines, including when
		// the caller uses ReadableStyle without repeating the parse dialect.
		layout.Dialect = "sqlserver"
	}
	if tree != nil && len(tokens) > 0 && len(tree.ExecuteSlash) == 0 {
		layout.Starts = StatementPositions(tree)
		layout.Batches = BatchPositions(tree)
		return JoinWithComments(stmts, tokens, comments, layout)
	}
	if tree == nil || len(stmts) != len(tree.Statements) || len(tree.StatementStarts) != len(stmts) || len(tree.StatementEnds) != len(stmts) {
		return JoinWithComments(stmts, tokens, comments, layout)
	}
	parts := make([]string, 0, len(stmts))
	items := make([]item, 0, len(stmts))
	add := func(text string, start, end models.Location, batch, execute bool) {
		first := sort.Search(len(tokens), func(i int) bool { return !before(tokens[i].Start, start) })
		last := sort.Search(len(tokens), func(i int) bool { return !before(tokens[i].Start, end) }) - 1
		items = append(items, item{first: first, last: last, term: -1, batch: batch, execute: execute, start: start, end: end})
		parts = append(parts, text)
	}
	for i, stmt := range tree.Statements {
		_, batch := stmt.(*ast.BatchSeparator)
		add(stmts[i], tree.StatementStarts[i], tree.StatementEnds[i], batch, false)
		if i < len(tree.ExecuteSlash) && tree.ExecuteSlash[i] {
			pos := models.Location{}
			if i < len(tree.ExecuteSlashPositions) {
				pos = tree.ExecuteSlashPositions[i]
			}
			end := pos
			end.Column++
			// ExecuteSlashStatement also keeps the END; of PL/SQL blocks.
			parts[len(parts)-1] = strings.TrimSuffix(ExecuteSlashStatement(stmt, stmts[i]), "\n/")
			add("/", pos, end, true, true)
		}
	}
	// Starts describes AST statements, while items also contains execute lines.
	layout.Starts = nil
	return joinWithCommentItems(parts, tokens, comments, layout, items)
}

func formatASTComments(tree *ast.AST, opts ast.FormatOptions, tokens []models.TokenWithSpan) (string, error) {
	parts := make([]string, len(tree.Statements))
	for i, stmt := range tree.Statements {
		local := opts
		if i < len(tree.ExecuteSlash) && tree.ExecuteSlash[i] {
			local.AddSemicolon = false
		}
		parts[i] = RestoreUnicodeIdentifiers(tree, i, formatStatement(stmt, local), local.Dialect)
		parts[i] = EnsureStatementTerminator(stmt, parts[i], local.AddSemicolon)
	}
	layout := CommentLayout{Dialect: opts.Dialect, Terminator: ";", Gap: "\n", Batches: BatchPositions(tree), Starts: StatementPositions(tree)}
	if opts.AddSemicolon {
		layout.Terminator = ""
	}
	if !opts.NewlinePerClause {
		layout.Gap = " "
	}
	return JoinASTWithComments(tree, parts, tokens, tree.Comments, layout)
}
