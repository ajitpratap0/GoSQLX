// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

// Package batch recognizes SQL Server client batch separators. Callers must
// enable it only for the SQL Server dialect.
package batch

import (
	"strconv"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Count validates a positive decimal GO repeat count without executing it.
func Count(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	for i := range s {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	return n, err == nil && n > 0
}

// IsText reports whether s is a rendered GO or GO followed by a repeat count.
func IsText(s string) bool {
	fields := strings.Fields(s)
	if len(fields) == 0 || !strings.EqualFold(fields[0], "GO") {
		return false
	}
	if len(fields) == 1 {
		return true
	}
	if len(fields) != 2 {
		return false
	}
	_, ok := Count(fields[1])
	return ok
}

// End returns the first token after an unquoted GO [count] on its own line.
// Tokens without source positions cannot describe a client directive.
func End(tokens []models.TokenWithSpan, i int) (int, bool) {
	end, valid, ok := Line(tokens, i)
	return end, ok && valid
}

// Line reports whether the token at index i is an unquoted GO alone on its
// line, optionally followed on that line by one number token: the shape of a
// sqlcmd batch separator. SQL comments are trivia and may follow GO or its
// count, including a block comment spanning multiple lines (see TextEnd).
// end is the index of the first token after the line
// and valid reports whether the number, if any, is a valid repeat count
// (GO 0 and GO 1.5 have the shape of a separator but an invalid count).
// Tokens without source positions cannot describe a client directive.
func Line(tokens []models.TokenWithSpan, i int) (end int, valid, ok bool) {
	if i < 0 || i >= len(tokens) {
		return 0, false, false
	}
	tok := &tokens[i]
	if tok.Token.Type != models.TokenTypeIdentifier || tok.Token.Quote != 0 ||
		!strings.EqualFold(tok.Token.Value, "GO") || tok.Start.Line == 0 ||
		tok.Start.Line != tok.End.Line || tok.End.Column-tok.Start.Column != 2 ||
		(i > 0 && tokens[i-1].End.Line >= tok.Start.Line) {
		return 0, false, false
	}
	valid = true
	j := i + 1
	if j < len(tokens) && tokens[j].Token.Type == models.TokenTypeNumber && tokens[j].Start.Line == tok.Start.Line {
		_, valid = Count(tokens[j].Token.Value)
		j++
	}
	if j < len(tokens) && tokens[j].Token.Type != models.TokenTypeEOF && tokens[j].Start.Line <= tok.Start.Line {
		return 0, false, false
	}
	return j, valid, true
}
