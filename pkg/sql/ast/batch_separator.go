// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	"strconv"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// BatchSeparator preserves a SQL Server GO client directive between batches.
// RepeatCount is zero when omitted, otherwise the positive repeat count as
// written. Rendering never expands or executes repeated batches.
type BatchSeparator struct {
	RepeatCount int
	Pos         models.Location
}

func (*BatchSeparator) statementNode()       {}
func (*BatchSeparator) TokenLiteral() string { return "GO" }
func (*BatchSeparator) Children() []Node     { return nil }

// SQL returns GO, optionally followed by a positive repeat count. The enclosing
// AST renderer places the directive on its own line without a semicolon.
func (b *BatchSeparator) SQL() string {
	if b == nil {
		return ""
	}
	if b.RepeatCount > 0 {
		return "GO " + strconv.Itoa(b.RepeatCount)
	}
	return "GO"
}
