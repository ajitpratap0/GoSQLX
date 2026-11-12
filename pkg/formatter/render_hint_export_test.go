// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"

func NeedsDialectRewriteForTest(n ast.Node, target string) bool {
	return needsDialectRewrite(n, target)
}
