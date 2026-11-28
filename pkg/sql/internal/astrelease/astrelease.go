// Copyright 2026 GoSQLX Contributors
// SPDX-License-Identifier: Apache-2.0

// Package astrelease is the internal hook through which pkg/sql/parser tells
// pkg/sql/ast that a tree it just built contains no pooled nodes, so
// ast.ReleaseAST can return the container in O(1) instead of walking the tree.
//
// It exists because the parser and ast packages must not widen the public API
// of ast. The hook is importable only from packages under pkg/sql.
package astrelease

// MarkParserBuilt records on tree (an *ast.AST) that the parser built it and
// drew pooledDraws nodes from the ast pools while doing so. A count of zero
// lets ast.ReleaseAST skip the release walk; a non-zero count leaves the full
// walk in place. It is a no-op until package ast has been initialised, which
// every importer of the parser guarantees.
//
// ast assigns this variable from its init function.
var MarkParserBuilt = func(tree any, pooledDraws int) {}
