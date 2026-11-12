// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

// Package renderhint connects parser-owned metadata and trusted formatting.
// Hints are used only before the parsed tree reaches user code.
package renderhint

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

const (
	Operator uint8 = 1 << iota
	DataType
)

// Parser hooks are installed by parser. A snapshot is valid only for a
// successful parse of the same generation and statement count.
var (
	ParserGeneration func(any) uint32
	ParserMask       func(any, int, uint32) (uint64, bool)
	SourceParse      func(string, string) (*ast.AST, uint64, bool, error)
)

// Formatter hooks are installed by formatter. Indices >= 64 always walk.
var (
	FormatAST       func(any, uint64, bool, any) (string, error)
	FormatStatement func(any, int, uint64, bool, any) (string, error)
)

// OperatorMayRetarget conservatively screens operators by primitive fields.
// Only known invariant operators are clean; unknown operators stay dirty so
// additions to the exact retarget rules cannot silently bypass the walk.
func OperatorMayRetarget(e ast.Expression) bool {
	switch x := e.(type) {
	case *ast.BinaryExpression:
		if x == nil {
			return false
		}
		if x.Lambda || x.PipesOr {
			return true
		}
		switch x.Operator {
		case "=", "!=", "<>", "<", ">", "<=", ">=", "==",
			"AND", "OR", "XOR", "NOT", "IS", "IS NOT", "IS NULL",
			"IS DISTINCT FROM", "IS NOT DISTINCT FROM", "LIKE", "ILIKE",
			"SIMILAR TO", "REGEXP", "RLIKE", "GLOB", "MATCH", "SOUNDS LIKE":
			return false
		}
		return true
	case *ast.UnaryExpression:
		if x == nil {
			return false
		}
		switch x.Operator {
		case ast.Plus, ast.Minus, ast.Not:
			return false
		}
		return true
	case *ast.UnicodeEscapeExpression:
		return x != nil
	case *ast.ObjectLiteral:
		return x != nil
	}
	return false
}

// DataTypeMayRestyle is the target-independent superset of the exact rules.
func DataTypeMayRestyle(typ string) bool {
	if !strings.ContainsAny(typ, "\"`[") {
		return false
	}
	for _, target := range [...]string{"postgresql", "mysql", "mariadb", "sqlserver", "snowflake", "clickhouse", "sqlite", "oracle", "generic"} {
		if ast.DataTypeNeedsRestyleForDialect(typ, target) {
			return true
		}
	}
	return false
}

// Dirty reports whether a statement requires the exact rewrite scan.
func Dirty(mask uint64, index int) bool {
	return index < 0 || index >= 64 || mask&(uint64(1)<<uint(index)) != 0
}
