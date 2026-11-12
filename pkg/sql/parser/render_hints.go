// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"github.com/ajitpratap0/GoSQLX/internal/renderhint"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func (p *Parser) noteRenderOperator(e ast.Expression) {
	if p.renderHint&renderhint.Operator == 0 && renderhint.OperatorMayRetarget(e) {
		p.renderHint |= renderhint.Operator
	}
}

func (p *Parser) noteRenderDataType(typ string) {
	if p.renderHint&renderhint.DataType == 0 && renderhint.DataTypeMayRestyle(typ) {
		p.renderHint |= renderhint.DataType
	}
}

func (p *Parser) hintBinaryExpression(n *ast.BinaryExpression) *ast.BinaryExpression {
	p.noteRenderOperator(n)
	return n
}
func (p *Parser) hintUnaryExpression(n *ast.UnaryExpression) *ast.UnaryExpression {
	p.noteRenderOperator(n)
	return n
}
func (p *Parser) hintUnicodeEscapeExpression(n *ast.UnicodeEscapeExpression) *ast.UnicodeEscapeExpression {
	p.noteRenderOperator(n)
	return n
}
func (p *Parser) hintObjectLiteral(n *ast.ObjectLiteral) *ast.ObjectLiteral {
	p.noteRenderOperator(n)
	return n
}
func (p *Parser) hintCastExpression(n *ast.CastExpression) *ast.CastExpression {
	p.noteRenderDataType(n.Type)
	return n
}
func (p *Parser) hintColumnDef(n *ast.ColumnDef) *ast.ColumnDef {
	p.noteRenderDataType(n.Type)
	return n
}

// resetRenderHints invalidates previous snapshots, including failed parses.
func (p *Parser) resetRenderHints() {
	p.renderGeneration++
	p.renderMask = 0
	p.renderCount = 0
	p.renderHint = 0
	p.renderValid = false
}

func (p *Parser) appendRenderHint() {
	if p.renderHint != 0 && p.renderCount < 64 {
		p.renderMask |= uint64(1) << p.renderCount
	}
	if p.renderCount != ^uint16(0) {
		p.renderCount++
	}
}

func (p *Parser) renderHintSnapshot(count int, generation uint32) (uint64, bool) {
	if !p.renderValid || p.renderGeneration != generation || uint64(p.renderCount) != uint64(count) {
		return 0, false
	}
	return p.renderMask, true
}

func init() {
	renderhint.ParserGeneration = func(value any) uint32 {
		p, ok := value.(*Parser)
		if !ok || p == nil {
			return 0
		}
		return p.renderGeneration
	}
	renderhint.ParserMask = func(value any, count int, generation uint32) (uint64, bool) {
		p, ok := value.(*Parser)
		if !ok || p == nil {
			return 0, false
		}
		return p.renderHintSnapshot(count, generation)
	}
	renderhint.SourceParse = func(sql, dialect string) (*ast.AST, uint64, bool, error) {
		return parseWithDialectHints(sqlText{s: sql, isString: true}, keywords.SQLDialect(dialect))
	}
}
