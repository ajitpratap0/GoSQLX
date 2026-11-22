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

package ast

import "strings"

// SampleExpressionSQL renders a ClickHouse SAMPLE clause from Size /
// OffsetSize, or from the legacy numeric string fields when Size is nil. It
// returns "" when the clause has no valid sampling size (only possible in a
// hand-built AST), so callers never write a bare SAMPLE keyword; an invalid
// offset is likewise omitted rather than written empty.
func SampleExpressionSQL(s *SampleClause, kw func(string) string) string {
	if s == nil {
		return ""
	}
	if kw == nil {
		kw = identityKeyword
	}
	size := sampleLegacyRatio(s.Value, s.Denominator)
	if s.Size != nil {
		size = sampleExpressionRatio(s.Size)
	}
	if size == "" {
		return ""
	}
	result := kw("SAMPLE") + " " + size
	offset := sampleLegacyRatio(s.Offset, s.OffsetDenominator)
	if s.OffsetSize != nil {
		offset = sampleExpressionRatio(s.OffsetSize)
	}
	if offset != "" {
		result += " " + kw("OFFSET") + " " + offset
	}
	return result
}

func sampleLegacyRatio(n, d string) string {
	if !IsPlainNumberText(n) {
		return ""
	}
	if IsPlainNumberText(d) {
		return n + "/" + d
	}
	return n
}

// sampleExpressionRatio accepts only the numeric grammar supported by SAMPLE.
// General expression rendering would permit raw text in hand-built numeric
// LiteralValue nodes, bypassing the checks on the legacy string fields.
func sampleExpressionRatio(e Expression) string {
	if b, ok := e.(*BinaryExpression); ok {
		if b == nil || b.Operator != "/" || b.Not || b.CustomOp != nil ||
			b.PipesOr || b.BitwiseXor || (b.Extras != nil && b.Extras.Escape != nil) {
			return ""
		}
		left, right := sampleNumericLiteral(b.Left), sampleNumericLiteral(b.Right)
		if left == "" || right == "" {
			return ""
		}
		return left + "/" + right
	}
	return sampleNumericLiteral(e)
}

func sampleNumericLiteral(e Expression) string {
	literal, ok := e.(*LiteralValue)
	if !ok || literal == nil {
		return ""
	}
	switch {
	case strings.EqualFold(literal.Type, "int"), strings.EqualFold(literal.Type, "INTEGER"),
		strings.EqualFold(literal.Type, "float"):
		text := literalText(literal.Value)
		if IsPlainNumberText(text) {
			return text
		}
	}
	return ""
}

func releaseSampleClause(s *SampleClause, mode releaseMode) {
	if s == nil {
		return
	}
	releaseExpression(s.Size, mode)
	releaseExpression(s.OffsetSize, mode)
	*s = SampleClause{}
}
