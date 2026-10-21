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

import "bytes"

// SQL returns the composite-field selection, preserving quoted field names
// and the parentheses that distinguish it from a qualified column reference.
func (f *FieldAccessExpression) SQL() string {
	if f == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	f.writeSQL(buf)
	return buf.String()
}

func (f *FieldAccessExpression) writeSQL(buf *bytes.Buffer) {
	if f == nil {
		return
	}
	switch f.Expr.(type) {
	case *ParenthesizedExpression, *SubqueryExpression, *TupleExpression,
		*FieldAccessExpression, *ArraySubscriptExpression, *ArraySliceExpression:
		writeExpr(buf, f.Expr)
	default:
		// Also keep manually constructed nodes valid: f(x).a needs to be
		// written as (f(x)).a, and an operator must bind inside the base.
		buf.WriteByte('(')
		writeExpr(buf, f.Expr)
		buf.WriteByte(')')
	}
	buf.WriteByte('.')
	// Any keyword, reserved or not, is a valid field label after the dot
	// ((a).order), so an unquoted field is quoted only when its characters
	// could not form a bare word; quoting a reserved word here would turn
	// Quoted false into true on a re-parse.
	if f.Quoted || (f.Field != "*" && !isBareNameChars(f.Field, false)) {
		writeQuotedIdentifier(buf, f.Field)
	} else {
		buf.WriteString(f.Field)
	}
}
