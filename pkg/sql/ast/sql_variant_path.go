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

import (
	"bytes"
	"strings"
)

// SQL returns the SQL representation of a Snowflake VARIANT path such as
// "src:a.b[0].c". The first field follows ':' and later fields follow '.';
// bracket subscripts render as "[expr]". A field name that would not re-parse
// as a bare path element is double-quoted with embedded quotes doubled, so a
// hostile key cannot break out of the path.
func (v *VariantPath) SQL() string {
	if v == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	v.writeSQL(buf)
	return buf.String()
}

func (v *VariantPath) writeSQL(buf *bytes.Buffer) {
	if v == nil {
		return
	}
	// Operator-like roots are parenthesized so the path binds to the whole
	// expression rather than only its last operand. UnaryExpression is
	// deliberately not wrapped: the parser currently attaches the path to the
	// already-unary operand (-src:a parses as Root=-src), and wrapping would
	// turn Snowflake's -(src:a) into (-src):a, which means something else.
	switch v.Root.(type) {
	case *BinaryExpression, *CastExpression,
		*CaseExpression, *BetweenExpression, *InExpression:
		buf.WriteByte('(')
		writeExpr(buf, v.Root)
		buf.WriteByte(')')
	default:
		writeExpr(buf, v.Root)
	}
	colon := false // the ':' introducing the first field has been written
	for _, seg := range v.Segments {
		if seg.Index != nil {
			buf.WriteByte('[')
			writeExpr(buf, seg.Index)
			buf.WriteByte(']')
			continue
		}
		if colon {
			buf.WriteByte('.')
		} else {
			buf.WriteByte(':')
			colon = true
		}
		writeVariantFieldName(buf, seg.Name)
	}
}

// writeVariantFieldName writes a VARIANT path field name, double-quoting it
// unless it is bare-safe: a non-empty run of letters, digits and '_' that does
// not start with a digit and is not a reserved word. The parser accepts only
// words the tokenizer emits as keyword tokens as bare path fields; words with
// their own token type (NULL, FROM, ORDER, KEY, ...) and ANY/SOME are
// rejected, so they are quoted. Snowflake treats path elements as
// case-sensitive whether or not they are quoted, so quoting is always safe.
func writeVariantFieldName(buf *bytes.Buffer, name string) {
	if name != "" && !nameNeedsQuoting(name, false) &&
		!strings.EqualFold(name, "ANY") && !strings.EqualFold(name, "SOME") &&
		!variantQuotedWords[strings.ToUpper(name)] {
		buf.WriteString(name)
		return
	}
	writeQuotedIdentifier(buf, name)
}

// variantQuotedWords lists words that the tokenizer gives their own token type
// (neither identifier nor generic keyword) but that are absent from
// reservedNameWords. The VARIANT path parser rejects them bare, so they are
// always quoted. A brute-force test over every keyword table guards this list.
var variantQuotedWords = map[string]bool{
	"URL": true, "OWNER": true, "POLICY": true, "VALID": true, "UNTIL": true,
	"RESET": true, "MEMBER": true, "CONNECTOR": true, "AUTO_INCREMENT": true,
	"DCPROPERTIES": true, "NOCREATEDB": true, "NOCREATEROLE": true,
	"NOLOGIN": true, "NOSUPERUSER": true,
}
