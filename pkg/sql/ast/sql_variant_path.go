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
	writeExpr(buf, v.Root)
	for i, seg := range v.Segments {
		if seg.Index != nil {
			buf.WriteByte('[')
			writeExpr(buf, seg.Index)
			buf.WriteByte(']')
			continue
		}
		if i == 0 {
			buf.WriteByte(':')
		} else {
			buf.WriteByte('.')
		}
		writeVariantFieldName(buf, seg.Name)
	}
}

// writeVariantFieldName writes a VARIANT path field name, double-quoting it
// unless it is a non-empty run of letters, digits and '_' that does not start
// with a digit. Reserved words stay bare: the parser accepts keywords as
// path fields.
func writeVariantFieldName(buf *bytes.Buffer, name string) {
	if name != "" && isBareNameChars(name, false) {
		buf.WriteString(name)
		return
	}
	writeQuotedIdentifier(buf, name)
}
