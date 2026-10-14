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

// writeTableHints writes SQL Server table hints as " WITH (h1, h2)". Hints are
// written verbatim (the parser has already upper-cased them).
func writeTableHints(buf *bytes.Buffer, hints []string) {
	if len(hints) == 0 {
		return
	}
	buf.WriteString(" WITH (")
	for i, h := range hints {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(h)
	}
	buf.WriteByte(')')
}

// writePivotClause writes " PIVOT (agg FOR col IN (v1, v2))". InValues already
// carry their source delimiters (e.g. [Q1]) so they are written verbatim.
func writePivotClause(buf *bytes.Buffer, p *PivotClause) {
	if p == nil {
		return
	}
	buf.WriteString(" PIVOT (")
	writeExpr(buf, p.AggregateFunction)
	buf.WriteString(" FOR ")
	buf.WriteString(p.PivotColumn)
	buf.WriteString(" IN (")
	for i, v := range p.InValues {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(v)
	}
	buf.WriteString("))")
}

// writeUnpivotClause writes " UNPIVOT (val FOR name IN (c1, c2))".
func writeUnpivotClause(buf *bytes.Buffer, u *UnpivotClause) {
	if u == nil {
		return
	}
	buf.WriteString(" UNPIVOT (")
	buf.WriteString(u.ValueColumn)
	buf.WriteString(" FOR ")
	buf.WriteString(u.NameColumn)
	buf.WriteString(" IN (")
	for i, c := range u.InColumns {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(c)
	}
	buf.WriteString("))")
}
