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

// RowsFromItem is a function and optional record column definitions in ROWS FROM.
type RowsFromItem struct {
	Function *FunctionCall
	Columns  *ColumnAliasList
}

// RowsFromSQL renders a PostgreSQL ROWS FROM table body and its ordinality.
func RowsFromSQL(t *TableReference, kw func(string) string) string {
	if t == nil || t.Modifiers == nil || len(t.Modifiers.RowsFrom) == 0 {
		return ""
	}
	if kw == nil {
		kw = identityKeyword
	}
	var w strings.Builder
	w.WriteString(kw("ROWS FROM"))
	w.WriteString(" (")
	for i, item := range t.Modifiers.RowsFrom {
		if i > 0 {
			w.WriteString(", ")
		}
		w.WriteString(exprSQL(item.Function))
		if item.Columns != nil {
			w.WriteByte(' ')
			w.WriteString(kw("AS"))
			w.WriteString(" (")
			writeColumnAliasEntries(&w, item.Columns, nil)
			w.WriteByte(')')
		}
	}
	w.WriteByte(')')
	if t.WithOrdinality {
		w.WriteByte(' ')
		w.WriteString(kw("WITH ORDINALITY"))
	}
	return w.String()
}
