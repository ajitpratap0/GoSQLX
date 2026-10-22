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

// render_query_ext.go renders the query-expression parts that the formatter
// used to drop: CTE MATERIALIZED / NOT MATERIALIZED, ClickHouse scalar CTEs,
// and the table-factor modifiers of a FROM item.

package formatter

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// cteSQL renders one common table expression of a WITH clause.
func cteSQL(cte *ast.CommonTableExpr, f *nodeFormatter) string {
	if cte == nil {
		return ""
	}
	var sb strings.Builder
	// ClickHouse scalar CTE: WITH <expr> AS <name>
	if cte.ScalarExpr != nil {
		sb.WriteString(FormatExpression(cte.ScalarExpr, f.opts))
		sb.WriteString(" ")
		sb.WriteString(f.kw("AS"))
		sb.WriteString(" ")
		sb.WriteString(ast.QuoteTableAlias(cte.Name))
		return sb.String()
	}
	sb.WriteString(ast.QuoteTableAlias(cte.Name))
	sb.WriteString(" ")
	if len(cte.Columns) > 0 {
		sb.WriteString("(")
		sb.WriteString(quoteNames(cte.Columns))
		sb.WriteString(") ")
	}
	sb.WriteString(f.kw("AS"))
	sb.WriteString(" ")
	if cte.Materialized != nil {
		if !*cte.Materialized {
			sb.WriteString(f.kw("NOT"))
			sb.WriteString(" ")
		}
		sb.WriteString(f.kw("MATERIALIZED"))
		sb.WriteString(" ")
	}
	sb.WriteString("(")
	sb.WriteString(FormatStatement(cte.Statement, nestedOpts(f.opts)))
	sb.WriteString(")")
	sb.WriteString(ast.CTESearchCycleSQL(cte, f.kw))
	return sb.String()
}
