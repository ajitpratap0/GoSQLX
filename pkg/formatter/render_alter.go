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

package formatter

import (
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// renderAlterStatement renders an *ast.AlterStatement. ALTER TABLE statements
// (every action the parser produces, comma-separated) are rendered in full, as
// are ALTER ROLE, POLICY and CONNECTOR; a statement without an operation is
// the bare ALTER keyword. The clause writers are shared with
// ast.AlterStatement.SQL() (ast.AlterSQL).
func renderAlterStatement(a *ast.AlterStatement, opts ast.FormatOptions) string {
	if a == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	f.sb.WriteString(ast.AlterSQL(a, f.ddlStyle()))
	return f.finishDDL()
}
