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
	"sort"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// renderAlterOther renders ALTER ROLE, ALTER POLICY and ALTER CONNECTOR. It
// returns "" when the statement has no operation of the matching kind, so the
// caller can fall back to its previous output.
func renderAlterOther(a *ast.AlterStatement, opts ast.FormatOptions) string {
	f := newNodeFormatter(opts)
	switch op := a.Operation.(type) {
	case *ast.AlterRoleOperation:
		if a.Type != ast.AlterTypeRole || op == nil {
			return ""
		}
		f.sb.WriteString(f.kw("ALTER ROLE"))
		f.sb.WriteString(" ")
		f.sb.WriteString(ast.QuoteColumnName(a.Name))
		f.sb.WriteString(f.clauseSep())
		writeAlterRoleOperation(f, op)
	case *ast.AlterPolicyOperation:
		if a.Type != ast.AlterTypePolicy || op == nil {
			return ""
		}
		f.sb.WriteString(f.kw("ALTER POLICY"))
		f.sb.WriteString(" ")
		f.sb.WriteString(ast.QuoteColumnName(a.Name))
		f.sb.WriteString(" ")
		f.sb.WriteString(f.kw("ON"))
		f.sb.WriteString(" ")
		f.sb.WriteString(ast.QuoteQualifiedName(op.Table))
		f.sb.WriteString(f.clauseSep())
		writeAlterPolicyOperation(f, op)
	case *ast.AlterConnectorOperation:
		if a.Type != ast.AlterTypeConnector || op == nil {
			return ""
		}
		f.sb.WriteString(f.kw("ALTER CONNECTOR"))
		f.sb.WriteString(" ")
		f.sb.WriteString(ast.QuoteColumnName(a.Name))
		f.sb.WriteString(f.clauseSep())
		writeAlterConnectorOperation(f, op)
	default:
		return ""
	}
	if opts.AddSemicolon {
		f.sb.WriteString(";")
	}
	return f.result()
}

// writeAlterRoleOperation renders the action of ALTER ROLE.
func writeAlterRoleOperation(f *nodeFormatter, op *ast.AlterRoleOperation) {
	sb := f.sb
	switch op.Type {
	case ast.RenameRole:
		sb.WriteString(f.kw("RENAME TO"))
		sb.WriteString(" ")
		sb.WriteString(ast.QuoteColumnName(op.NewName))
	case ast.AddMember:
		sb.WriteString(f.kw("ADD MEMBER"))
		sb.WriteString(" ")
		sb.WriteString(ast.QuoteColumnName(op.MemberName))
	case ast.DropMember:
		sb.WriteString(f.kw("DROP MEMBER"))
		sb.WriteString(" ")
		sb.WriteString(ast.QuoteColumnName(op.MemberName))
	case ast.SetConfig:
		sb.WriteString(f.kw("SET"))
		sb.WriteString(" ")
		sb.WriteString(ast.QuoteColumnName(op.ConfigName))
		if op.ConfigValue != nil {
			sb.WriteString(" ")
			sb.WriteString(f.kw("TO"))
			sb.WriteString(" ")
			sb.WriteString(exprSQL(op.ConfigValue))
		}
	case ast.ResetConfig:
		sb.WriteString(f.kw("RESET"))
		sb.WriteString(" ")
		if op.ConfigName == "ALL" {
			sb.WriteString(f.kw("ALL"))
		} else {
			sb.WriteString(ast.QuoteColumnName(op.ConfigName))
		}
	case ast.WithOptions:
		sb.WriteString(f.kw("WITH"))
		for i := range op.Options {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(" ")
			sb.WriteString(roleOptionSQL(f, &op.Options[i]))
		}
	}
}

// roleOptionSQL renders one role option; the value of PASSWORD and VALID
// UNTIL is an expression rendered as SQL.
func roleOptionSQL(f *nodeFormatter, opt *ast.RoleOption) string {
	switch opt.Type {
	case ast.Password:
		if e, ok := opt.Value.(ast.Expression); ok && e != nil {
			return f.kw("PASSWORD") + " " + exprSQL(e)
		}
		return f.kw("PASSWORD NULL")
	case ast.ValidUntil:
		if e, ok := opt.Value.(ast.Expression); ok && e != nil {
			return f.kw("VALID UNTIL") + " " + exprSQL(e)
		}
		return f.kw("VALID UNTIL")
	}
	return f.kw(opt.String())
}

// writeAlterPolicyOperation renders the action of ALTER POLICY.
func writeAlterPolicyOperation(f *nodeFormatter, op *ast.AlterPolicyOperation) {
	sb := f.sb
	if op.Type == ast.RenamePolicy {
		sb.WriteString(f.kw("RENAME TO"))
		sb.WriteString(" ")
		sb.WriteString(ast.QuoteColumnName(op.NewName))
		return
	}
	var parts []string
	if len(op.To) > 0 {
		names := make([]string, len(op.To))
		for i, n := range op.To {
			names[i] = ast.QuoteColumnName(n)
		}
		parts = append(parts, f.kw("TO")+" "+strings.Join(names, ", "))
	}
	if op.Using != nil {
		parts = append(parts, f.kw("USING")+" ("+exprSQL(op.Using)+")")
	}
	if op.WithCheck != nil {
		parts = append(parts, f.kw("WITH CHECK")+" ("+exprSQL(op.WithCheck)+")")
	}
	sb.WriteString(strings.Join(parts, f.clauseSep()))
}

// writeAlterConnectorOperation renders the action of ALTER CONNECTOR.
func writeAlterConnectorOperation(f *nodeFormatter, op *ast.AlterConnectorOperation) {
	sb := f.sb
	sb.WriteString(f.kw("SET"))
	sb.WriteString(" ")
	switch {
	case op.Properties != nil:
		keys := make([]string, 0, len(op.Properties))
		for k := range op.Properties {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sb.WriteString(f.kw("DCPROPERTIES"))
		sb.WriteString(" (")
		for i, k := range keys {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(stringLiteralSQL(k))
			sb.WriteString(" = ")
			sb.WriteString(stringLiteralSQL(op.Properties[k]))
		}
		sb.WriteString(")")
	case op.Owner != nil:
		sb.WriteString(f.kw("OWNER"))
		sb.WriteString(" ")
		if op.Owner.IsUser {
			sb.WriteString(f.kw("USER"))
		} else {
			sb.WriteString(f.kw("ROLE"))
		}
		sb.WriteString(" ")
		sb.WriteString(ast.QuoteColumnName(op.Owner.Name))
	default:
		sb.WriteString(f.kw("URL"))
		sb.WriteString(" ")
		sb.WriteString(stringLiteralSQL(op.URL))
	}
}

// stringLiteralSQL renders s as a single-quoted string literal.
func stringLiteralSQL(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
