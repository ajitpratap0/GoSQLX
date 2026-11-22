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

// RestyleDataTypes changes explicit delimiters in type names under node.
// Callers formatting into another dialect should apply it to a private tree.
func RestyleDataTypes(node Node, style rune) {
	restyleDataTypes(node, func(typ string) string { return RequoteDataType(typ, style) })
}

// RestyleDataTypesForDialect retains delimiters accepted by the target dialect.
// ClickHouse accepts both backticks and double quotes; brackets are translated.
func RestyleDataTypesForDialect(node Node, dialect string) {
	style := rune('"')
	switch strings.ToLower(dialect) {
	case "mysql", "mariadb":
		style = '`'
	case "sqlserver":
		style = '['
	case "clickhouse":
		restyleDataTypes(node, func(typ string) string { return requoteDataType(typ, style, true) })
		return
	}
	RestyleDataTypes(node, style)
}

// DataTypeNeedsRestyleForDialect reports whether restyling an explicit type
// name delimiter would change typ. It skips arrays and string parameters and,
// like RequoteDataType, leaves malformed type spellings alone. It allocates no
// memory and does not modify typ.
func DataTypeNeedsRestyleForDialect(typ, target string) bool {
	if !strings.ContainsAny(typ, "\"`[") {
		return false
	}
	style := byte('"')
	if strings.EqualFold(target, "mysql") || strings.EqualFold(target, "mariadb") {
		style = '`'
	} else if strings.EqualFold(target, "sqlserver") {
		style = '['
	}
	keepANSIAndBacktick := strings.EqualFold(target, "clickhouse")
	changed := false
	for i := 0; i < len(typ); i++ {
		c := typ[i]
		if c == '\'' {
			for i++; i < len(typ); i++ {
				if typ[i] == '\'' {
					if i+1 < len(typ) && typ[i+1] == '\'' {
						i++
						continue
					}
					break
				}
			}
			if i >= len(typ) {
				return false
			}
			continue
		}
		bracketName := c == '[' && (i == 0 || i+1 < len(typ) && typ[i+1] != ']' && (typ[i+1] < '0' || typ[i+1] > '9'))
		if c != '"' && c != '`' && !bracketName {
			continue
		}
		end, ok := skipTypeDelimited(typ, i)
		if !ok {
			return false
		}
		if c != style && !(keepANSIAndBacktick && c != '[') {
			changed = true
		}
		i = end
	}
	return changed
}

func restyleDataTypes(node Node, requote func(string) string) {
	Inspect(node, func(n Node) bool {
		switch v := n.(type) {
		case *CastExpression:
			if !v.TypeAsString {
				v.Type = requote(v.Type)
			}
		case *CreateTableStatement:
			for i := range v.Columns {
				v.Columns[i].Type = requote(v.Columns[i].Type)
			}
		case *CreateMaterializedViewStatement:
			for i := range v.ColumnDefs {
				v.ColumnDefs[i].Type = requote(v.ColumnDefs[i].Type)
			}
		case *AlterStatement:
			ops := v.Operations
			if len(ops) == 0 && v.Operation != nil {
				ops = []AlterOperation{v.Operation}
			}
			for _, op := range ops {
				if col, ok := op.(*AlterTableOperation); ok && col != nil {
					col.DataType = requote(col.DataType)
					if col.ColumnDef != nil {
						col.ColumnDef.Type = requote(col.ColumnDef.Type)
					}
					for _, def := range col.ColumnDefs {
						if def != nil {
							def.Type = requote(def.Type)
						}
					}
				}
			}
		}
		return true
	})
}

// RequoteDataType changes explicit identifier delimiters in a type spelling
// while retaining bare type keywords, parameters, arrays and string arguments.
func RequoteDataType(typ string, style rune) string {
	return requoteDataType(typ, style, false)
}

func requoteDataType(typ string, style rune, keepANSIAndBacktick bool) string {
	if !strings.ContainsAny(typ, "\"`[") {
		return typ
	}
	var out strings.Builder
	for i := 0; i < len(typ); i++ {
		c := typ[i]
		if c == '\'' {
			start := i
			for i++; i < len(typ); i++ {
				if typ[i] == '\'' {
					if i+1 < len(typ) && typ[i+1] == '\'' {
						i++
						continue
					}
					break
				}
			}
			if i >= len(typ) {
				return typ
			}
			out.WriteString(typ[start : i+1])
			continue
		}
		bracketName := c == '[' && (i == 0 || i+1 < len(typ) && typ[i+1] != ']' && (typ[i+1] < '0' || typ[i+1] > '9'))
		if c != '"' && c != '`' && !bracketName {
			out.WriteByte(c)
			continue
		}
		end, ok := skipTypeDelimited(typ, i)
		if !ok {
			return typ
		}
		if keepANSIAndBacktick && c != '[' {
			out.WriteString(typ[i : end+1])
			i = end
			continue
		}
		close := c
		if close == '[' {
			close = ']'
		}
		name := strings.ReplaceAll(typ[i+1:end], string([]byte{close, close}), string(close))
		out.WriteString(QuoteNameWith(name, QuotedName(style)))
		i = end
	}
	return out.String()
}

// skipTypeDelimited also handles SQL Server brackets, which otherwise mark
// array dimensions in a type spelling.
func skipTypeDelimited(s string, i int) (int, bool) {
	if s[i] != '[' {
		return skipDelimited(s, i)
	}
	for j := i + 1; j < len(s); j++ {
		if s[j] == '\\' {
			return 0, false
		}
		if s[j] == ']' {
			if j+1 < len(s) && s[j+1] == ']' {
				j++
				continue
			}
			return j, true
		}
	}
	return 0, false
}
