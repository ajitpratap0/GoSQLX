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

// Package rules contains individual dialect rewrite rules used by the transpiler.
package rules

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// MySQLAutoIncrementToSerial rewrites columns that use the AUTO_INCREMENT
// constraint to use the PostgreSQL SERIAL (or BIGSERIAL) type instead.
//
// MySQL:      id INT AUTO_INCREMENT PRIMARY KEY
// PostgreSQL: id SERIAL PRIMARY KEY
func MySQLAutoIncrementToSerial(stmt ast.Statement) error {
	ct, ok := stmt.(*ast.CreateTableStatement)
	if !ok {
		return nil
	}
	for i := range ct.Columns {
		col := &ct.Columns[i]
		// AUTO_INCREMENT is stored as a boolean flag on ColumnConstraint,
		// but the parser may also emit it as a constraint with Type "AUTO_INCREMENT".
		// Check both representations.
		hasAutoInc := false
		newConstraints := col.Constraints[:0]
		for _, c := range col.Constraints {
			if c.AutoIncrement || strings.EqualFold(c.Type, "AUTO_INCREMENT") {
				hasAutoInc = true
				// Drop this constraint — it will be encoded in the type name.
				continue
			}
			newConstraints = append(newConstraints, c)
		}
		if hasAutoInc {
			col.Constraints = newConstraints
			switch strings.ToUpper(col.Type) {
			case "BIGINT":
				col.Type = "BIGSERIAL"
			default:
				col.Type = "SERIAL"
			}
		}
	}
	return nil
}

// MySQLBacktickToDoubleQuote is a no-op: the GoSQLX tokenizer strips backtick
// quoting and stores raw identifier names in the AST.  The formatter applies
// the correct quoting style for the target dialect.
func MySQLBacktickToDoubleQuote(_ ast.Statement) error {
	return nil
}

// MySQLLimitCommaToOffset is a no-op: the GoSQLX parser already normalises
// MySQL's `LIMIT offset, count` syntax into the AST's Limit / Offset fields,
// which are emitted by the formatter in standard `LIMIT n OFFSET m` form.
func MySQLLimitCommaToOffset(_ ast.Statement) error {
	return nil
}

// MySQLBooleanToPgBool rewrites TINYINT columns (MySQL's conventional boolean
// representation) to BOOLEAN for PostgreSQL.
//
// Only TINYINT with no explicit size argument or TINYINT(1) is rewritten.
//
// MySQL:      active TINYINT(1)  or  active TINYINT
// PostgreSQL: active BOOLEAN
func MySQLBooleanToPgBool(stmt ast.Statement) error {
	ct, ok := stmt.(*ast.CreateTableStatement)
	if !ok {
		return nil
	}
	for i := range ct.Columns {
		col := &ct.Columns[i]
		// ColumnDef.Type is a bare type string like "TINYINT", "TINYINT(1)", etc.
		t := strings.ToUpper(strings.TrimSpace(col.Type))
		if t == "TINYINT" || t == "TINYINT(1)" {
			col.Type = "BOOLEAN"
		}
	}
	return nil
}
