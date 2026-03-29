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

package rules

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// PgSerialToIntegerPK rewrites PostgreSQL SERIAL/BIGSERIAL/SMALLSERIAL to
// INTEGER which, when paired with PRIMARY KEY, becomes SQLite's implicit
// auto-increment rowid alias.
//
// PostgreSQL: id SERIAL PRIMARY KEY
// SQLite:     id INTEGER PRIMARY KEY
func PgSerialToIntegerPK(stmt ast.Statement) error {
	ct, ok := stmt.(*ast.CreateTableStatement)
	if !ok {
		return nil
	}
	for i := range ct.Columns {
		col := &ct.Columns[i]
		switch strings.ToUpper(col.Type) {
		case "SERIAL", "SMALLSERIAL", "BIGSERIAL":
			col.Type = "INTEGER"
		}
	}
	return nil
}

// PgArrayToJSON rewrites PostgreSQL array types (e.g. TEXT[], INT[]) to TEXT.
// SQLite has no native array type; storing JSON-encoded arrays as TEXT is the
// conventional workaround.
//
// PostgreSQL: tags TEXT[]
// SQLite:     tags TEXT
func PgArrayToJSON(stmt ast.Statement) error {
	ct, ok := stmt.(*ast.CreateTableStatement)
	if !ok {
		return nil
	}
	for i := range ct.Columns {
		col := &ct.Columns[i]
		if strings.HasSuffix(col.Type, "[]") {
			col.Type = "TEXT"
		}
	}
	return nil
}
