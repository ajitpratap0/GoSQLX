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

package transpiler

import (
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// identifierDelimiter returns the delimiter the target dialect uses for a
// quoted identifier: backticks for MySQL and MariaDB (which read "..." as a
// string unless ANSI_QUOTES is set), brackets for SQL Server (valid whatever
// QUOTED_IDENTIFIER is set to), and ANSI double quotes for PostgreSQL,
// Oracle, SQLite, Snowflake, ClickHouse and generic SQL.
func identifierDelimiter(d keywords.SQLDialect) rune {
	switch d {
	case keywords.DialectMySQL, keywords.DialectMariaDB:
		return '`'
	case keywords.DialectSQLServer:
		return '['
	}
	return '"'
}

// requoteIdentifiers rewrites the delimiters of the quoted names in stmt to
// the target dialect's (see identifierDelimiter), so a MySQL `my col` is not
// carried into PostgreSQL output where backticks are invalid. Oracle bare
// names with '#' (emp#) stay bare only when the target is Oracle too.
func requoteIdentifiers(stmt ast.Statement, from, to keywords.SQLDialect) {
	if from == to {
		return
	}
	ast.SetNameQuoteStyle(stmt, identifierDelimiter(to), to == keywords.DialectOracle)
	ast.RestyleDataTypes(stmt, identifierDelimiter(to))
}
