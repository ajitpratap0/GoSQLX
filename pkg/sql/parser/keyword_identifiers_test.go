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

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// firstColumn returns the first select-list item of a single SELECT.
func utilFirstColumn(t *testing.T, d keywords.SQLDialect, sql string) ast.Expression {
	t.Helper()
	stmt := utilParseOne(t, d, sql)
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		t.Fatalf("%q: got %T, want *ast.SelectStatement", sql, stmt)
	}
	if len(sel.Columns) == 0 {
		t.Fatalf("%q: no select columns", sql)
	}
	return sel.Columns[0]
}

// After AS only a name can follow, so keywords spelled as plain words are
// accepted as select-list aliases; words that start a clause are not.
func TestParser_KeywordAliasAfterAS(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		alias   string
	}{
		{keywords.DialectPostgreSQL, "SELECT a AS share FROM t", "share"},
		{keywords.DialectPostgreSQL, "SELECT a AS filter FROM t", "filter"},
		{keywords.DialectPostgreSQL, "SELECT a AS key FROM t", "key"},
		{keywords.DialectMariaDB, "SELECT a AS next FROM t", "next"},
		{keywords.DialectMariaDB, "SELECT a AS first FROM t", "first"},
		{keywords.DialectMySQL, "SELECT a AS last FROM t", "last"},
		{keywords.DialectSnowflake, "SELECT a AS final FROM t", "final"},
		{keywords.DialectSnowflake, "SELECT a AS index FROM t", "index"},
		{keywords.DialectMySQL, "SELECT 1 AS `exists`", "exists"},
		{keywords.DialectPostgreSQL, "SELECT d AS date FROM t", "date"},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			col := utilFirstColumn(t, tt.dialect, tt.sql)
			ae, ok := col.(*ast.AliasedExpression)
			if !ok {
				t.Fatalf("got %T, want *ast.AliasedExpression", col)
			}
			if ae.Alias != tt.alias {
				t.Errorf("Alias = %q, want %q", ae.Alias, tt.alias)
			}
		})
	}

	for _, sql := range []string{"SELECT a AS FROM t", "SELECT a AS WHERE x = 1", "SELECT a AS UNION SELECT b"} {
		if _, err := ParseWithDialect(sql, keywords.DialectPostgreSQL); err == nil {
			t.Errorf("%q parsed, want an error", sql)
		}
	}
}

// Role-option words (OWNER, URL, MEMBER, ...) are keyword tokens only so the
// role and ALTER statements can match them; as an operand they are names.
func TestParser_KeywordColumnNames(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		name    string
		table   string
	}{
		{keywords.DialectPostgreSQL, "SELECT owner FROM t", "owner", ""},
		{keywords.DialectPostgreSQL, "SELECT t.owner FROM t", "owner", "t"},
		{keywords.DialectMySQL, "SELECT url FROM links", "url", ""},
		{keywords.DialectPostgreSQL, "SELECT member FROM teams WHERE member = 1", "member", ""},
		{keywords.DialectSnowflake, "SELECT policy FROM t", "policy", ""},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			col := utilFirstColumn(t, tt.dialect, tt.sql)
			id, ok := col.(*ast.Identifier)
			if !ok {
				t.Fatalf("got %T, want *ast.Identifier", col)
			}
			if id.Name != tt.name || id.Table != tt.table {
				t.Errorf("name/table = %q/%q, want %q/%q", id.Name, id.Table, tt.name, tt.table)
			}
		})
	}
}

// A delimited identifier is a name, never a keyword: `key`, `from` and
// [Group] parse as identifiers, record their delimiter, and render with it.
func TestParser_DelimitedKeywordIdentifiers(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		name    string
		style   rune
		want    string // Identifier.SQL()
	}{
		{keywords.DialectMySQL, "SELECT `key` FROM t", "key", '`', "`key`"},
		{keywords.DialectMySQL, "SELECT `from` FROM t", "from", '`', "`from`"},
		{keywords.DialectMariaDB, "SELECT `default` FROM t", "default", '`', "`default`"},
		{keywords.DialectMySQL, "SELECT `my col` FROM t", "my col", '`', "`my col`"},
		{keywords.DialectMySQL, "SELECT `users`.`select` FROM users", "select", '`', "users.`select`"},
		{keywords.DialectMySQL, "SELECT `id` FROM t", "id", '`', "id"},
		{keywords.DialectSQLServer, "SELECT [Group] FROM t", "Group", '[', "[Group]"},
		{keywords.DialectSQLServer, "SELECT [Order].[x y] FROM t", "x y", '[', "[Order].[x y]"},
		{keywords.DialectPostgreSQL, `SELECT "select" FROM t`, "select", '"', `"select"`},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			col := utilFirstColumn(t, tt.dialect, tt.sql)
			id, ok := col.(*ast.Identifier)
			if !ok {
				t.Fatalf("got %T, want *ast.Identifier", col)
			}
			if id.Name != tt.name || id.QuoteStyle != tt.style {
				t.Errorf("name/style = %q/%q, want %q/%q", id.Name, id.QuoteStyle, tt.name, tt.style)
			}
			if got := id.SQL(); got != tt.want {
				t.Errorf("SQL() = %s, want %s", got, tt.want)
			}
			// Quoted keeps its meaning: ANSI double quotes only.
			if id.Quoted != (tt.style == '"') {
				t.Errorf("Quoted = %v for style %q", id.Quoted, tt.style)
			}
		})
	}
}

// A delimited identifier may follow a column as an implicit alias.
func TestParser_DelimitedImplicitAlias(t *testing.T) {
	col := utilFirstColumn(t, keywords.DialectMariaDB, "SELECT b `z` FROM t")
	ae, ok := col.(*ast.AliasedExpression)
	if !ok {
		t.Fatalf("got %T, want *ast.AliasedExpression", col)
	}
	if ae.Alias != "z" {
		t.Errorf("Alias = %q, want z", ae.Alias)
	}
}

// SQL Server system variables are names that are never quoted.
func TestParser_SystemVariableNotQuoted(t *testing.T) {
	col := utilFirstColumn(t, keywords.DialectSQLServer, "SELECT @@VERSION")
	id, ok := col.(*ast.Identifier)
	if !ok {
		t.Fatalf("got %T, want *ast.Identifier", col)
	}
	if got := id.SQL(); got != "@@VERSION" {
		t.Errorf("SQL() = %s, want @@VERSION", got)
	}
	// A delimited name that happens to start with @ stays delimited.
	col = utilFirstColumn(t, keywords.DialectSQLServer, "SELECT [@@VERSION] FROM t")
	id, ok = col.(*ast.Identifier)
	if !ok {
		t.Fatalf("got %T, want *ast.Identifier", col)
	}
	if got := id.SQL(); got != "[@@VERSION]" {
		t.Errorf("SQL() = %s, want [@@VERSION]", got)
	}
}
