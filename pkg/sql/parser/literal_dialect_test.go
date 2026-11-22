// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package parser_test

import (
	"reflect"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

func TestLiteralDialectRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		dialect keywords.SQLDialect
		values  []string
	}{
		{keywords.DialectPostgreSQL, []string{"1_000", "0x1F", "0o17", "0b101", "1_000.000_1", `U&'d\0061t\+000061'`, `U&'d!0061t' UESCAPE '!'`}},
		{keywords.DialectMySQL, []string{"0x1F", "0b101", "1x", "1_000"}},
		{keywords.DialectSQLite, []string{"0x1F", "1_000"}},
		{keywords.DialectClickHouse, []string{"1_000", "0x1F", "0b101"}},
		{keywords.DialectSQLServer, []string{"0x1F"}},
		{keywords.DialectOracle, []string{"0x1F", "1d", "1f", "1.5f", "1e5d", "1.5D"}},
		{keywords.DialectSnowflake, []string{"0xFF"}},
		{keywords.DialectGeneric, []string{"0x1F"}},
	} {
		for _, value := range tc.values {
			t.Run(string(tc.dialect)+"/"+value, func(t *testing.T) {
				sql := "SELECT " + value
				tree, err := parser.ParseWithDialect(sql, tc.dialect)
				if err != nil {
					t.Fatal(err)
				}
				defer ast.ReleaseAST(tree)
				want := sql
				if tc.dialect == keywords.DialectMySQL && (value == "1x" || value == "1_000") {
					want = "SELECT `" + value + "`"
				}
				if got := tree.SQL(); got != want {
					t.Fatalf("got %q want %q", got, want)
				}
				again, err := parser.ParseWithDialect(tree.SQL(), tc.dialect)
				if err != nil {
					t.Fatal(err)
				}
				defer ast.ReleaseAST(again)
				if !reflect.DeepEqual(tree.Statements, again.Statements) {
					t.Fatal("round trip changed tree")
				}
			})
		}
	}
}

func TestLiteralDialectRejectTrailingJunk(t *testing.T) {
	for _, dialect := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectSQLServer, keywords.DialectOracle, keywords.DialectSnowflake, keywords.DialectGeneric} {
		for _, value := range []string{"1x", "1__0", "1_"} {
			tree, err := parser.ParseWithDialect("SELECT "+value, dialect)
			if tree != nil {
				ast.ReleaseAST(tree)
			}
			if err == nil {
				t.Errorf("%s %s: expected error", dialect, value)
			}
		}
	}
}

func TestUnicodeNamesAreIdentifiers(t *testing.T) {
	// U&"..." names decode into quoted identifiers usable wherever a name is;
	// SQL() writes the decoded name (quoted when it needs to be).
	for _, tc := range []struct{ sql, want string }{
		{`SELECT U&"d\0061t".a`, `SELECT dat.a`},
		{`SELECT a FROM U&"t"`, `SELECT a FROM t`},
		{`SELECT a AS U&"x"`, `SELECT a AS x`},
		{`SELECT x U&"y" FROM t`, `SELECT x AS y FROM t`},
		{`SELECT a FROM U&"d\0061t" AS U&"\0041"`, `SELECT a FROM dat "A"`},
		{`SELECT U&"A!0042" UESCAPE '!'`, `SELECT "AB"`},
		{`SELECT U&"a""b"`, `SELECT "a""b"`},
	} {
		tree, err := parser.ParseWithDialect(tc.sql, keywords.DialectPostgreSQL)
		if err != nil {
			t.Errorf("%s: %v", tc.sql, err)
			continue
		}
		got := tree.SQL()
		ast.ReleaseAST(tree)
		if got != tc.want {
			t.Errorf("%s: got %q want %q", tc.sql, got, tc.want)
		}
	}
}

func TestUnicodeEscapeCommentBeforeUESCAPE(t *testing.T) {
	for _, sql := range []string{"SELECT U&'x' /* c */ UESCAPE '!'", "SELECT U&'x' -- c\n UESCAPE '!'"} {
		tree, err := parser.ParseWithDialect(sql, keywords.DialectPostgreSQL)
		if err != nil {
			t.Errorf("%q: %v", sql, err)
			continue
		}
		got := tree.SQL()
		ast.ReleaseAST(tree)
		if got != "SELECT U&'x' UESCAPE '!'" {
			t.Errorf("%q: got %q", sql, got)
		}
	}
}

func TestStorageSizesParse(t *testing.T) {
	// Oracle storage sizes parse wherever Oracle takes a size, in the oracle
	// and generic dialects, and render back unchanged.
	for _, sql := range []string{
		"ALTER DATABASE DATAFILE 'f' RESIZE 100M",
		"CREATE TABLESPACE ts DATAFILE 'f' SIZE 10M MAXSIZE 1G",
		"ALTER DATABASE DATAFILE 'f' AUTOEXTEND ON MAXSIZE 2G",
		"CREATE TABLESPACE ts DATAFILE 'f' SIZE 10M BLOCKSIZE 8K",
		"CREATE PROFILE p LIMIT PRIVATE_SGA 15K",
		"ALTER SYSTEM SET sga_target=2G",
		"CREATE USER u IDENTIFIED BY p QUOTA 1G ON ts",
		"CREATE TABLESPACE ts DATAFILE 'f' SIZE 10M AUTOEXTEND ON NEXT 5M MAXSIZE 1G",
	} {
		for _, dialect := range []keywords.SQLDialect{keywords.DialectOracle, keywords.DialectGeneric} {
			tree, err := parser.ParseWithDialect(sql, dialect)
			if err != nil {
				t.Errorf("%s %s: %v", dialect, sql, err)
				continue
			}
			got := tree.SQL()
			ast.ReleaseAST(tree)
			if got != sql {
				t.Errorf("%s %s: got %q", dialect, sql, got)
			}
		}
	}
}

func TestNumberThenAlias(t *testing.T) {
	for _, tc := range []struct {
		dialect   keywords.SQLDialect
		sql, want string
	}{
		{keywords.DialectMySQL, "SELECT 1.5a, 1.0d, .5x", "SELECT 1.5 AS a, 1.0 AS d, .5 AS x"},
		{keywords.DialectMariaDB, "SELECT 1.5a", "SELECT 1.5 AS a"},
		{keywords.DialectOracle, "SELECT 1FROM dual", "SELECT 1 FROM dual"},
		{keywords.DialectSQLServer, "SELECT 1AS x", "SELECT 1 AS x"},
		{keywords.DialectGeneric, "SELECT * FROM t FETCH FIRST 5ROWS ONLY", "SELECT * FROM t FETCH FIRST 5 ROWS ONLY"},
	} {
		tree, err := parser.ParseWithDialect(tc.sql, tc.dialect)
		if err != nil {
			t.Errorf("%s %s: %v", tc.dialect, tc.sql, err)
			continue
		}
		got := tree.SQL()
		ast.ReleaseAST(tree)
		if got != tc.want {
			t.Errorf("%s %s: got %q want %q", tc.dialect, tc.sql, got, tc.want)
		}
	}
}
