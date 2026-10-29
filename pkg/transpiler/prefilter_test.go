// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package transpiler

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func prefilterDialects() []keywords.SQLDialect {
	return []keywords.SQLDialect{keywords.DialectGeneric, keywords.DialectPostgreSQL,
		keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectSQLServer,
		keywords.DialectOracle, keywords.DialectSQLite, keywords.DialectSnowflake,
		keywords.DialectClickHouse}
}

// Compare the exact error text as well as output, including parse failures.
func checkPrefilterEquivalent(t *testing.T, sql string, from, to keywords.SQLDialect) {
	t.Helper()
	got, gotErr := transpile(sql, from, to, true)
	want, wantErr := transpile(sql, from, to, false)
	if got != want || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
		t.Fatalf("%s -> %s, SQL %q: filtered=(%q, %v), unfiltered=(%q, %v)", from, to, sql, got, gotErr, want, wantErr)
	}
}

func TestPrefilterEquivalence(t *testing.T) {
	dialects := prefilterDialects()
	if testing.Short() {
		dialects = []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectSQLite}
	}
	fixed := []string{
		"CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY, flag TINYINT(1))",
		"SELECT a = 1 || b = 2 FROM t", "SELECT a || b FROM t", "SELECT a OR b FROM t",
		"SELECT 'a\\nb'", "SELECT \"x\"", "SELECT $$a\\b$$", "SELECT $tag$a\\b$tag$",
		"SELECT ‘a’", "SELECT «a»", "SELECT E'a\\nb'", "SELECT N'a'", "SELECT X'41'", "SELECT B'01'",
		"SELECT q'[a]'", "SELECT _utf8mb4'a'", "SELECT 'a\x00b'",
		`CREATE TABLE t (v "custom")`, "CREATE TABLE t (v `custom`)", "CREATE TABLE t (v [custom])", "CREATE TABLE t (v INT[])",
		"SELECT 'a\x00b'; SELECT a ^ b", "SELECT a ^ b; SELECT 'a\x00b'",
		"SELECT emp# FROM t", "SELECT 1 -- ' || [\n", "SELECT 1 /* $ || [ */", "SELECT 1; SELECT 'x'", "SELECT (((1)))",
	}
	for _, from := range dialects {
		for _, to := range dialects {
			t.Run(string(from)+"_"+string(to), func(t *testing.T) {
				for _, sql := range fixed {
					checkPrefilterEquivalent(t, sql, from, to)
				}
			})
		}
	}
	files := 0
	err := filepath.WalkDir("../../testdata/realworld", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".sql" {
			return nil
		}
		files++
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Deliberately split exactly on semicolons, including chunks inside quoted
		// strings: malformed fragments also pin equality of parse errors.
		statements := strings.Split(string(data), ";")
		if testing.Short() && len(statements) > 2 {
			statements = statements[:2]
		}
		for _, sql := range statements {
			if strings.TrimSpace(sql) == "" {
				continue
			}
			for _, from := range dialects {
				for _, to := range dialects {
					checkPrefilterEquivalent(t, sql, from, to)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("realworld corpus contained no SQL files")
	}
}

func TestScanSourceStringOpeners(t *testing.T) {
	cases := []struct {
		literal string
		dialect keywords.SQLDialect
		flags   sourceFeatures
	}{
		{"'abc'", keywords.DialectPostgreSQL, sourceFeatures{quote: true}},
		{`"abc"`, keywords.DialectMySQL, sourceFeatures{quote: true, typeDelim: true}},
		{"$$abc$$", keywords.DialectPostgreSQL, sourceFeatures{quote: true}},
		{"$tag$abc$tag$", keywords.DialectPostgreSQL, sourceFeatures{quote: true}},
		{"‘abc’", keywords.DialectPostgreSQL, sourceFeatures{nonASCII: true}},
		{"«abc»", keywords.DialectPostgreSQL, sourceFeatures{nonASCII: true}},
		{"E'abc'", keywords.DialectPostgreSQL, sourceFeatures{quote: true}},
		{"N'abc'", keywords.DialectSQLServer, sourceFeatures{quote: true}},
		{"X'41'", keywords.DialectMySQL, sourceFeatures{quote: true}},
		{"B'01'", keywords.DialectPostgreSQL, sourceFeatures{quote: true}},
		{"q'[abc]'", keywords.DialectOracle, sourceFeatures{quote: true, typeDelim: true}},
		{"_utf8mb4'abc'", keywords.DialectMySQL, sourceFeatures{quote: true}},
	}
	for _, tc := range cases {
		t.Run(tc.literal, func(t *testing.T) {
			sql := "SELECT " + tc.literal
			if got := scanSource(sql); got != tc.flags {
				t.Fatalf("scanSource=%+v, want %+v", got, tc.flags)
			}
			tree, err := parser.ParseWithDialect(sql, tc.dialect)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			found := false
			ast.Inspect(tree, func(n ast.Node) bool {
				if lit, ok := n.(*ast.LiteralValue); ok && lit.Type == "string" {
					found = true
				}
				return true
			})
			if !found {
				// nextToken routes MySQL double quotes to readQuotedIdentifier.
				// Pin that existing parser behavior as well as the conservative
				// quote gate; changing its semantics is outside this optimization.
				if tc.literal != `"abc"` {
					t.Fatal("opener did not produce a string literal")
				}
				identifier := false
				ast.Inspect(tree, func(n ast.Node) bool {
					if _, ok := n.(*ast.Identifier); ok {
						identifier = true
					}
					return true
				})
				if !identifier {
					t.Fatal("MySQL double quotes produced neither identifier nor literal")
				}
			}
			flags := scanSource(sql)
			if !flags.quote && !flags.nonASCII {
				t.Fatal("string literal would skip retargeting")
			}
		})
	}
}

func TestScanSourceTypeDelimiters(t *testing.T) {
	for _, tc := range []struct {
		typ     string
		dialect keywords.SQLDialect
	}{
		{`"t"`, keywords.DialectPostgreSQL}, {"`t`", keywords.DialectMySQL}, {"[t]", keywords.DialectSQLServer}, {"INT[]", keywords.DialectPostgreSQL},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			sql := "CREATE TABLE tbl (v " + tc.typ + ")"
			if !scanSource(sql).typeDelim {
				t.Fatal("quoted or array type would skip restyling")
			}
			tree, err := parser.ParseWithDialect(sql, tc.dialect)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
		})
	}
}

func TestPrefilterPipesTokenAndAST(t *testing.T) {
	tk := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tk)
	for _, from := range prefilterDialects() {
		tk.SetDialect(from)
		for _, op := range []string{"||", "OR", "|"} {
			sql := "SELECT a " + op + " b FROM t"
			toks, err := tk.TokenizeString(sql)
			if err != nil {
				t.Fatal(err)
			}
			concatTokens := 0
			for _, tok := range toks {
				if tok.Token.Type == models.TokenTypeStringConcat {
					concatTokens++
					if tok.Token.Value != "||" {
						t.Fatalf("concat token from %q", tok.Token.Value)
					}
				}
			}
			if (concatTokens == 1) != (op == "||") {
				t.Fatalf("%s %q: %d StringConcat tokens", from, op, concatTokens)
			}
			tree, err := parser.ParseWithDialect(sql, from)
			if err != nil {
				t.Fatal(err)
			}
			matched := false
			ast.Inspect(tree, func(n ast.Node) bool {
				if bin, ok := n.(*ast.BinaryExpression); ok && (bin.PipesOr || bin.Operator == "||") {
					matched = true
				}
				return true
			})
			ast.ReleaseAST(tree)
			if matched != (op == "||") {
				t.Fatalf("%s %q: PipesOr/concat = %v", from, op, matched)
			}
			if matched && !scanSource(sql).pipe {
				t.Fatal("pipe rewrite would be skipped")
			}
		}
	}
}

func TestPrefilterMustRunAndSkip(t *testing.T) {
	cases := []struct {
		sql                     string
		from, to                keywords.SQLDialect
		contains, errorContains string
	}{
		{"SELECT a = 1 || b = 2 FROM t", keywords.DialectMySQL, keywords.DialectPostgreSQL, " OR ", ""},
		{"SELECT a || b FROM t", keywords.DialectPostgreSQL, keywords.DialectMySQL, "CONCAT(", ""},
		{`SELECT 'a\0b'`, keywords.DialectMySQL, keywords.DialectSQLite, "", "control character U+0000"},
		{`CREATE TABLE t (v "custom")`, keywords.DialectPostgreSQL, keywords.DialectSQLServer, "[custom]", ""},
	}
	for _, tc := range cases {
		checkPrefilterEquivalent(t, tc.sql, tc.from, tc.to)
		got, err := Transpile(tc.sql, tc.from, tc.to)
		if tc.errorContains != "" {
			if err == nil || !strings.Contains(err.Error(), tc.errorContains) {
				t.Fatalf("%q: got %q, %v", tc.sql, got, err)
			}
		} else if err != nil || !strings.Contains(got, tc.contains) {
			t.Fatalf("%q: got %q, %v; want %q", tc.sql, got, err, tc.contains)
		}
	}
	for _, sql := range []string{`SELECT 'a\0b'; SELECT a ^ b`, `SELECT a ^ b; SELECT 'a\0b'`} {
		checkPrefilterEquivalent(t, sql, keywords.DialectMySQL, keywords.DialectSQLite)
		_, err := Transpile(sql, keywords.DialectMySQL, keywords.DialectSQLite)
		if err == nil || !strings.Contains(err.Error(), "bitwise XOR operator") {
			t.Fatalf("operator pass must fail before literal pass: %v", err)
		}
	}
	const create = "CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY, flag TINYINT(1))"
	if got := scanSource(create); got != (sourceFeatures{}) {
		t.Fatalf("benchmark input should skip all three optional passes: %+v", got)
	}
	checkPrefilterEquivalent(t, create, keywords.DialectMySQL, keywords.DialectPostgreSQL)
}

func TestRulesForFreshSliceAndBoundedCache(t *testing.T) {
	from, to := keywords.DialectMySQL, keywords.DialectPostgreSQL
	const sql = "SELECT a = 1 || b = 2 FROM t"
	want, err := Transpile(sql, from, to)
	if err != nil {
		t.Fatal(err)
	}
	rs := RulesFor(from, to)
	if len(rs) == 0 {
		t.Fatal("expected registered rules")
	}
	rs[0] = func(ast.Statement) error { return fmt.Errorf("mutated caller slice") }
	got, err := Transpile(sql, from, to)
	if err != nil || got != want {
		t.Fatalf("caller mutation affected Transpile: %q, %v", got, err)
	}
	if len(rulesCache) != 9*9*2 {
		t.Fatalf("cache size = %d, want 162", len(rulesCache))
	}
	for i := 0; i < 32; i++ {
		unknown := keywords.SQLDialect(fmt.Sprintf("unknown-%d", i))
		for _, pipes := range []bool{false, true} {
			for _, pair := range [][2]keywords.SQLDialect{{unknown, to}, {from, unknown}, {unknown, unknown}} {
				cached := rulesForSource(pair[0], pair[1], pipes)
				built := buildRules(pair[0], pair[1], pipes)
				if len(cached) != len(built) {
					t.Fatalf("unknown fallback length = %d, want %d", len(cached), len(built))
				}
				// Execute both independently: row-limit closures must keep per-call state.
				a, e1 := transpile("SELECT a FROM t LIMIT 2", pair[0], pair[1], true)
				b, e2 := transpile("SELECT a FROM t LIMIT 2", pair[0], pair[1], false)
				if a != b || fmt.Sprint(e1) != fmt.Sprint(e2) {
					t.Fatalf("unknown fallback differs: %q %v vs %q %v", a, e1, b, e2)
				}
			}
		}
	}
	if len(rulesCache) != 162 {
		t.Fatalf("unknown dialects grew cache to %d", len(rulesCache))
	}
	for _, from := range prefilterDialects() {
		for _, to := range prefilterDialects() {
			for _, pipes := range []bool{false, true} {
				got, ok := rulesCache[rulesKey{from, to, pipes}]
				if !ok {
					t.Fatalf("missing cache pair %s/%s/%v", from, to, pipes)
				}
				want := buildRules(from, to, pipes)
				if len(got) != len(want) {
					t.Fatal("cached rule list differs")
				}
				for i := range got {
					if reflect.ValueOf(got[i]).Pointer() != reflect.ValueOf(want[i]).Pointer() {
						t.Fatal("cached rule order differs")
					}
				}
			}
		}
	}
}

func TestPrefilterParallelTranspile(t *testing.T) {
	for _, from := range prefilterDialects() {
		for _, to := range prefilterDialects() {
			t.Run(string(from)+"_"+string(to), func(t *testing.T) {
				t.Parallel()
				for i := 0; i < 8; i++ {
					for _, sql := range []string{"SELECT a || b FROM t LIMIT 2", "SELECT 'a\\b' FROM t", "CREATE TABLE t (a INT)"} {
						checkPrefilterEquivalent(t, sql, from, to)
					}
				}
			})
		}
	}
}
