// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package fingerprint_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/internal/namequote"
	"github.com/ajitpratap0/GoSQLX/pkg/fingerprint"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestSharedNameQuoteParserRendering(t *testing.T) {
	for _, tt := range []struct{ sql, want string }{
		{`SELECT "key", "users", "user" FROM t`, `SELECT "key", users, "user" FROM t`},
	} {
		t.Run(tt.sql, func(t *testing.T) {
			tree, err := gosqlx.Parse(tt.sql)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			if got := tree.SQL(); got != tt.want {
				t.Errorf("SQL()=%q, want %q", got, tt.want)
			}
		})
	}
}

// TestBareNameReTokenizes pins the soundness of the parser's shared quoting
// predicate: every name it renders bare must remain one unchanged identifier.
func TestBareNameReTokenizes(t *testing.T) {
	corpus, err := benchcorpus.Default()
	if err != nil {
		t.Fatal(err)
	}
	words := map[string]bool{"KEY": true, "QUALIFY": true}
	add := func(word string) {
		words[word] = true
		words[strings.ToLower(word)] = true
		words[strings.ToUpper(word)] = true
	}
	for _, list := range [][]keywords.Keyword{keywords.RESERVED_FOR_TABLE_ALIAS, keywords.ADDITIONAL_KEYWORDS} {
		for _, kw := range list {
			add(kw.Word)
		}
	}
	dialects := append([]keywords.SQLDialect{""}, keywords.AllDialects()...)
	for _, d := range dialects {
		for _, kw := range keywords.DialectKeywords(d) {
			add(kw.Word)
		}
	}
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	var rejected int
	for _, st := range corpus.All() {
		// Probe both default tokenization and the statement's own dialect.
		for _, d := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.SQLDialect(st.Dialect)} {
			if st.Dialect == benchcorpus.GenericDialect && d != keywords.DialectPostgreSQL {
				d = keywords.DialectPostgreSQL
			}
			tkz.SetDialect(d)
			tokens, err := tkz.TokenizeString(st.SQL)
			if err != nil {
				rejected++
				continue // Lexically invalid corpus SQL cannot contribute words.
			}
			for _, tw := range tokens {
				tok := tw.Token
				if tok.Type == models.TokenTypeIdentifier || tok.Type == models.TokenTypeDoubleQuotedString || tok.Type.IsKeyword() {
					add(tok.Value)
					if tok.Type.IsKeyword() {
						for _, word := range strings.Fields(tok.Value) {
							add(word)
						}
					}
				}
			}
		}
	}
	sorted := make([]string, 0, len(words))
	for word := range words {
		sorted = append(sorted, word)
	}
	sort.Strings(sorted)
	t.Logf("probing %d words in %d dialects; %d corpus tokenizations rejected", len(sorted), len(dialects), rejected)
	for _, d := range dialects {
		t.Run(string(d), func(t *testing.T) {
			effective := d
			if effective == "" {
				effective = keywords.DialectPostgreSQL
			}
			tkz.SetDialect(effective)
			for _, word := range sorted {
				mustQuote := namequote.MustStayQuoted(word, d)
				// Probe the tokenizer's actual keyword table, never Keywords.IsKeyword.
				if tokenizer.IsKeyword(word) && !mustQuote {
					t.Fatalf("tokenizer keyword %q must stay quoted in dialect %q", word, d)
				}
				tokens, err := tkz.TokenizeString(word)
				if len(tokens) > 0 && tokens[len(tokens)-1].Token.Type == models.TokenTypeEOF {
					tokens = tokens[:len(tokens)-1]
				}
				if !mustQuote && (err != nil || len(tokens) != 1 || tokens[0].Token.Type != models.TokenTypeIdentifier || tokens[0].Token.Value != word) {
					t.Fatalf("bare name soundness counterexample: word=%q dialect=%q error=%v tokens=%+v", word, d, err, tokens)
				}
				if err == nil && len(tokens) == 1 && tokens[0].Token.Type.IsKeyword() && !mustQuote {
					t.Fatalf("keyword-typed bare name must stay quoted: word=%q dialect=%q tokens=%+v", word, d, tokens)
				}
			}
		})
	}
}

// TestNormalizeV2Rules pins the normal form, including negative cases where
// the same spelling has a different structural role.
var normalizeV2RuleCases = []struct {
	name, sql, want string
	dialect         keywords.SQLDialect
}{
	{"N1", "select a from t", "SELECT a FROM t", ""},
	{"N1_identifier", "select Foo from t", "SELECT Foo FROM t", ""},
	{"N2", "select t.key, key from t", "SELECT t.key, KEY FROM t", ""},
	{"N2_right", "select key.x, t.KEY from t", "SELECT key.x, t.KEY FROM t", ""},
	{"N3_bare", `SELECT "users"."id"`, `SELECT users.id`, ""},
	{"N3_case", `SELECT "Users", "select", "a""b"`, `SELECT "Users", "select", "a""b"`, ""},
	{"N3_backtick", "SELECT `my-db`.`t`, `select`", "SELECT `my-db`.t, `select`", keywords.DialectMySQL},
	{"N3_backtick_multiline", "SELECT `a\nb` FROM t", "SELECT `a\nb` FROM t", keywords.DialectMySQL},
	{"N3_bracket", "SELECT [p q], [users]", "SELECT [p q], users", keywords.DialectSQLServer},
	{"N3_upper", `SELECT "USERS", "users"`, `SELECT USERS, "users"`, keywords.DialectSnowflake},
	{"N4", "WHERE a = 1 AND b = 'x' LIMIT 10 OFFSET 20", "WHERE a = ? AND b = ? LIMIT ? OFFSET ?", ""},
	{"N4_double_quote_mysql_email", `WHERE email = "john@example.com"`, "WHERE email = ?", keywords.DialectMySQL},
	{"N4_double_quote_mysql_name", `WHERE name = "alice"`, "WHERE name = ?", keywords.DialectMySQL},
	{"N4_double_quote_mariadb", `WHERE name = "alice"`, "WHERE name = ?", keywords.DialectMariaDB},
	{"N4_double_quote_bigquery", `WHERE name = "alice"`, "WHERE name = ?", keywords.DialectBigQuery},
	{"N3_double_quote_default", `WHERE email = "john@example.com" AND name = "alice"`, `WHERE email = "john@example.com" AND name = alice`, ""},
	{"N3_double_quote_postgres", `WHERE email = "john@example.com" AND name = "alice"`, `WHERE email = "john@example.com" AND name = alice`, keywords.DialectPostgreSQL},
	{"N14_double_quote_mysql", `SELECT date "abc"`, "SELECT DATE ?", keywords.DialectMySQL},
	{"N4b_double_quote_mysql", `SELECT a AS "lbl"`, `SELECT a AS "lbl"`, keywords.DialectMySQL},
	{"N9_double_quote_literal_cast", `SELECT "CAST"(a AS item), "XMLFOREST"(a AS id)`, "SELECT ? (a item), ? (a id)", keywords.DialectMySQL},
	{"N4_utility", "SHOW VARIABLES LIKE 'x'; KILL 1234; SET x = 'a'", "SHOW VARIABLES LIKE ?; KILL ?; SET x = ?", ""},
	{"N4_typed", "SELECT DATE '2020-01-01', $$abc$$, $1", "SELECT DATE ?, ?, $1", keywords.DialectPostgreSQL},
	{"N4a", "CREATE TABLE t (a VARCHAR(255), b DECIMAL(10,2))", "CREATE TABLE t(a VARCHAR(255), b DECIMAL(10, 2))", ""},
	{"N4a_cast", "SELECT CAST(x AS varchar(10)), x::DECIMAL(10,2), f(10)", "SELECT CAST(x AS varchar(10)), x::DECIMAL(10, 2), f(?)", ""},
	{"N4a_not_type", "CREATE TABLE t (a INT DEFAULT f(10 + 2))", "CREATE TABLE t(a INT DEFAULT f(? + ?))", ""},
	{"N4b", "SELECT a AS 'lbl'", "SELECT a AS 'lbl'", keywords.DialectMySQL},
	{"N4b_cast", "SELECT CAST('lbl' AS TEXT)", "SELECT CAST(? AS TEXT)", ""},
	{"N5", "b IS NOT NULL AND c IS TRUE AND d = NULL", "b IS NOT NULL AND c IS TRUE AND d = ?", ""},
	{"N5_ddl", "CREATE TABLE t (a INT NOT NULL DEFAULT NULL, b INT NULL)", "CREATE TABLE t(a INT NOT NULL DEFAULT ?, b INT NULL)", ""},
	{"N5_bool", "SELECT TRUE, FALSE, NULL; x IS NOT FALSE", "SELECT ?, ?, ?; x IS NOT FALSE", ""},
	{"N6", "SELECT $1, ?, : name, @p", "SELECT $1, ?, :name, @p", ""},
	{"N6_at_at_default", "SELECT @@version, @@session.sql_mode", "SELECT @@version, @@session.sql_mode", ""},
	{"N6_at_at_mysql", "SELECT @@version, @@session.sql_mode", "SELECT @@version, @@session.sql_mode", keywords.DialectMySQL},
	{"N6_at_at_mariadb", "SELECT @@version, @@session.sql_mode", "SELECT @@version, @@session.sql_mode", keywords.DialectMariaDB},
	{"N6_colon_unquoted_name", `:"a"`, ":a", keywords.DialectGeneric},
	{"N6_colon_oracle_quoted_name", `:"A"(`, ":A (", keywords.DialectOracle},
	{"N6_literal", "SELECT 1, 'x'", "SELECT ?, ?", ""},
	{"N7_in", "x IN (1, 2, 3) AND y IN (?, ?)", "x IN (?) AND y IN (?)", ""},
	{"N7_distinct", "x IN ($1, $2) AND y IN (SELECT 1, 2 FROM u)", "x IN ($1, $2) AND y IN (SELECT ?, ? FROM u)", ""},
	{"N7_values", "VALUES (1,'a'),(2,'b')", "VALUES (?, ?)", ""},
	{"N7_rows", "VALUES ($1,1),($2,2)", "VALUES ($1, ?), ($2, ?)", ""},
	{"N8", "SELECT * FROM t INNER JOIN u LEFT OUTER JOIN v", "SELECT * FROM t JOIN u LEFT JOIN v", ""},
	{"N8_cross", "SELECT * FROM t CROSS JOIN u RIGHT JOIN v", "SELECT * FROM t CROSS JOIN u RIGHT JOIN v", ""},
	{"N8_inner_outer", "INNER OUTER JOIN", "INNER OUTER JOIN", keywords.DialectSQLServer},
	{"N8_bare_outer", "OUTER JOIN", "OUTER JOIN", keywords.DialectSQLServer},
	{"N8_outer_prefixes", "LEFT OUTER JOIN t RIGHT OUTER JOIN u FULL OUTER JOIN v", "LEFT JOIN t RIGHT JOIN u FULL JOIN v", keywords.DialectSQLServer},
	{"N8_outer_discard", "LEFT OUTER ASC JOIN", "LEFT JOIN", keywords.DialectSQLServer},
	{"N8_outer_inner", "LEFT OUTER INNER JOIN", "LEFT JOIN", keywords.DialectSQLServer},
	{"N8_outer_dotted", "t.left OUTER JOIN", "t.left OUTER JOIN", keywords.DialectSQLServer},
	{"N8_outer_alias", "LEFT AS OUTER JOIN", "LEFT AS OUTER JOIN", keywords.DialectSQLServer},
	{"N9", "SELECT a AS x FROM t AS tt", "SELECT a x FROM t tt", ""},
	{"N9_cte", "WITH c AS (SELECT 1) SELECT * FROM c", "WITH c AS (SELECT ?) SELECT * FROM c", ""},
	{"N9_ddl", "CREATE SEQUENCE s AS bigint", "CREATE SEQUENCE s AS bigint", ""},
	{"N9_with_expr", "WITH 1 AS x SELECT x", "WITH ? AS x SELECT x", keywords.DialectClickHouse},
	{"N10", "SELECT a FROM t ORDER BY a ASC, b DESC", "SELECT a FROM t ORDER BY a, b DESC", ""},
	{"N10_dotted", "SELECT t.asc, t.ASC, asc.x FROM t ORDER BY t.asc ASC", "SELECT t.asc, t.ASC, asc.x FROM t ORDER BY t.asc", ""},
	{"N10_identifier", "SELECT \"asc\" FROM t", "SELECT \"asc\" FROM t", ""},
	{"N11", "SELECT ALL a FROM t UNION ALL SELECT b FROM u", "SELECT a FROM t UNION ALL SELECT b FROM u", ""},
	{"N11_distinct", "SELECT DISTINCT a FROM t", "SELECT DISTINCT a FROM t", ""},
	{"N11_union_all_comments", "select 1 union/* c */all-- c\nselect 2", "SELECT ? UNION ALL SELECT ?", ""},
	{"N11_union_all_lower", "select 1 union all select 2", "SELECT ? UNION ALL SELECT ?", ""},
	{"N11_dotted_all", "select t.all, all.x from t", "SELECT t.all, all.x FROM t", ""},
	{"N11_after_discard", "SELECT ASC ALL ALL a FROM t", "SELECT a FROM t", ""},
	{"N12", "INSERT t VALUES (1); MERGE t AS tgt", "INSERT INTO t VALUES (?); MERGE INTO t tgt", ""},
	{"N12_into", "INSERT INTO t VALUES (1)", "INSERT INTO t VALUES (?)", ""},
	{"N12_after_discard", "INSERT ASC t VALUES (1); MERGE ASC u AS target", "INSERT INTO t VALUES (?); MERGE INTO u AS TARGET", ""},
	{"N12_dotted", "SELECT t.insert foo, t.merge bar FROM t", "SELECT t.insert foo, t.merge bar FROM t", ""},
	{"N13", "SELECT a != 1, b == 2", "SELECT a <> ?, b = ?", ""},
	{"N13_other", "SELECT a <= 1, b >= 2", "SELECT a <= ?, b >= ?", ""},
	{"N14", "SELECT date '2020-01-01', _utf8 'abc'", "SELECT DATE ?, _UTF8 ?", ""},
	{"N14_name", "SELECT date, foo FROM t", "SELECT date, foo FROM t", ""},
	{"N15", "SELECT count (x), a = - 1, - -1", "SELECT COUNT(x), a = -?, - -?", ""},
	{"N15_boolean", "SELECT - TRUE, + FALSE, - NULL", "SELECT -?, +?, -?", ""},
	{"N15_placeholder_binary", "SELECT ? + 1, $1 - 2, (1) + 3, a[1] - 4", "SELECT ? + ?, $1 - ?, (?) + ?, a [?] - ?", ""},
	{"N15_named_unary", "SELECT - :name, + :other", "SELECT -:name, +:other", ""},
	{"N15_binary", "SELECT a - 1, x::int, t.x", "SELECT a - ?, x::int, t.x", ""},
	{"N15_after_discard", "SELECT x ASC - 1", "SELECT x - ?", ""},
	{"N16", ";;SELECT 1; SELECT 2;;", "SELECT ?; SELECT ?", ""},
	{"N16_single", "SELECT 1", "SELECT ?", ""},
	{"N17", "SELECT a ->> 'x'", "SELECT a ->> ?", ""},
	{"N17_brackets", "SELECT a[1]", "SELECT a [?]", ""},
	{"N3_backtick_escape", "SELECT `a``b`", "SELECT `a``b`", keywords.DialectMySQL},
	{"N3_bracket_escape", "SELECT [a]]b]", "SELECT [a]]b]", keywords.DialectSQLServer},
	{"N3_oracle", `SELECT "USERS", "users"`, `SELECT USERS, "users"`, keywords.DialectOracle},
	{"N4_strings", "SELECT N'abc', E'abc', X'AB', B'01', U&'abc', '''abc'''", "SELECT ?, ?, ?, ?, ?, ?", ""},
	{"N4a_standalone", "VARCHAR(255)", "VARCHAR(?)", ""},
	{"N5_unknown", "SELECT a IS unknown, b IS NOT unknown, unknown", "SELECT a IS unknown, b IS NOT unknown, unknown", ""},
	{"N7_with", "x IN (WITH c AS (SELECT 1, 2) SELECT * FROM c)", "x IN (WITH c AS (SELECT ?, ?) SELECT * FROM c)", ""},
	{"N7_table", "x IN (TABLE u)", "x IN (TABLE u)", ""},
	{"N7_values_query", "x IN (VALUES (1, 2), (3, 4))", "x IN (VALUES (?, ?))", ""},
	{"N7_nested", "x IN ((1, 2), (3, 4), ($1, $2))", "x IN ((?, ?), ($1, $2))", ""},
	{"N7_row_interruption", "VALUES (1), foo, (2)", "VALUES (?), foo, (?)", ""},
	{"N9_xmlattributes", "SELECT XMLATTRIBUTES(employee_id AS id, 'label' AS title)", "SELECT XMLATTRIBUTES(employee_id AS id, ? AS title)", keywords.DialectOracle},
	{"N9_xmlforest", "SELECT XMLFOREST(employee_id AS id)", "SELECT XMLFOREST(employee_id AS id)", keywords.DialectOracle},
	{"N9_xml_nested_alias", "SELECT XMLFOREST(f(employee_id AS id) AS title) AS result", "SELECT XMLFOREST(f(employee_id id) AS title) result", keywords.DialectOracle},
	{"N9_xml_quoted", `SELECT "XMLATTRIBUTES"(employee_id AS id), "XMLFOREST"(employee_id AS id), "CAST"(a AS item)`, `SELECT "XMLATTRIBUTES"(employee_id id), "XMLFOREST"(employee_id id), "CAST"(a item)`, ""},
	{"N9_try_cast", "SELECT try_cast(x AS varchar(10)), safe_cast(x AS decimal(10,2))", "SELECT try_cast(x AS varchar(10)), safe_cast(x AS decimal(10, 2))", ""},
	{"N9_after_discard", "SELECT a AS ASC x, b AS AS y", "SELECT a x, b y", ""},
	{"N9_pending_kept", "SELECT a AS ASC 'lbl'; AS", "SELECT a AS ?; AS", ""},
	{"N15_pending_target", "SELECT - ASC 1, + AS x", "SELECT -?, +x", ""},
	{"N15_pending_colon", "SELECT - : ASC name, + : AS name", "SELECT -:name, +:name", ""},
	{"N12_delimited", `INSERT "my table" VALUES (1)`, `INSERT INTO "my table" VALUES (?)`, ""},
	{"N15_colon_guard", "SELECT a : ::int", "SELECT a : ::int", ""},
	{"mysql_comment", "SELECT 1 # x\n FROM t", "SELECT ? FROM t", keywords.DialectMySQL},
}

func TestNormalizeV2Rules(t *testing.T) {
	for _, tc := range normalizeV2RuleCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fingerprint.NormalizeWithOptions(tc.sql, fingerprint.Options{Dialect: tc.dialect})
			if err != nil || got != tc.want {
				t.Fatalf("Normalize(%q)=%q, %v; want %q", tc.sql, got, err, tc.want)
			}
			again, err := fingerprint.NormalizeWithOptions(got, fingerprint.Options{Dialect: tc.dialect})
			if err != nil || again != got {
				t.Errorf("normal form is not idempotent: %q -> %q, %v", got, again, err)
			}
		})
	}
	for _, dialect := range append([]keywords.SQLDialect{""}, keywords.AllDialects()...) {
		for _, tc := range []struct{ sql, want string }{
			{": a", ":a"},
			{":A(", ":A ("},
			{": a 'x'", ":a ?"},
			{"SELECT - : ASC a, + : AS b", "SELECT -:a, +:b"},
			{"CREATE TABLE t (x :a(10))", "CREATE TABLE t(x :a (?))"},
		} {
			t.Run("N6_colon_bind/"+string(dialect)+"/"+tc.sql, func(t *testing.T) {
				opts := fingerprint.Options{Dialect: dialect}
				got, err := fingerprint.NormalizeWithOptions(tc.sql, opts)
				if err != nil || got != tc.want {
					t.Fatalf("Normalize(%q)=%q, %v; want %q", tc.sql, got, err, tc.want)
				}
				again, err := fingerprint.NormalizeWithOptions(got, opts)
				if err != nil || again != got {
					t.Errorf("normal form is not idempotent: %q -> %q, %v", got, again, err)
				}
			})
		}
	}
}

// Deep frames must retain the same AS and type-modifier rules as shallow frames.
func TestNormalizeV2DeepFrames(t *testing.T) {
	for _, depth := range []int{33, 34, 65} {
		for _, tc := range []struct{ sql, want string }{
			{"CAST(a AS varchar(10))", "CAST(a AS varchar(10))"},
			{"XMLATTRIBUTES(a AS id)", "XMLATTRIBUTES(a AS id)"},
			{"XMLFOREST(f(a AS id) AS title)", "XMLFOREST(f(a id) AS title)"},
			{`"CAST"(a AS item)`, `"CAST"(a item)`},
		} {
			prefix, suffix := "SELECT "+strings.Repeat("(", depth), strings.Repeat(")", depth)
			sql, want := prefix+tc.sql+suffix, prefix+tc.want+suffix
			got, err := fingerprint.Normalize(sql)
			if err != nil || got != want {
				t.Fatalf("depth %d: Normalize(%q)=%q, %v; want %q", depth, sql, got, err, want)
			}
			again, err := fingerprint.Normalize(got)
			if err != nil || again != got {
				t.Fatalf("depth %d: normal form is not idempotent: %q -> %q, %v", depth, got, again, err)
			}
		}
	}
}

func TestNormalizeV2PooledDialectReset(t *testing.T) {
	for i := 0; i < 200; i++ {
		for _, tc := range []struct {
			dialect keywords.SQLDialect
			want    string
		}{
			{keywords.DialectMySQL, "?"},
			{"", `"Users"`},
			{keywords.DialectMariaDB, "?"},
			{keywords.DialectPostgreSQL, `"Users"`},
			{keywords.DialectBigQuery, "?"},
		} {
			got, err := fingerprint.NormalizeWithOptions(`"Users"`, fingerprint.Options{Dialect: tc.dialect})
			if err != nil || got != tc.want {
				t.Fatalf("iteration %d dialect %q: got %q, %v; want %q", i, tc.dialect, got, err, tc.want)
			}
		}
	}
}
