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

package ast_test

import (
	"reflect"
	"sort"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// keywordFieldLiterals cover parser paths for the allow-listed keyword fields
// that the testdata corpus does not reach.
var keywordFieldLiterals = []string{
	"SELECT a FROM t NATURAL JOIN u",
	"SELECT a FROM t NATURAL INNER JOIN u",
	"SELECT a FROM t NATURAL LEFT OUTER JOIN u",
	"SELECT a FROM t NATURAL RIGHT JOIN u",
	"SELECT a FROM t NATURAL FULL JOIN u",
	"SELECT a FROM t CROSS JOIN u",
	"SELECT a FROM t FULL OUTER JOIN u ON t.a = u.a",
	"SELECT a FROM t RIGHT JOIN u ON t.a = u.a",
	"SELECT a FROM t CROSS APPLY (SELECT b FROM u) x",
	"SELECT a FROM t OUTER APPLY (SELECT b FROM u) x",
	"SELECT a FROM t GLOBAL ANY LEFT JOIN u ON t.a = u.a",
	"DROP TABLE t", "DROP VIEW v", "DROP MATERIALIZED VIEW v", "DROP INDEX i",
	"SELECT FIRST_VALUE(x) IGNORE NULLS OVER (ORDER BY y) FROM t",
	"SELECT LAG(x) RESPECT NULLS OVER (ORDER BY y) FROM t",
	"SHOW TABLES", "SHOW TABLES FROM db", "SHOW DATABASES", "SHOW CREATE TABLE t", "SHOW CREATE VIEW v",
	"SHOW COLUMNS FROM t", "SHOW INDEX FROM t", "SHOW INDEXES FROM t", "SHOW KEYS FROM t",
	"SHOW STATUS", "SHOW VARIABLES", "SHOW PROCESSLIST", "SHOW GRANTS", "SHOW WARNINGS",
	"SELECT a FROM t UNION SELECT b FROM u", "SELECT a FROM t union all SELECT b FROM u",
	"SELECT a FROM t EXCEPT SELECT b FROM u", "SELECT a FROM t INTERSECT SELECT b FROM u",
	"SELECT a FROM t MINUS SELECT b FROM u",
	"MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET a = s.a WHEN NOT MATCHED THEN INSERT (id) VALUES (s.id)",
	"MERGE INTO t USING s ON t.id = s.id WHEN NOT MATCHED BY SOURCE THEN DELETE",
	"CREATE TABLE t (a INT NOT NULL, b INT NULL, c INT UNIQUE, d INT PRIMARY KEY, e INT DEFAULT 1, f INT CHECK (f > 0), g INT REFERENCES r (x), h INT AUTO_INCREMENT)",
	"CREATE TABLE t (a INT, PRIMARY KEY (a), UNIQUE (a), FOREIGN KEY (a) REFERENCES r (x), CHECK (a > 0))",
	"CREATE TABLE t (a INT) PARTITION BY RANGE (a)", "CREATE TABLE t (a INT) PARTITION BY LIST (a)",
	"CREATE TABLE t (a INT) PARTITION BY HASH (a)",
	"CREATE TABLE t (a INT) ENGINE = InnoDB CHARSET = utf8mb4 COLLATE = utf8mb4_bin COMMENT = 'x'",
	"CREATE TABLE t (a INT) engine = InnoDB",
	"CREATE VIEW v AS SELECT a FROM t WITH CHECK OPTION",
	"CREATE VIEW v AS SELECT a FROM t WITH CASCADED CHECK OPTION",
	"CREATE VIEW v AS SELECT a FROM t WITH LOCAL CHECK OPTION",
	"SELECT a FROM t WHERE a LIKE 'x' AND b NOT LIKE 'y' OR c ILIKE 'z' AND d NOT ILIKE 'w'",
	"SELECT a FROM t WHERE a like any ('x', 'y') AND b ILIKE ALL ('z')",
	"SELECT a FROM t WHERE a REGEXP 'x' OR b RLIKE 'y' OR c NOT REGEXP 'z'",
	"SELECT a FROM t WHERE a IS NULL OR b IS NOT NULL",
	"SELECT a FROM t WHERE NOT EXISTS (SELECT 1 FROM u)",
	"SELECT a FROM t WHERE MATCH(a) AGAINST ('x')",
	"SELECT a FROM t WHERE a = ANY (SELECT b FROM u) AND a > ALL (SELECT b FROM u)",
	"SELECT a FROM t START WITH a = 1 CONNECT BY PRIOR id = parent AND a = 1 OR b = 2",
	"SELECT a % b, a / b, a * b, a - b, a + b, a || b, a <> b, a != b, a <= b, a >= b FROM t",
	"SELECT d -> 'k', d ->> 'k', d #> '{a}', d #>> '{a}', d @> '{}', d <@ '{}', d ? 'k', d ?| ARRAY['k'], d ?& ARRAY['k'], d #- '{a}' FROM t",
	"SELECT a FROM t WHERE a ~ 'x' OR a ~* 'x' OR a !~ 'x' OR a !~* 'x'",
}

// intervalQualifierLiterals returns INTERVAL literals for every unit the
// parser accepts and every "<unit> TO <unit>" combination, so the qualifier
// allow-list is checked against the parser's own unit tables.
func intervalQualifierLiterals() []string {
	units := []string{
		"YEAR", "MONTH", "DAY", "HOUR", "MINUTE", "SECOND", "WEEK", "QUARTER",
		"MICROSECOND", "MILLISECOND", "SECOND_MICROSECOND", "MINUTE_MICROSECOND",
		"MINUTE_SECOND", "HOUR_MICROSECOND", "HOUR_SECOND", "HOUR_MINUTE",
		"DAY_MICROSECOND", "DAY_SECOND", "DAY_MINUTE", "DAY_HOUR", "YEAR_MONTH",
		"DAYS", "MILLENNIUM", "EPOCH", "DECADE", "CENTURY", "NANOSECOND", "TIMEZONE",
	}
	var out []string
	for _, u := range units {
		out = append(out, "SELECT INTERVAL '1' "+u, "SELECT INTERVAL '1' "+u+" FROM t")
		for _, e := range units {
			out = append(out, "SELECT INTERVAL '1' "+u+" TO "+e)
		}
	}
	return out
}

// keywordFieldGates maps each allow-listed keyword field to whether the
// renderers write a given value of it unchanged: the explicit cases of the
// renderer switches plus the field's allow-list.
var keywordFieldGates = map[string]func(string) bool{
	"JoinClause.Type":              func(v string) bool { return ast.JoinTypeText(v) == v },
	"DropStatement.ObjectType":     func(v string) bool { return ast.DropObjectTypeText(v) == v },
	"FunctionCall.NullTreatment":   func(v string) bool { return v == "" || ast.NullTreatmentText(v) == v },
	"IntervalExpression.Qualifier": func(v string) bool { return v == "" || ast.IntervalQualifierText(v) == v },
	"ShowStatement.ShowType":       func(v string) bool { return v == "" || ast.IsShowTypeText(v) },
	"SetOperation.Operator":        func(v string) bool { return ast.SetOperatorText(v) == v },
	"MergeWhenClause.Type": func(v string) bool {
		return v == "MATCHED" || v == "NOT_MATCHED" || v == "NOT_MATCHED_BY_SOURCE" || ast.MergeWhenText(v) == v
	},
	"MergeAction.ActionType": func(v string) bool {
		return v == "UPDATE" || v == "INSERT" || ast.MergeActionText(v) == v
	},
	"ColumnConstraint.Type": func(v string) bool {
		return v == "DEFAULT" || v == "CHECK" || v == "REFERENCES" || ast.ColumnConstraintText(v) == v
	},
	"TableConstraint.Type": func(v string) bool {
		return v == "PRIMARY KEY" || v == "UNIQUE" || v == "FOREIGN KEY" || v == "CHECK"
	},
	"PartitionBy.Type":               func(v string) bool { return ast.PartitionByText(v) == v },
	"TableOption.Name":               func(v string) bool { return ast.TableOptionNameText(v) == v },
	"CreateViewStatement.WithOption": func(v string) bool { return v == "" || ast.ViewWithOptionText(v) == v },
	"BinaryExpression.Operator":      ast.IsOperatorText,
	"AnyExpression.Operator":         ast.IsOperatorText,
	"AllExpression.Operator":         ast.IsOperatorText,
}

// collectKeywordFields records, for every field named in keywordFieldGates
// and reachable from v, the values it holds.
func collectKeywordFields(v reflect.Value, seen map[uintptr]bool, out map[string]map[string]bool) {
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() || seen[v.Pointer()] {
			return
		}
		seen[v.Pointer()] = true
		collectKeywordFields(v.Elem(), seen, out)
	case reflect.Interface:
		if !v.IsNil() {
			collectKeywordFields(v.Elem(), seen, out)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			collectKeywordFields(v.Index(i), seen, out)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name := t.Name() + "." + f.Name
			if _, ok := keywordFieldGates[name]; ok && v.Field(i).Kind() == reflect.String {
				if out[name] == nil {
					out[name] = map[string]bool{}
				}
				out[name][v.Field(i).String()] = true
			}
			collectKeywordFields(v.Field(i), seen, out)
		}
	}
}

// TestKeywordAllowListsCoverParserValues_PR632 parses testdata/**/*.sql, the
// parser testdata and keywordFieldLiterals in every dialect and checks that
// every value the parser stores in an allow-listed keyword field is written
// unchanged by the renderers, so the allow-lists never alter parsed SQL.
func TestKeywordAllowListsCoverParserValues_PR632(t *testing.T) {
	dialects := []keywords.SQLDialect{
		keywords.DialectGeneric, keywords.DialectPostgreSQL, keywords.DialectMySQL,
		keywords.DialectMariaDB, keywords.DialectSQLServer, keywords.DialectOracle,
		keywords.DialectSnowflake, keywords.DialectClickHouse, keywords.DialectSQLite,
	}
	srcs := append(dataTypeCorpus(t), keywordFieldLiterals...)
	srcs = append(srcs, intervalQualifierLiterals()...)
	values := map[string]map[string]bool{}
	for _, src := range srcs {
		for _, d := range dialects {
			tree, err := gosqlx.ParseWithDialect(src, d)
			if err != nil {
				continue
			}
			collectKeywordFields(reflect.ValueOf(tree), map[uintptr]bool{}, values)
			ast.ReleaseAST(tree)
		}
	}
	names := make([]string, 0, len(keywordFieldGates))
	for name := range keywordFieldGates {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if len(values[name]) == 0 {
			t.Errorf("no parsed value reached %s; is the corpus path right?", name)
			continue
		}
		for v := range values[name] {
			if !keywordFieldGates[name](v) {
				t.Errorf("the parser stores %s = %q, which the renderers would not write unchanged", name, v)
			}
		}
	}
	// The interval literals must reach both qualifier forms.
	for _, q := range []string{"YEAR_MONTH", "DAY TO SECOND", "HOUR TO MINUTE", "MICROSECOND"} {
		if !values["IntervalExpression.Qualifier"][q] {
			t.Errorf("the parser did not store interval qualifier %q; update intervalQualifierLiterals", q)
		}
	}
}
