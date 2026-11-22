// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

// External test package: internal/benchcorpus imports pkg/gosqlx, which
// imports pkg/transpiler, so an in-package import would be a cycle.
package transpiler_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler"
)

// benchDialects is the 9-dialect set the prefilter and differential tests
// iterate (generic plus the eight named dialects), giving 9x9 = 81 ordered
// pairs. It mirrors prefilterDialects in the internal test package.
func benchDialects() []keywords.SQLDialect {
	return []keywords.SQLDialect{keywords.DialectGeneric, keywords.DialectPostgreSQL,
		keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectSQLServer,
		keywords.DialectOracle, keywords.DialectSQLite, keywords.DialectSnowflake,
		keywords.DialectClickHouse}
}

// benchShort returns the short dialect name used in benchmark names, matching
// the pair names the perf plan references (pg_mysql, mssql_pg, pg_pg, ...).
func benchShort(d keywords.SQLDialect) string {
	switch d {
	case keywords.DialectPostgreSQL:
		return "pg"
	case keywords.DialectSQLServer:
		return "mssql"
	default:
		return string(d)
	}
}

func benchPair(from, to keywords.SQLDialect) string {
	return benchShort(from) + "_" + benchShort(to)
}

// rwCorpus returns the real-world statements for a source dialect. The eight
// named dialects use set.RealWorld (feature/* fixtures excluded), matching the
// other wave-0 matrices. Generic has no realworld folder, so it uses
// ByDialect("generic") (TPC, ORM and real_world statements).
func rwCorpus(set *benchcorpus.Set, d keywords.SQLDialect) []benchcorpus.Statement {
	if d == keywords.DialectGeneric {
		return set.ByDialect(string(d))
	}
	return set.RealWorld(string(d))
}

// BenchmarkTranspileRW transpiles the real-world corpus of the source dialect
// to every target dialect (9x9 = 81 ordered pairs, identity included). Each
// iteration transpiles every statement of the source corpus that the source
// dialect accepts as an identity transpile, so ns/op and allocs/op are per
// full corpus pass. Sub-benchmarks are named <from>_<to> (short names).
func BenchmarkTranspileRW(b *testing.B) {
	set, err := benchcorpus.Default()
	if err != nil {
		b.Fatalf("load benchmark corpus: %v", err)
	}
	dialects := benchDialects()
	corpora := make(map[keywords.SQLDialect][]string, len(dialects))
	for _, from := range dialects {
		var ok []string
		for _, st := range rwCorpus(set, from) {
			if _, err := transpiler.Transpile(st.SQL, from, from); err == nil {
				ok = append(ok, st.SQL)
			}
		}
		corpora[from] = ok
	}
	for _, from := range dialects {
		stmts := corpora[from]
		for _, to := range dialects {
			b.Run(benchPair(from, to), func(b *testing.B) {
				if len(stmts) == 0 {
					b.Skipf("no corpus statements for %s", from)
				}
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					for _, s := range stmts {
						_, _ = transpiler.Transpile(s, from, to)
					}
				}
			})
		}
	}
}

// Shape texts. benchMedium is the verbatim statement the perf-audit verifier
// (BenchmarkVShapes) measured the W7-02/03/05/06 evidence on; it carries the
// `a ^ b` operator-retarget path and the LIMIT 10 row-limit path. Not every
// source dialect accepts it (SQL Server has no LIMIT; Oracle and ClickHouse
// reject `^`), so each pair pins the variant it uses (see BenchmarkTranspileShape).
const (
	benchMediumBody = "SELECT u.id, u.name || 'x', COUNT(*) AS c, %sCASE WHEN u.age > 18 AND u.flag = 1 THEN 'adult' ELSE 'minor' END " +
		"FROM users u JOIN orders o ON o.uid = u.id AND o.total > 10 " +
		"WHERE u.status IN ('a','b') OR (u.score * 2 + 1) >= 5 GROUP BY u.id, u.name HAVING COUNT(*) > 1 ORDER BY c DESC%s"
)

func mediumVariants() []string {
	return []string{
		fmt.Sprintf(benchMediumBody, "a ^ b, ", " LIMIT 10"), // verbatim verifier text
		fmt.Sprintf(benchMediumBody, "a ^ b, ", ""),          // no LIMIT (SQL Server sources)
		fmt.Sprintf(benchMediumBody, "", " LIMIT 10"),        // no caret (Oracle, ClickHouse sources)
		fmt.Sprintf(benchMediumBody, "", ""),                 // portable
	}
}

// mediumAt returns the pinned medium variant for a pair. The variant index is
// fixed per pair (no silent fallback): a perf gate must fail, not report a fake
// speedup, if a later change makes the pinned text stop transpiling.
func mediumAt(from, to keywords.SQLDialect, variant int) (string, error) {
	v := mediumVariants()[variant]
	if _, err := transpiler.Transpile(v, from, to); err != nil {
		return "", fmt.Errorf("pinned medium variant %d no longer transpiles: %w", variant, err)
	}
	return v, nil
}

func benchShapes(from, to keywords.SQLDialect, variant int) (shapes []struct{ name, sql string }, err error) {
	medium, err := mediumAt(from, to, variant)
	if err != nil {
		return nil, err
	}
	var sb strings.Builder
	sb.WriteString("SELECT a FROM t WHERE ")
	for i := 0; i < 200; i++ {
		if i > 0 {
			sb.WriteString(" OR ")
		}
		sb.WriteString("(a = 'x' AND b = 'y' AND c = 1)")
	}
	return []struct{ name, sql string }{
		{"small", "SELECT id, name FROM users WHERE id = 1"},
		{"medium", medium},
		{"large", sb.String()},
	}, nil
}

// BenchmarkTranspileShape measures statement-size scaling on identity and
// representative cross-dialect pairs. Sub-benchmarks are named
// <from>_<to>/{small,medium,large} using short dialect names (pg_pg, pg_mysql,
// mysql_pg, mssql_pg, oracle_snowflake, clickhouse_sqlite).
func BenchmarkTranspileShape(b *testing.B) {
	// variant indexes mediumVariants(): 0 verbatim, 1 no LIMIT, 2 no caret,
	// 3 portable (no caret, no LIMIT).
	pairs := []struct {
		from, to keywords.SQLDialect
		variant  int
	}{
		{keywords.DialectPostgreSQL, keywords.DialectPostgreSQL, 0},
		{keywords.DialectPostgreSQL, keywords.DialectMySQL, 0},
		{keywords.DialectMySQL, keywords.DialectPostgreSQL, 0},
		{keywords.DialectSQLServer, keywords.DialectPostgreSQL, 1},
		{keywords.DialectOracle, keywords.DialectSnowflake, 3},
		{keywords.DialectClickHouse, keywords.DialectSQLite, 2},
	}
	for _, pr := range pairs {
		p := [2]keywords.SQLDialect{pr.from, pr.to}
		shapes, err := benchShapes(p[0], p[1], pr.variant)
		if err != nil {
			b.Fatalf("%s -> %s: %v", p[0], p[1], err)
		}
		for _, sh := range shapes {
			if _, err := transpiler.Transpile(sh.sql, p[0], p[1]); err != nil {
				b.Fatalf("%s -> %s %s: %v", p[0], p[1], sh.name, err)
			}
			b.Run(benchPair(p[0], p[1])+"/"+sh.name, func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if _, err := transpiler.Transpile(sh.sql, p[0], p[1]); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
