// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package transpiler

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// benchMatrixSQL is a portable statement that every dialect parses, so every
// ordered pair measures a successful transpile.
const benchMatrixSQL = "SELECT u.id, u.name, COUNT(*) AS c FROM users u " +
	"JOIN orders o ON o.uid = u.id WHERE u.status = 'a' AND o.total > 10 " +
	"GROUP BY u.id, u.name ORDER BY c DESC"

// BenchmarkTranspileMatrix runs one transpile for every ordered dialect pair,
// identity pairs included (9x9 = 81 with the generic dialect).
func BenchmarkTranspileMatrix(b *testing.B) {
	dialects := prefilterDialects()
	for _, from := range dialects {
		for _, to := range dialects {
			if _, err := Transpile(benchMatrixSQL, from, to); err != nil {
				b.Fatalf("%s -> %s: %v", from, to, err)
			}
			b.Run(fmt.Sprintf("%s_%s", from, to), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if _, err := Transpile(benchMatrixSQL, from, to); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func benchShapes() []struct{ name, sql string } {
	medium := "SELECT u.id, u.name || 'x', COUNT(*) AS c, CASE WHEN u.age > 18 AND u.flag = 1 THEN 'adult' ELSE 'minor' END " +
		"FROM users u JOIN orders o ON o.uid = u.id AND o.total > 10 " +
		"WHERE u.status IN ('a','b') OR (u.score * 2 + 1) >= 5 GROUP BY u.id, u.name HAVING COUNT(*) > 1 ORDER BY c DESC"
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
	}
}

// BenchmarkTranspileShape measures statement-size scaling on identity and
// representative cross-dialect pairs.
func BenchmarkTranspileShape(b *testing.B) {
	pairs := [][2]keywords.SQLDialect{
		{keywords.DialectPostgreSQL, keywords.DialectPostgreSQL},
		{keywords.DialectPostgreSQL, keywords.DialectMySQL},
		{keywords.DialectMySQL, keywords.DialectPostgreSQL},
		{keywords.DialectSQLServer, keywords.DialectPostgreSQL},
		{keywords.DialectOracle, keywords.DialectSnowflake},
		{keywords.DialectClickHouse, keywords.DialectSQLite},
	}
	shapes := benchShapes()
	for _, p := range pairs {
		for _, sh := range shapes {
			if _, err := Transpile(sh.sql, p[0], p[1]); err != nil {
				b.Fatalf("%s -> %s %s: %v", p[0], p[1], sh.name, err)
			}
			b.Run(fmt.Sprintf("%s_%s/%s", p[0], p[1], sh.name), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if _, err := Transpile(sh.sql, p[0], p[1]); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
