// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package fingerprint_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/fingerprint"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func FuzzNormalizeV2(f *testing.F) {
	// Regression for /tmp/w5-08-fuzz-ca7775a415f0bcec (SQL Server).
	f.Add("INNER OUTER JOIN", uint8(77))
	dialects := append([]keywords.SQLDialect{""}, keywords.AllDialects()...)
	add := func(sql string) {
		for i := range dialects {
			f.Add(sql, uint8(i))
		}
	}
	for _, tc := range normalizeV2RuleCases {
		add(tc.sql)
	}
	for _, q := range portableQueries(f) {
		add(q.SQL)
	}
	// Rule examples include kept literals, quote escaping, all frame kinds,
	// placeholder forms, multi-statements, and the operator glue guard.
	for _, sql := range []string{
		"select a from t", "select t.key, key from t", `SELECT "users"."id", "Users", "select", "a""b" FROM t`,
		"SELECT `my-db`.`t`, `select` FROM t", "SELECT [p q], [users] FROM t",
		"SELECT a FROM t WHERE a = 1 AND b = 'x' LIMIT 10 OFFSET 2", "SELECT CAST(x AS varchar(10)), f(10)",
		"CREATE TABLE t (a VARCHAR(255), b DECIMAL(10,2), c INT NOT NULL DEFAULT NULL, d INT NULL)",
		"SELECT a AS 'lbl' FROM t", "SELECT * FROM t WHERE b IS NOT NULL AND c IS TRUE AND d = NULL",
		"SELECT $1, ?, :name, @p", "SELECT * FROM t WHERE a IN (1,2,3)", "SELECT * FROM t WHERE a IN ($1,$2)",
		"SELECT * FROM t WHERE a IN (SELECT 1,2 FROM u)", "INSERT t VALUES (1,'a'),(2,'b')",
		"SELECT * FROM a INNER JOIN b ON a.id=b.id LEFT OUTER JOIN c ON c.id=b.id",
		"SELECT a AS x FROM t AS tt", "WITH c AS (SELECT 1) SELECT * FROM c", "CREATE SEQUENCE s AS bigint",
		"SELECT try_cast(a AS INT), safe_cast(b AS INT)", "MERGE t AS tgt USING u ON tgt.id=u.id WHEN MATCHED THEN DELETE",
		"SELECT ALL a FROM t ORDER BY a ASC, b DESC", "SELECT 1 UNION ALL SELECT 2", "SELECT a != 1, b == 2",
		"SELECT date '2020-01-01'", "SELECT count (x) FROM t", "SELECT - -1, a = - 1 FROM t",
		";;SELECT 1; SELECT 2;;", "SELECT $$text$$, $1, x::varchar(10)", "", "SELECT FROM WHERE", "SELECT 'unterminated",
	} {
		add(sql)
	}
	f.Fuzz(func(t *testing.T, sql string, dialectIndex uint8) {
		opts := fingerprint.Options{Dialect: dialects[int(dialectIndex)%len(dialects)]}
		norm, err := fingerprint.NormalizeWithOptions(sql, opts)
		if err != nil {
			return
		}
		again, err := fingerprint.NormalizeWithOptions(norm, opts)
		if err != nil {
			t.Fatalf("normal form %q cannot tokenize: %v", norm, err)
		}
		if norm != again {
			t.Fatalf("not idempotent: %q -> %q", norm, again)
		}
		got, err := fingerprint.FingerprintWithOptions(sql, opts)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(norm))
		want := "v2:" + hex.EncodeToString(sum[:])
		if got != want {
			t.Fatalf("fingerprint = %q, want %q", got, want)
		}
	})
}
