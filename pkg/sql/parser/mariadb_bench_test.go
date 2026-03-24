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

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// BenchmarkMariaDB_Sequence benchmarks MariaDB SEQUENCE DDL parsing.
func BenchmarkMariaDB_Sequence(b *testing.B) {
	benchmarks := []struct {
		name string
		sql  string
	}{
		{
			name: "create_minimal",
			sql:  "CREATE SEQUENCE seq_orders",
		},
		{
			name: "create_all_options",
			sql:  "CREATE SEQUENCE s START WITH 1000 INCREMENT BY 5 MINVALUE 1 MAXVALUE 9999 CACHE 20 CYCLE",
		},
		{
			name: "create_or_replace_nocache",
			sql:  "CREATE OR REPLACE SEQUENCE s NOCACHE NOCYCLE",
		},
		{
			name: "alter_restart_with",
			sql:  "ALTER SEQUENCE s RESTART WITH 5000",
		},
		{
			name: "drop_if_exists",
			sql:  "DROP SEQUENCE IF EXISTS seq_orders",
		},
	}

	for _, bm := range benchmarks {
		bm := bm
		b.Run(bm.name, func(b *testing.B) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(bm.sql))
			if err != nil {
				b.Fatalf("Tokenize error: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				p := parser.NewParser(parser.WithDialect(string(keywords.DialectMariaDB)))
				result, err := p.ParseFromModelTokens(tokens)
				if err != nil {
					b.Fatalf("Parse error: %v", err)
				}
				ast.ReleaseAST(result)
				p.Release()
			}
		})
	}
}

// BenchmarkMariaDB_ForSystemTime benchmarks MariaDB temporal table query parsing.
func BenchmarkMariaDB_ForSystemTime(b *testing.B) {
	benchmarks := []struct {
		name string
		sql  string
	}{
		{
			name: "as_of_timestamp",
			sql:  "SELECT * FROM t FOR SYSTEM_TIME AS OF TIMESTAMP '2024-01-01 00:00:00'",
		},
		{
			name: "all",
			sql:  "SELECT id, name FROM orders FOR SYSTEM_TIME ALL",
		},
		{
			name: "between",
			sql:  "SELECT * FROM t FOR SYSTEM_TIME BETWEEN TIMESTAMP '2023-01-01' AND TIMESTAMP '2023-12-31'",
		},
		{
			name: "from_to",
			sql:  "SELECT * FROM t FOR SYSTEM_TIME FROM TIMESTAMP '2023-01-01' TO TIMESTAMP '2024-01-01'",
		},
		{
			name: "join_with_system_time",
			sql: `SELECT o.id, h.status
				FROM orders o
				JOIN order_history h FOR SYSTEM_TIME AS OF TIMESTAMP '2024-01-01'
				ON o.id = h.order_id`,
		},
	}

	for _, bm := range benchmarks {
		bm := bm
		b.Run(bm.name, func(b *testing.B) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(bm.sql))
			if err != nil {
				b.Fatalf("Tokenize error: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				p := parser.NewParser(parser.WithDialect(string(keywords.DialectMariaDB)))
				result, err := p.ParseFromModelTokens(tokens)
				if err != nil {
					b.Fatalf("Parse error: %v", err)
				}
				ast.ReleaseAST(result)
				p.Release()
			}
		})
	}
}

// BenchmarkMariaDB_ConnectBy benchmarks MariaDB CONNECT BY hierarchical query parsing.
func BenchmarkMariaDB_ConnectBy(b *testing.B) {
	benchmarks := []struct {
		name string
		sql  string
	}{
		{
			name: "simple_prior_left",
			sql: `SELECT id, name FROM employees
				START WITH parent_id IS NULL
				CONNECT BY PRIOR id = parent_id`,
		},
		{
			name: "prior_right",
			sql: `SELECT id, name FROM employees
				START WITH id = 1
				CONNECT BY id = PRIOR parent_id`,
		},
		{
			name: "nocycle",
			sql: `SELECT id, name, level FROM employees
				START WITH parent_id IS NULL
				CONNECT BY NOCYCLE PRIOR id = parent_id`,
		},
		{
			name: "with_where_and_order",
			sql: `SELECT id, name FROM employees
				WHERE active = 1
				START WITH parent_id IS NULL
				CONNECT BY PRIOR id = parent_id
				ORDER BY id`,
		},
	}

	for _, bm := range benchmarks {
		bm := bm
		b.Run(bm.name, func(b *testing.B) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(bm.sql))
			if err != nil {
				b.Fatalf("Tokenize error: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				p := parser.NewParser(parser.WithDialect(string(keywords.DialectMariaDB)))
				result, err := p.ParseFromModelTokens(tokens)
				if err != nil {
					b.Fatalf("Parse error: %v", err)
				}
				ast.ReleaseAST(result)
				p.Release()
			}
		})
	}
}

// BenchmarkMariaDB_Mixed benchmarks parsing of queries that combine multiple
// MariaDB-specific features in a single statement.
func BenchmarkMariaDB_Mixed(b *testing.B) {
	benchmarks := []struct {
		name string
		sql  string
	}{
		{
			name: "temporal_with_cte",
			sql: `WITH history AS (
					SELECT * FROM orders FOR SYSTEM_TIME ALL
				)
				SELECT id, status FROM history WHERE status = 'cancelled'`,
		},
		{
			name: "hierarchical_with_cte",
			sql: `WITH RECURSIVE org AS (
					SELECT id, name, parent_id FROM employees
					START WITH parent_id IS NULL
					CONNECT BY PRIOR id = parent_id
				)
				SELECT * FROM org ORDER BY id`,
		},
		{
			name: "create_table_versioned",
			sql: `CREATE TABLE orders (
					id INT PRIMARY KEY,
					status VARCHAR(50),
					row_start DATETIME(6) GENERATED ALWAYS AS ROW START,
					row_end   DATETIME(6) GENERATED ALWAYS AS ROW END,
					PERIOD FOR SYSTEM_TIME(row_start, row_end)
				) WITH SYSTEM VERSIONING`,
		},
	}

	for _, bm := range benchmarks {
		bm := bm
		b.Run(bm.name, func(b *testing.B) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(bm.sql))
			if err != nil {
				b.Fatalf("Tokenize error: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				p := parser.NewParser(parser.WithDialect(string(keywords.DialectMariaDB)))
				result, err := p.ParseFromModelTokens(tokens)
				if err != nil {
					b.Fatalf("Parse error: %v", err)
				}
				ast.ReleaseAST(result)
				p.Release()
			}
		})
	}
}
