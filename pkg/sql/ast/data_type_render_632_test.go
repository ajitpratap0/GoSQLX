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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// dataTypeLiterals are CREATE TABLE / CAST statements from the parser tests
// whose types the testdata corpus does not cover, notably the ClickHouse
// column CODEC(...) the parser appends to the column type.
var dataTypeLiterals = []string{
	"CREATE TABLE t (id UInt64 CODEC(ZSTD(3))) ENGINE = MergeTree() ORDER BY id",
	"CREATE TABLE t (id UInt64 CODEC(Delta(8), ZSTD)) ENGINE = MergeTree() ORDER BY id",
	"CREATE TABLE t (id UInt64, ts DateTime CODEC(Delta, LZ4)) ENGINE = MergeTree() ORDER BY id",
	"CREATE TABLE t (id UInt64, payload String CODEC(ZSTD(3))) ENGINE = MergeTree() ORDER BY id",
	"CREATE TABLE t (a Nullable(String), b LowCardinality(String), c Array(Nullable(Int32)), d Map(String, Array(UInt32)), e Tuple(a UInt8, b String), f DateTime64(3, 'UTC'), g Enum8('a' = 1, 'b' = 2), h FixedString(16), i Decimal(38, 18)) ENGINE = MergeTree() ORDER BY a",
	"CREATE TABLE t (a VARCHAR(100), b DECIMAL(10,2), c TEXT, d INT, e TIMESTAMP, f BOOLEAN)",
	"SELECT CAST(a AS VARCHAR(10)), CAST(b AS DECIMAL(10, 2)), c::INTEGER[], d::TEXT, CAST(e AS TIMESTAMP) FROM t",
	`CREATE TABLE t (c "a b")`,
	`SELECT CAST(x AS "a b") FROM t`,
}

// dataTypeCorpus returns every statement source under testdata/**/*.sql and
// the parser testdata, plus dataTypeLiterals.
func dataTypeCorpus(t *testing.T) []string {
	t.Helper()
	srcs := append([]string(nil), dataTypeLiterals...)
	for _, root := range []string{"../../../testdata", "../parser/testdata"} {
		err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(p, ".sql") {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			srcs = append(srcs, string(b))
			for _, s := range strings.Split(string(b), ";") {
				if strings.TrimSpace(s) != "" {
					srcs = append(srcs, s)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	return srcs
}

// collectDataTypes appends the Type of every ColumnDef and CastExpression
// reachable from v.
func collectDataTypes(v reflect.Value, seen map[uintptr]bool, out *[]string) {
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() || seen[v.Pointer()] {
			return
		}
		seen[v.Pointer()] = true
		collectDataTypes(v.Elem(), seen, out)
	case reflect.Interface:
		if !v.IsNil() {
			collectDataTypes(v.Elem(), seen, out)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			collectDataTypes(v.Index(i), seen, out)
		}
	case reflect.Struct:
		switch x := v.Interface().(type) {
		case ast.ColumnDef:
			*out = append(*out, x.Type)
		case ast.CastExpression:
			*out = append(*out, x.Type)
		}
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				collectDataTypes(v.Field(i), seen, out)
			}
		}
	}
}

// TestCorpusDataTypesRenderBare_PR632 checks, for every column and CAST type
// the parser stores from the corpus in each dialect, that SQL() writes the
// type unquoted unless the source wrote it quoted: a legitimate type such as
// ClickHouse's UInt64 CODEC(ZSTD(3)) must not become a quoted custom type.
func TestCorpusDataTypesRenderBare_PR632(t *testing.T) {
	dialects := []keywords.SQLDialect{
		keywords.DialectGeneric, keywords.DialectPostgreSQL, keywords.DialectMySQL,
		keywords.DialectSQLServer, keywords.DialectOracle, keywords.DialectSnowflake,
		keywords.DialectClickHouse, keywords.DialectSQLite,
	}
	checked := map[string]bool{}
	sawCodec := false
	for _, src := range dataTypeCorpus(t) {
		for _, d := range dialects {
			tree, err := gosqlx.ParseWithDialect(src, d)
			if err != nil {
				continue
			}
			var types []string
			collectDataTypes(reflect.ValueOf(tree), map[uintptr]bool{}, &types)
			ast.ReleaseAST(tree)
			for _, typ := range types {
				if typ == "" || checked[typ] {
					continue
				}
				checked[typ] = true
				if strings.Contains(typ, " CODEC(") {
					sawCodec = true
				}
				if strings.Contains(src, `"`+typ+`"`) {
					continue // quoted in the source: quoting it back is correct
				}
				col := (&ast.CreateTableStatement{Name: "t", Columns: []ast.ColumnDef{{Name: "c", Type: typ}}}).SQL()
				if want := "CREATE TABLE t (c " + typ + ")"; col != want {
					t.Errorf("[%s] column type %q renders as %q, want %q", d, typ, col, want)
				}
				cast := (&ast.CastExpression{Expr: &ast.Identifier{Name: "x"}, Type: typ}).SQL()
				if want := "CAST(x AS " + typ + ")"; cast != want {
					t.Errorf("[%s] cast type %q renders as %q, want %q", d, typ, cast, want)
				}
			}
		}
	}
	if len(checked) < 20 || !sawCodec {
		t.Fatalf("corpus produced too few types (%d, codec=%v); is the testdata path right?", len(checked), sawCodec)
	}
}

// TestClickHouseCodecColumnRoundTrip_PR632 pins the CODEC regression: the
// parser appends CODEC(...) to the column type, and SQL() must write it bare
// so it re-parses as the same column.
func TestClickHouseCodecColumnRoundTrip_PR632(t *testing.T) {
	for _, in := range []string{
		"CREATE TABLE t (id UInt64 CODEC(ZSTD(3))) ENGINE = MergeTree() ORDER BY id",
		"CREATE TABLE t (id UInt64, ts DateTime CODEC(Delta, LZ4) CODEC(ZSTD)) ENGINE = MergeTree() ORDER BY id",
	} {
		tree, err := gosqlx.ParseWithDialect(in, keywords.DialectClickHouse)
		if err != nil {
			t.Fatalf("parse %q: %v", in, err)
		}
		out := tree.SQL()
		ast.ReleaseAST(tree)
		if strings.Contains(out, `"`) {
			t.Errorf("SQL() of %q quotes the CODEC type: %s", in, out)
		}
		tree2, err := gosqlx.ParseWithDialect(out, keywords.DialectClickHouse)
		if err != nil {
			t.Errorf("SQL() %q does not re-parse: %v", out, err)
			continue
		}
		if got := tree2.SQL(); got != out {
			t.Errorf("re-parse of %q renders %q", out, got)
		}
		ast.ReleaseAST(tree2)
	}
	// A quoted custom type that merely looks like a CODEC suffix without its
	// argument list stays quoted.
	if got := (&ast.CastExpression{Expr: &ast.Identifier{Name: "x"}, Type: "a CODEC"}).SQL(); got != `CAST(x AS "a CODEC")` {
		t.Errorf("type %q renders as %s", "a CODEC", got)
	}
}
