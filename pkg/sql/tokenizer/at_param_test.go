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

package tokenizer

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// atParamInputs covers plain @param / @@var names and every edge case where
// the identifier after '@' interacts with readIdentifier's special paths
// (prefixed strings, U& escapes, compound keywords, non-ASCII folding).
var atParamInputs = []string{
	"SELECT @id",
	"SELECT @id, @name FROM t WHERE a = @a1 AND b=@b_2",
	"SELECT @@ROWCOUNT, @@version",
	"SELECT @@ROWCOUNT",
	"SELECT @@ x",
	"SELECT @",
	"SELECT @ id",
	"SELECT @>",
	"SELECT a @> b, a @@ b",
	"SELECT @1",
	"SELECT @_x$y#z",
	"SELECT @x.y",
	"SELECT @x::int",
	"SELECT @é, @@ü, @日本",
	"SELECT @ſ, @ı",
	"SELECT @N'x'",
	"SELECT @n'x', @X'ab', @B'1', @E'a\\nb', @q'[x]'",
	"SELECT @a'x'",
	"SELECT @U&'d\\0061t'",
	"SELECT @u&\"d\"",
	"SELECT @@U&'x'",
	"SELECT @group by x",
	"SELECT @GROUP   BY x",
	"SELECT @group\nby x",
	"SELECT @order by, @left join, @right outer, @inner join, @cross join",
	"SELECT @natural join, @full outer join, @grouping sets, @outer apply",
	"SELECT @group",
	"SELECT @group, @order",
	"SELECT @@group by",
	"SELECT @@Left Outer Join",
	"SELECT\n  @a,\n  @@b,\r\n  @c",
	"SELECT '@id', \"@id\", -- @id\n 1 /* @id */",
	"EXEC p @a = 1, @b = @c OUTPUT",
	"SELECT @x ",
	"SELECT @abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789",
}

var atParamDialects = []keywords.SQLDialect{
	keywords.DialectGeneric, keywords.DialectSQLServer, keywords.DialectPostgreSQL,
	keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectOracle,
	keywords.DialectSQLite, keywords.DialectSnowflake, keywords.DialectClickHouse,
}

func renderAtParam(dialect keywords.SQLDialect, sql string) string {
	tkz, err := NewWithDialect(dialect)
	if err != nil {
		return "newerr: " + err.Error()
	}
	toks, err := tkz.Tokenize([]byte(sql))
	var b strings.Builder
	for _, tw := range toks {
		fmt.Fprintf(&b, "%d %q q=%d %d:%d-%d:%d\n", tw.Token.Type, tw.Token.Value, tw.Token.Quote,
			tw.Start.Line, tw.Start.Column, tw.End.Line, tw.End.Column)
	}
	if err != nil {
		fmt.Fprintf(&b, "ERR %v\n", err)
	}
	return b.String()
}

// TestAtParam_Golden pins the exact token stream (types, values, quote and
// spans, plus any error) for @param / @@var inputs in every dialect. The
// golden was generated before the zero-copy change, so any diff is a
// behaviour change.
func TestAtParam_Golden(t *testing.T) {
	var out strings.Builder
	for _, d := range atParamDialects {
		for _, sql := range atParamInputs {
			fmt.Fprintf(&out, "=== %s %q\n%s", d, sql, renderAtParam(d, sql))
		}
	}
	const path = "testdata/at_param_golden.txt"
	if os.Getenv("GOSQLX_UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(path, []byte(out.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.ReplaceAll(out.String(), "\r\n", "\n"); got != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Fatalf("@param token stream differs from golden %s (regenerate only for an intentional change)", path)
	}
}

// TestAtParam_ValueIsSourceSlice checks the plain-name behaviour directly.
func TestAtParam_ValueIsSourceSlice(t *testing.T) {
	tkz, err := NewWithDialect(keywords.DialectSQLServer)
	if err != nil {
		t.Fatal(err)
	}
	toks, err := tkz.Tokenize([]byte("SELECT @id, @@ROWCOUNT"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, tw := range toks {
		switch tw.Token.Type {
		case models.TokenTypePlaceholder, models.TokenTypeIdentifier:
			got = append(got, tw.Token.Value)
		}
	}
	if strings.Join(got, ",") != "@id,@@ROWCOUNT" {
		t.Fatalf("got %v", got)
	}
}

// TestAtParam_NoPerTokenAlloc guards the zero-copy property: a statement
// full of plain @params must not allocate a string per parameter.
func TestAtParam_NoPerTokenAlloc(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("SELECT ")
	for i := 0; i < 64; i++ {
		fmt.Fprintf(&sb, "@p%d, ", i)
	}
	sb.WriteString("@@ROWCOUNT")
	sql := sb.String()
	tkz, err := NewWithDialect(keywords.DialectSQLServer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tkz.TokenizeString(sql); err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(20, func() {
		if _, err := tkz.TokenizeString(sql); err != nil {
			t.Fatal(err)
		}
	})
	// Result slice growth only; the old code added >= 65 string allocations.
	if allocs > 20 {
		t.Fatalf("allocs/run = %v, want <= 20 (per-param concatenation regressed)", allocs)
	}
}
