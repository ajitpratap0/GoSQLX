// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter_test

import (
	"strings"
	"testing"

	"fmt"
	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/internal/renderhint"
	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestRenderHintSoundness(t *testing.T) {
	corpus, err := benchcorpus.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range corpus.All() {
		tree, mask, valid, err := renderhint.SourceParse(item.SQL, item.Dialect)
		if err != nil {
			continue
		}
		if !valid {
			t.Errorf("%s %d: invalid hints", item.File, item.Index)
			ast.ReleaseAST(tree)
			continue
		}
		for i, stmt := range tree.Statements {
			for _, target := range []string{"postgresql", "mysql", "sqlite", "sqlserver", "oracle", "snowflake", "clickhouse", "mariadb", "generic", "MySQL"} {
				if formatter.NeedsDialectRewriteForTest(stmt, strings.ToLower(target)) && i < 64 && mask&(uint64(1)<<uint(i)) == 0 {
					t.Errorf("%s %d statement %d target %s: missing hint", item.File, item.Index, i, target)
				}
			}
		}
		ast.ReleaseAST(tree)
	}
}

// Unsupported source dialect/operator pairs are rejected by the parser; every
// accepted pair must satisfy the same implication as the harvested corpus.
func TestRenderHintGeneratedSoundness(t *testing.T) {
	operators := []string{"=", "!=", "<>", "<", ">", "<=", ">=", "==", "+", "-", "*", "/", "%", "^", "||", "&&", "&", "|", "#", "<<", ">>", "->", "->>", "#>", "#>>", "@>", "<@", "?", "?|", "?&", "~", "~*", "!~", "!~*", "AND", "OR", "XOR", "IS", "IS NOT", "IS DISTINCT FROM", "IS NOT DISTINCT FROM", "LIKE", "ILIKE", "SIMILAR TO", "REGEXP", "RLIKE", "GLOB", "MATCH", "SOUNDS LIKE", "DIV", "MOD", "@?", "@@", "<=>", "!<", "!>", "!="}
	dialects := []string{"postgresql", "mysql", "sqlite", "sqlserver", "oracle", "snowflake", "clickhouse", "mariadb", "generic"}
	forms := make([]string, 0, len(operators)+30)
	for _, op := range operators {
		forms = append(forms, "SELECT a "+op+" b")
	}
	for _, op := range []string{"+", "-", "NOT", "~", "@", "|/", "||/", "!!"} {
		forms = append(forms, "SELECT "+op+" a")
	}
	forms = append(forms, "SELECT a !", "SELECT U&'d\\0061t'")
	for _, typ := range []string{"INT", "INTEGER", "VARCHAR(20)", "DOUBLE PRECISION", "BOOLEAN", "TIMESTAMP", "TIMESTAMP WITH TIME ZONE", "BYTEA", "BINARY", "VARIANT", "ARRAY", "\"MyType\"", "`MyType`", "[MyType]"} {
		forms = append(forms, fmt.Sprintf("SELECT CAST(a AS %s)", typ), fmt.Sprintf("CREATE TABLE t (a %s)", typ), fmt.Sprintf("ALTER TABLE t ALTER COLUMN a TYPE %s", typ))
	}
	accepted := 0
	for _, source := range dialects {
		for _, sql := range forms {
			tree, mask, valid, err := renderhint.SourceParse(sql, source)
			if err != nil {
				continue
			}
			accepted++
			if !valid {
				t.Fatalf("%s %s: invalid mask", source, sql)
			}
			for i, stmt := range tree.Statements {
				for _, target := range dialects {
					if formatter.NeedsDialectRewriteForTest(stmt, target) && i < 64 && mask&(uint64(1)<<uint(i)) == 0 {
						t.Errorf("%s %s -> %s: missing rewrite hint", source, sql, target)
					}
				}
			}
			ast.ReleaseAST(tree)
		}
	}
	if accepted == 0 {
		t.Fatal("no generated cases accepted")
	}
	t.Logf("checked %d generated source statements", accepted)
}
