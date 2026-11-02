// Copyright 2026 GoSQLX Contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// drawnNodeTypes are the node types the parser draws from ast pools; they
// mirror releaseDrawnConstructors in pkg/sql/ast/pool_drawn_policy_test.go.
var drawnNodeTypes = map[string]bool{
	"TupleExpression":            true,
	"ArrayConstructorExpression": true,
	"ArraySubscriptExpression":   true,
	"ArraySliceExpression":       true,
	"AlterStatement":             true,
	"ShowStatement":              true,
	"DescribeStatement":          true,
	"ReplaceStatement":           true,
	"CreateSequenceStatement":    true,
	"DropSequenceStatement":      true,
	"AlterSequenceStatement":     true,
}

// drawnTypesIn reports the pooled node types reachable from tree.
func drawnTypesIn(tree *ast.AST) map[string]bool {
	found := map[string]bool{}
	seen := map[uintptr]bool{}
	var walk func(v reflect.Value, depth int)
	walk = func(v reflect.Value, depth int) {
		if depth > 400 {
			return
		}
		switch v.Kind() {
		case reflect.Interface:
			if !v.IsNil() {
				walk(v.Elem(), depth+1)
			}
		case reflect.Ptr:
			if v.IsNil() || seen[v.Pointer()] {
				return
			}
			seen[v.Pointer()] = true
			if drawnNodeTypes[v.Elem().Type().Name()] {
				found[v.Elem().Type().Name()] = true
			}
			walk(v.Elem(), depth+1)
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				walk(v.Field(i), depth+1)
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i), depth+1)
			}
		case reflect.Map:
			it := v.MapRange()
			for it.Next() {
				walk(it.Value(), depth+1)
			}
		}
	}
	walk(reflect.ValueOf(tree), 0)
	return found
}

// parseCounting parses sql and returns the tree with the parse's pooled-draw
// count.
func parseCounting(sql string, d keywords.SQLDialect) (*ast.AST, int, error) {
	tkz, err := tokenizer.NewWithDialect(d)
	if err != nil {
		return nil, 0, err
	}
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return nil, 0, err
	}
	p := NewParser(WithDialect(string(d)))
	defer p.Release()
	tree, err := p.ParseFromModelTokens(tokens)
	return tree, p.pooledDraws, err
}

type drawCase struct {
	sql     string
	dialect keywords.SQLDialect
	typ     string // pooled type the statement must produce; "" = none
}

var drawCases = []drawCase{
	{"SELECT 1", keywords.DialectPostgreSQL, ""},
	{"SELECT a, b FROM t WHERE a = 1 ORDER BY b", keywords.DialectPostgreSQL, ""},
	{"SELECT c, COUNT(*) FROM o JOIN u ON o.u = u.id GROUP BY c HAVING COUNT(*) > 1", keywords.DialectPostgreSQL, ""},
	{"SELECT * FROM t WHERE (a, b) IN ((1, 2), (3, 4))", keywords.DialectPostgreSQL, "TupleExpression"},
	{"SELECT ARRAY[1, 2, 3]", keywords.DialectPostgreSQL, "ArrayConstructorExpression"},
	{"SELECT a[1] FROM t", keywords.DialectPostgreSQL, "ArraySubscriptExpression"},
	{"SELECT a[1:2] FROM t", keywords.DialectPostgreSQL, "ArraySliceExpression"},
	{"ALTER TABLE t ADD COLUMN c INT", keywords.DialectPostgreSQL, "AlterStatement"},
	{"SHOW TABLES", keywords.DialectMySQL, "ShowStatement"},
	{"DESCRIBE t", keywords.DialectMySQL, "DescribeStatement"},
	{"REPLACE INTO t (a) VALUES (1)", keywords.DialectMySQL, "ReplaceStatement"},
	{"CREATE SEQUENCE s", keywords.DialectMariaDB, "CreateSequenceStatement"},
	{"DROP SEQUENCE s", keywords.DialectMariaDB, "DropSequenceStatement"},
	{"ALTER SEQUENCE s INCREMENT BY 2", keywords.DialectMariaDB, "AlterSequenceStatement"},
	{"UPDATE t SET (a, b) = (SELECT 1, 2)", keywords.DialectPostgreSQL, "TupleExpression"},
	{"INSERT INTO t (a, b) VALUES (1, 2), (3, 4)", keywords.DialectPostgreSQL, ""},
	{"INSERT INTO t (a) VALUES (1)", keywords.DialectPostgreSQL, ""},
}

// TestPooledDraws_CountMatchesTree pins the contract between the parser's draw
// counter and the tree it returns: a parse that reports zero pooled draws must
// have no pooled node reachable, and every pooled node type the parser can
// build must be counted.
func TestPooledDraws_CountMatchesTree(t *testing.T) {
	covered := map[string]bool{}
	for _, c := range drawCases {
		t.Run(c.sql, func(t *testing.T) {
			tree, draws, err := parseCounting(c.sql, c.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", c.sql, err)
			}
			defer ast.ReleaseAST(tree)
			found := drawnTypesIn(tree)
			if c.typ == "" {
				if draws != 0 || len(found) != 0 {
					t.Errorf("want no pooled draws, got count=%d nodes=%v", draws, found)
				}
				return
			}
			if !found[c.typ] {
				t.Fatalf("expected a %s in the tree, found %v", c.typ, found)
			}
			covered[c.typ] = true
			if draws == 0 {
				t.Errorf("tree holds a pooled %s but the parser counted no draw", c.typ)
			}
		})
	}
	for typ := range drawnNodeTypes {
		if !covered[typ] {
			t.Errorf("no case exercises pooled type %s; add one to drawCases", typ)
		}
	}
}

// TestPooledDraws_CorpusEquivalence is the differential check over the
// repository's SQL corpora: wherever the parser reports zero pooled draws, the
// tree must hold no pooled node (so skipping the release walk is equivalent),
// and any pooled node must be counted.
func TestPooledDraws_CorpusEquivalence(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata")
	var files []string
	for _, sub := range []string{"corpus", "real_world", "realworld", "sql", "postgresql", "mysql", "mssql", "oracle"} {
		_ = filepath.Walk(filepath.Join(root, sub), func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && strings.HasSuffix(path, ".sql") {
				files = append(files, path)
			}
			return nil
		})
	}
	if len(files) == 0 {
		t.Skip("no corpus files found")
	}
	sort.Strings(files)
	dialects := []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectSQLServer, keywords.DialectOracle}
	var parsed, zero, nonZero int
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range strings.Split(string(raw), ";") {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			for _, d := range dialects {
				tree, draws, err := parseCounting(stmt, d)
				if err != nil {
					continue
				}
				parsed++
				found := drawnTypesIn(tree)
				if len(found) > 0 && draws == 0 {
					t.Errorf("%s (%s): tree holds pooled nodes %v but draw count is 0:\n%s", f, d, found, stmt)
				}
				if draws == 0 {
					zero++
				} else {
					nonZero++
				}
				ast.ReleaseAST(tree)
			}
		}
	}
	if parsed == 0 || zero == 0 {
		t.Fatalf("corpus produced no usable data: parsed=%d zero=%d nonZero=%d", parsed, zero, nonZero)
	}
	t.Logf("parsed=%d zero-draw=%d with-draws=%d", parsed, zero, nonZero)
}

// TestPooledDraws_ResetPerParse checks the counter does not leak across parses
// on one pooled Parser: a draw-free parse after a drawing one must report 0.
func TestPooledDraws_ResetPerParse(t *testing.T) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	p := NewParser()
	defer p.Release()
	for i, sql := range []string{"SELECT (1, 2)", "SELECT 1", "SELECT (1, 2)", "SELECT 2"} {
		tokens, err := tkz.Tokenize([]byte(sql))
		if err != nil {
			t.Fatal(err)
		}
		tree, err := p.ParseFromModelTokens(tokens)
		if err != nil {
			t.Fatalf("%q: %v", sql, err)
		}
		want := i%2 == 0
		if got := p.pooledDraws > 0; got != want {
			t.Errorf("%q: pooledDraws=%d, want draws=%v", sql, p.pooledDraws, want)
		}
		ast.ReleaseAST(tree)
	}
}
