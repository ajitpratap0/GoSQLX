// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// legacyScratchParse deliberately uses the public copying tokenizer API as an
// independent reference for all three scratch consumers in transform.go.
func legacyScratchParse(sql string, dialect keywords.SQLDialect, withDialect bool) (*ast.AST, error) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	if withDialect && dialect != "" {
		tkz.SetDialect(dialect)
	}
	tokens, err := tkz.TokenizeString(sql)
	if err != nil {
		return nil, fmt.Errorf("tokenize: %w", err)
	}
	p := parser.GetParser()
	defer parser.PutParser(p)
	if withDialect {
		p.ApplyOptions(parser.WithDialect(string(dialect)))
	}
	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return tree, nil
}

type scratchCase struct {
	name, sql string
	dialect   keywords.SQLDialect
}

func scratchCorpus(t *testing.T) []scratchCase {
	t.Helper()
	var cases []scratchCase
	for _, root := range []string{"../../testdata/realworld", "../../testdata/corpus"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || filepath.Ext(path) != ".sql" {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			dialect := keywords.DialectGeneric
			for _, d := range keywords.AllDialects() {
				if strings.Contains(filepath.ToSlash(path), "/"+string(d)+"/") {
					dialect = d
					break
				}
			}
			for i, sql := range gosqlx.SplitStatements(string(data), string(dialect)) {
				cases = append(cases, scratchCase{fmt.Sprintf("%s/%d", path, i), sql, dialect})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(cases) < 100 {
		t.Fatalf("corpus unexpectedly small: %d", len(cases))
	}
	for _, sql := range []string{"", "SELECT 'unterminated", "SELECT FROM", "SELECT first_name FROM first_table; SELECT second_name FROM second_table"} {
		cases = append(cases, scratchCase{sql, sql, keywords.DialectGeneric})
	}
	return cases
}

type scratchResult struct {
	output []string
	err    string
}

func scratchRender(tree *ast.AST, err error) scratchResult {
	if err != nil {
		return scratchResult{err: err.Error()}
	}
	var result scratchResult
	if tree != nil {
		for _, stmt := range tree.Statements {
			sql, err := FormatSQLChecked(stmt)
			if err != nil {
				result.output = append(result.output, "render error: "+err.Error())
			} else {
				result.output = append(result.output, sql)
			}
		}
	}
	return result
}

func scratchParseCase(c scratchCase, mode int, legacy bool) (*ast.AST, error) {
	if legacy {
		tree, err := legacyScratchParse(c.sql, c.dialect, mode == 1)
		if mode != 2 || err != nil {
			return tree, err
		}
		if tree == nil || len(tree.Statements) == 0 {
			ast.ReleaseAST(tree)
			return nil, fmt.Errorf("no statements parsed")
		}
		stmt := tree.Statements[0]
		tree.Statements[0] = nil
		ast.ReleaseAST(tree)
		return &ast.AST{Statements: []ast.Statement{stmt}}, nil
	}
	switch mode {
	case 0:
		return ParseSQL(c.sql)
	case 1:
		return ParseSQLWithDialect(c.sql, c.dialect)
	default:
		stmt, err := parseSQL(c.sql)
		if err != nil {
			return nil, err
		}
		return &ast.AST{Statements: []ast.Statement{stmt}}, nil
	}
}

func TestTokenScratchCorpusDifferential(t *testing.T) {
	for _, c := range scratchCorpus(t) {
		for mode, name := range []string{"ParseSQL", "ParseSQLWithDialect", "parseSQL"} {
			t.Run(c.name+"/"+name, func(t *testing.T) {
				oldTree, oldErr := scratchParseCase(c, mode, true)
				defer ast.ReleaseAST(oldTree)
				newTree, newErr := scratchParseCase(c, mode, false)
				defer ast.ReleaseAST(newTree)
				want, got := scratchRender(oldTree, oldErr), scratchRender(newTree, newErr)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("got %#v, want %#v", got, want)
				}
			})
		}
	}
}

func TestTokenScratchCorpusConcurrent(t *testing.T) {
	cases := scratchCorpus(t)
	sequential := make([][3]scratchResult, len(cases))
	for i, c := range cases {
		for mode := range 3 {
			tree, err := scratchParseCase(c, mode, false)
			sequential[i][mode] = scratchRender(tree, err)
			ast.ReleaseAST(tree)
		}
	}
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i, c := range cases {
				for mode := range 3 {
					tree, err := scratchParseCase(c, mode, false)
					got := scratchRender(tree, err)
					ast.ReleaseAST(tree)
					if !reflect.DeepEqual(got, sequential[i][mode]) {
						t.Errorf("worker %d %s mode %d: got %#v, want %#v", worker, c.name, mode, got, sequential[i][mode])
						return
					}
				}
			}
		}()
	}
	wg.Wait()
}

func TestTokenScratchReturnedASTSurvivesReuse(t *testing.T) {
	// Retain caller-owned nodes while later calls overwrite tokenizer scratch.
	for mode, name := range []string{"ParseSQL", "ParseSQLWithDialect", "parseSQL"} {
		t.Run(name, func(t *testing.T) {
			c := scratchCase{sql: "SELECT retained_name, 'retained value' FROM retained_table WHERE retained_id = 123", dialect: keywords.DialectPostgreSQL}
			tree, err := scratchParseCase(c, mode, false)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			want := scratchRender(tree, nil)
			for i := range 64 {
				other, err := scratchParseCase(scratchCase{sql: fmt.Sprintf("SELECT overwritten_%d, 'replacement' FROM another_table WHERE another_id = 999", i), dialect: keywords.DialectMySQL}, i%3, false)
				if err != nil {
					t.Fatal(err)
				}
				ast.ReleaseAST(other)
			}
			if got := scratchRender(tree, nil); !reflect.DeepEqual(got, want) {
				t.Fatalf("after reuse: got %#v, want %#v", got, want)
			}
		})
	}
}

func TestTokenScratchExtractedNodesConcurrent(t *testing.T) {
	// These two helpers return subnodes detached from parseSQL's statement.
	// Retain those subnodes across calls on every worker as well.
	const condition = "retained_id = 123 AND retained_name = 'kept'"
	const join = "JOIN retained_table r ON r.retained_id = _t.retained_id"
	makeTree := func() (*ast.AST, error) {
		expr, err := parseCondition(condition)
		if err != nil {
			return nil, err
		}
		clause, err := parseJoinClause(join)
		if err != nil {
			return nil, err
		}
		return &ast.AST{Statements: []ast.Statement{&ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "retained_column"}},
			Where:   expr, Joins: []ast.JoinClause{*clause},
		}}}, nil
	}
	baseline, err := makeTree()
	if err != nil {
		t.Fatal(err)
	}
	want := scratchRender(baseline, nil)
	ast.ReleaseAST(baseline)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			retained, err := makeTree()
			if err != nil {
				t.Error(err)
				return
			}
			defer ast.ReleaseAST(retained)
			for range 32 {
				other, err := makeTree()
				if err != nil {
					t.Error(err)
					return
				}
				ast.ReleaseAST(other)
			}
			if got := scratchRender(retained, nil); !reflect.DeepEqual(got, want) {
				t.Errorf("retained condition/join after reuse: got %#v, want %#v", got, want)
			}
		}()
	}
	wg.Wait()
}
