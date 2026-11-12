// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package renderhint_test

import (
	goast "go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/renderhint"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// Harvest spelling constants from both token recognition and exact retargeting
// so a newly supported spelling participates without hand-editing this table.
func operatorSpellings(t *testing.T) []string {
	t.Helper()
	found := map[string]bool{"^": true, "||": true, "unknown operator": true, "IS DISTINCT FROM": true, "IS NOT DISTINCT FROM": true, "SIMILAR TO": true, "SOUNDS LIKE": true}
	words := " AND OR XOR NOT IS LIKE ILIKE SIMILAR TO REGEXP RLIKE GLOB MATCH SOUNDS LIKE DIV MOD "
	for _, root := range []string{"../../pkg/sql/tokenizer", "../../pkg/sql/keywords", "../../pkg/sql/ast"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			goast.Inspect(file, func(n goast.Node) bool {
				lit, ok := n.(*goast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(lit.Value)
				if err != nil || value == "" {
					return true
				}
				symbolic := true
				for _, ch := range value {
					if !strings.ContainsRune("+-*/%^|&~!#@<>=?:", ch) {
						symbolic = false
						break
					}
				}
				if symbolic || strings.Contains(words, " "+strings.ToUpper(value)+" ") {
					found[value] = true
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	result := make([]string, 0, len(found))
	for op := range found {
		result = append(result, op)
	}
	return result
}

func TestOperatorSupersetDrift(t *testing.T) {
	targets := []string{"postgresql", "mysql", "mariadb", "sqlserver", "snowflake", "clickhouse", "sqlite", "oracle", "generic", "MySQL", ""}
	id := &ast.Identifier{Name: "a"}
	for _, op := range operatorSpellings(t) {
		for flags := 0; flags < 64; flags++ {
			binary := &ast.BinaryExpression{Left: id, Right: id, Operator: op, Lambda: flags&1 != 0, PipesOr: flags&2 != 0, BitwiseXor: flags&4 != 0, XorAtAdditive: flags&8 != 0, Not: flags&16 != 0}
			if flags&32 != 0 {
				binary.CustomOp = &ast.CustomBinaryOperator{}
			}
			// Nested operands also exercise target precedence and parenthesization.
			nested := *binary
			nested.Left = &ast.BinaryExpression{Left: id, Operator: "^", Right: id}
			for _, expression := range []ast.Expression{binary, &nested} {
				for _, target := range targets {
					if ast.OperatorNeedsRetarget(expression, target) && !renderhint.OperatorMayRetarget(expression) {
						t.Errorf("%T op=%q flags=%06b target=%q: exact retarget escaped superset", expression, op, flags, target)
					}
				}
			}
		}
	}
	for op := ast.Plus; op <= ast.MySQLBinary; op++ {
		expression := &ast.UnaryExpression{Operator: op, Expr: id}
		for _, target := range targets {
			if ast.OperatorNeedsRetarget(expression, target) && !renderhint.OperatorMayRetarget(expression) {
				t.Errorf("unary %s -> %s escapes superset", op, target)
			}
		}
	}

	for _, expression := range []ast.Expression{&ast.UnicodeEscapeExpression{}, &ast.ObjectLiteral{}} {
		for _, target := range targets {
			if ast.OperatorNeedsRetarget(expression, target) && !renderhint.OperatorMayRetarget(expression) {
				t.Errorf("%T target=%s: missing hint", expression, target)
			}
		}
	}
}

func TestDataTypeSuperset(t *testing.T) {
	for _, typ := range []string{"INT", "integer", "VARCHAR(20)", "DOUBLE PRECISION", "TIMESTAMP WITH TIME ZONE", "\"MyType\"", "`MyType`", "[MyType]", "ARRAY(\"MyType\")", "SCHEMA.\"MyType\""} {
		for _, target := range []string{"postgresql", "mysql", "mariadb", "sqlserver", "snowflake", "clickhouse", "sqlite", "oracle", "generic"} {
			if ast.DataTypeNeedsRestyleForDialect(typ, target) && !renderhint.DataTypeMayRestyle(typ) {
				t.Errorf("%s -> %s: missing type hint", typ, target)
			}
		}
	}
}

func TestDirtyStatementBounds(t *testing.T) {
	for _, index := range []int{-1, 64, 65, 100} {
		if !renderhint.Dirty(0, index) {
			t.Errorf("index %d must walk", index)
		}
	}
	if renderhint.Dirty(0, 63) {
		t.Fatal("clean representable statement is dirty")
	}
	if !renderhint.Dirty(uint64(1)<<63, 63) {
		t.Fatal("dirty final bit ignored")
	}
}
