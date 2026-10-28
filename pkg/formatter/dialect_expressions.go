// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// FormatASTChecked renders an AST and reports operators that have no equivalent
// in the requested target dialect. It never mutates the caller's tree.
func FormatASTChecked(a *ast.AST, opts ast.FormatOptions) (string, error) {
	if a == nil {
		return "", nil
	}
	n, err := prepareDialectNode(a, opts.Dialect)
	if err != nil {
		return "", err
	}
	copy, ok := n.(*ast.AST)
	if !ok {
		return "", fmt.Errorf("unexpected formatted AST type %T", n)
	}
	return formatAST(copy, opts), nil
}

// FormatStatementChecked is FormatStatement with target-dialect errors.
func FormatStatementChecked(s ast.Statement, opts ast.FormatOptions) (string, error) {
	if s == nil {
		return "", nil
	}
	n, err := prepareDialectNode(s, opts.Dialect)
	if err != nil {
		return "", err
	}
	copy, ok := n.(ast.Statement)
	if !ok {
		return "", fmt.Errorf("unexpected formatted statement type %T", n)
	}
	return formatStatement(copy, opts), nil
}

// FormatExpressionChecked is FormatExpression with target-dialect errors.
func FormatExpressionChecked(e ast.Expression, opts ast.FormatOptions) (string, error) {
	if e == nil {
		return "", nil
	}
	if opts.Dialect == "" {
		return formatExpression(e, opts), nil
	}
	// An expression occupies an ordinary statement slot during the shared
	// rewrite, so nested expressions receive exactly the same semantic checks.
	s := &ast.SelectStatement{Columns: []ast.Expression{e}}
	n, err := prepareDialectNode(s, opts.Dialect)
	if err != nil {
		return "", err
	}
	copy, ok := n.(*ast.SelectStatement)
	if !ok {
		return "", fmt.Errorf("unexpected formatted expression container %T", n)
	}
	return formatExpression(copy.Columns[0], opts), nil
}

func prepareDialectNode(n ast.Node, dialect string) (ast.Node, error) {
	if dialect == "" || nilRenderNode(n) {
		return n, nil
	}
	if !needsDialectRewrite(n, strings.ToLower(dialect)) {
		return n, nil
	}
	v := copyRenderValue(reflect.ValueOf(n), make(map[uintptr]reflect.Value))
	copy, ok := v.Interface().(ast.Node)
	if !ok {
		return nil, fmt.Errorf("cannot render node %T", n)
	}
	if a, ok := copy.(*ast.AST); ok {
		for _, s := range a.Statements {
			if err := ast.RetargetOperators(s, "", dialect); err != nil {
				return nil, err
			}
		}
	} else if s, ok := copy.(ast.Statement); ok {
		if err := ast.RetargetOperators(s, "", dialect); err != nil {
			return nil, err
		}
	}
	ast.RestyleDataTypesForDialect(copy, dialect)
	return copy, nil
}

func needsDialectRewrite(n ast.Node, target string) bool {
	if nilRenderNode(n) {
		return false
	}
	if e, ok := n.(ast.Expression); ok && ast.OperatorNeedsRetarget(e, target) {
		return true
	}
	switch x := n.(type) {
	case *ast.CastExpression:
		if !x.TypeAsString && ast.DataTypeNeedsRestyleForDialect(x.Type, target) {
			return true
		}
	case *ast.ColumnDef:
		if ast.DataTypeNeedsRestyleForDialect(x.Type, target) {
			return true
		}
	case *ast.CreateTableStatement:
		for _, col := range x.Columns {
			if ast.DataTypeNeedsRestyleForDialect(col.Type, target) {
				return true
			}
		}
	case *ast.CreateMaterializedViewStatement:
		for _, col := range x.ColumnDefs {
			if ast.DataTypeNeedsRestyleForDialect(col.Type, target) {
				return true
			}
		}
	case *ast.AlterTableOperation:
		if ast.DataTypeNeedsRestyleForDialect(x.DataType, target) {
			return true
		}
		if x.ColumnDef != nil && ast.DataTypeNeedsRestyleForDialect(x.ColumnDef.Type, target) {
			return true
		}
		for _, col := range x.ColumnDefs {
			if col != nil && ast.DataTypeNeedsRestyleForDialect(col.Type, target) {
				return true
			}
		}
	}
	return childrenNeedDialectRewrite(n, target)
}

func nilRenderNode(n ast.Node) bool {
	if n == nil {
		return true
	}
	v := reflect.ValueOf(n)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

// copyRenderValue copies exported AST storage before dialect rewrites. Private
// literal metadata is read-only and can remain shared with the source tree.
func copyRenderValue(v reflect.Value, seen map[uintptr]reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		if prior, ok := seen[v.Pointer()]; ok {
			return prior
		}
		out := reflect.New(v.Type().Elem())
		seen[v.Pointer()] = out
		out.Elem().Set(copyRenderValue(v.Elem(), seen))
		return out
	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(copyRenderValue(v.Elem(), seen))
		return out
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				out.Field(i).Set(copyRenderValue(v.Field(i), seen))
			}
		}
		return out
	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(copyRenderValue(v.Index(i), seen))
		}
		return out
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			out.SetMapIndex(iter.Key(), copyRenderValue(iter.Value(), seen))
		}
		return out
	case reflect.Array:
		out := reflect.New(v.Type()).Elem()
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(copyRenderValue(v.Index(i), seen))
		}
		return out
	default:
		return v
	}
}
