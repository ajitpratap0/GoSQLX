// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"go/importer"
	"go/token"
	"go/types"
	"reflect"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// directInterfaceType mirrors the runtime direct-interface shape rule.
func directInterfaceType(t types.Type) bool {
	switch t := t.Underlying().(type) {
	case *types.Pointer, *types.Map, *types.Chan, *types.Signature:
		return true
	case *types.Basic:
		return t.Kind() == types.UnsafePointer
	case *types.Array:
		return t.Len() == 1 && directInterfaceType(t.Elem())
	case *types.Struct:
		return t.NumFields() == 1 && directInterfaceType(t.Field(0).Type())
	}
	return false
}

func TestNilRenderNodeValueShapeGuard(t *testing.T) {
	imp := importer.ForCompiler(token.NewFileSet(), "source", nil)
	pkg, err := imp.Import("github.com/ajitpratap0/GoSQLX/pkg/sql/ast")
	if err != nil {
		t.Fatal(err)
	}
	node, ok := pkg.Scope().Lookup("Node").Type().Underlying().(*types.Interface)
	if !ok {
		t.Fatal("ast.Node is not an interface")
	}
	checked := 0
	for _, name := range pkg.Scope().Names() {
		obj, ok := pkg.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		typ, ok := obj.Type().(*types.Named)
		if !ok {
			continue
		}
		if _, ok := typ.Underlying().(*types.Interface); ok {
			continue
		}
		if types.Implements(typ, node) {
			checked++
			if directInterfaceType(typ) {
				t.Errorf("value type ast.%s implements Node and is pointer-shaped", name)
			}
		}
	}
	if checked < 40 {
		t.Fatalf("checked only %d value Node types", checked)
	}
}

func TestNilRenderNodeDifferential(t *testing.T) {
	check := func(n ast.Node) {
		t.Helper()
		want := n == nil
		if !want {
			v := reflect.ValueOf(n)
			want = v.Kind() == reflect.Pointer && v.IsNil()
		}
		if got := nilRenderNode(n); got != want {
			t.Fatalf("%T: got %v, reflect wants %v", n, got, want)
		}
	}
	check(nil)
	for _, n := range nilRenderNodes {
		check(n)
	}
	if len(nilRenderNodes) < 40 {
		t.Fatal("need at least 40 common pointer Node types")
	}
}

var nilRenderNodes = []ast.Node{
	(*ast.AST)(nil),
	(*ast.AliasedExpression)(nil),
	(*ast.AllExpression)(nil),
	(*ast.AlterColumnOperation)(nil),
	(*ast.AlterConnectorOperation)(nil),
	(*ast.AlterPolicyOperation)(nil),
	(*ast.AlterRoleOperation)(nil),
	(*ast.AlterSequenceStatement)(nil),
	(*ast.AlterStatement)(nil),
	(*ast.AlterTableAction)(nil),
	(*ast.AlterTableOperation)(nil),
	(*ast.AlterTableStatement)(nil),
	(*ast.AnyAllExpression)(nil),
	(*ast.AnyExpression)(nil),
	(*ast.ArrayConstructorExpression)(nil),
	(*ast.ArraySliceExpression)(nil),
	(*ast.ArraySubscriptExpression)(nil),
	(*ast.AssignmentExpression)(nil),
	(*ast.AtTimeZoneExpression)(nil),
	(*ast.BetweenExpression)(nil),
	(*ast.BinaryExpression)(nil),
	(*ast.CTECycleClause)(nil),
	(*ast.CallStatement)(nil),
	(*ast.CaseExpression)(nil),
	(*ast.CastExpression)(nil),
	(*ast.ClauseArgument)(nil),
	(*ast.ClusteredBy)(nil),
	(*ast.CollateExpression)(nil),
	(*ast.ColumnConstraint)(nil),
	(*ast.ColumnDef)(nil),
	(*ast.CommentDef)(nil),
	(*ast.CommonTableExpr)(nil),
	(*ast.ConnectByClause)(nil),
	(*ast.ConnectByRootExpression)(nil),
	(*ast.CreateIndexStatement)(nil),
	(*ast.CreateMaterializedViewStatement)(nil),
	(*ast.CreateSequenceStatement)(nil),
	(*ast.CreateTable)(nil),
	(*ast.CreateTableStatement)(nil),
	(*ast.CreateViewStatement)(nil),
	(*ast.CubeExpression)(nil),
	(*ast.DefaultExpr)(nil),
	(*ast.Delete)(nil),
	(*ast.DeleteStatement)(nil),
	(*ast.DescribeStatement)(nil),
	(*ast.DropSequenceStatement)(nil),
	(*ast.DropStatement)(nil),
	(*ast.ExistsExpression)(nil),
	(*ast.ExplainStatement)(nil),
	(*ast.ExtractExpression)(nil),
	(*ast.FetchClause)(nil),
	(*ast.FieldAccessExpression)(nil),
	(*ast.FlashbackClause)(nil),
	(*ast.ForClause)(nil),
	(*ast.ForOutputClause)(nil),
	(*ast.ForSystemTimeClause)(nil),
	(*ast.FunctionCall)(nil),
	(*ast.FunctionDesc)(nil),
	(*ast.GroupingSetsExpression)(nil),
	(*ast.Ident)(nil),
	(*ast.Identifier)(nil),
	(*ast.InExpression)(nil),
	(*ast.IndexColumn)(nil),
	(*ast.Insert)(nil),
	(*ast.InsertStatement)(nil),
	(*ast.InterpolateClause)(nil),
	(*ast.IntervalExpression)(nil),
	(*ast.JSONObjectEntry)(nil),
	(*ast.JoinClause)(nil),
	(*ast.JoinGroup)(nil),
	(*ast.KeepClause)(nil),
	(*ast.KeywordArgument)(nil),
	(*ast.LimitByClause)(nil),
	(*ast.ListExpression)(nil),
	(*ast.LiteralValue)(nil),
	(*ast.LogErrorsClause)(nil),
	(*ast.MatchAgainstExpression)(nil),
	(*ast.MatchRecognizeClause)(nil),
	(*ast.MergeAction)(nil),
	(*ast.MergeStatement)(nil),
	(*ast.MergeWhenClause)(nil),
	(*ast.MultiTableInsert)(nil),
	(*ast.NamedArgument)(nil),
	(*ast.NextValueForExpression)(nil),
	(*ast.ObjectLiteral)(nil),
	(*ast.ObjectName)(nil),
	(*ast.OnConflict)(nil),
	(*ast.OrderByExpression)(nil),
	(*ast.OuterJoinMarker)(nil),
	(*ast.OutputInto)(nil),
	(*ast.ParenthesizedExpression)(nil),
	(*ast.PartitionBy)(nil),
	(*ast.PartitionDefinition)(nil),
	(*ast.PartitionForClause)(nil),
	(*ast.PeriodDefinition)(nil),
	(*ast.PivotClause)(nil),
	(*ast.PositionExpression)(nil),
	(*ast.PragmaStatement)(nil),
	(*ast.Query)(nil),
	(*ast.QueryTail)(nil),
	(*ast.ReferenceDefinition)(nil),
	(*ast.RefreshMaterializedViewStatement)(nil),
	(*ast.ReplaceStatement)(nil),
	(*ast.RollupExpression)(nil),
	(*ast.RowAccessPolicy)(nil),
	(*ast.SampleClause)(nil),
	(*ast.Select)(nil),
	(*ast.SelectInto)(nil),
	(*ast.SelectStatement)(nil),
	(*ast.SetClause)(nil),
	(*ast.SetOperation)(nil),
	(*ast.SetStatement)(nil),
	(*ast.ShowStatement)(nil),
	(*ast.StarExpression)(nil),
	(*ast.StatementImpl)(nil),
	(*ast.SubqueryExpression)(nil),
	(*ast.SubstringExpression)(nil),
	(*ast.SystemVariable)(nil),
	(*ast.TableConstraint)(nil),
	(*ast.TableOption)(nil),
	(*ast.TableReference)(nil),
	(*ast.TableSampleClause)(nil),
	(*ast.TernaryExpression)(nil),
	(*ast.TimeTravelClause)(nil),
	(*ast.TopClause)(nil),
	(*ast.TransactionStatement)(nil),
	(*ast.TriggerEvent)(nil),
	(*ast.TriggerExecBody)(nil),
	(*ast.TriggerObject)(nil),
	(*ast.TriggerPeriod)(nil),
	(*ast.TriggerReferencing)(nil),
	(*ast.TruncateStatement)(nil),
	(*ast.TupleExpression)(nil),
	(*ast.TypedLiteral)(nil),
	(*ast.UnaryExpression)(nil),
	(*ast.UnicodeEscapeExpression)(nil),
	(*ast.UnpivotClause)(nil),
	(*ast.UnsupportedStatement)(nil),
	(*ast.Update)(nil),
	(*ast.UpdateExpression)(nil),
	(*ast.UpdateStatement)(nil),
	(*ast.UpsertClause)(nil),
	(*ast.UseStatement)(nil),
	(*ast.UtilityStatement)(nil),
	(*ast.Value)(nil),
	(*ast.Values)(nil),
	(*ast.VariantPath)(nil),
	(*ast.WhenClause)(nil),
	(*ast.WindowFrame)(nil),
	(*ast.WindowFrameBound)(nil),
	(*ast.WindowSpec)(nil),
	(*ast.WithClause)(nil),
	(*ast.WithFillClause)(nil),
}

// NilRenderNodeForTest exposes the differential probe only in test builds.
func NilRenderNodeForTest(n ast.Node) bool { return nilRenderNode(n) }
