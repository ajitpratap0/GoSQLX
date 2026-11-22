package ast

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

// This file guards the aliasing contract documented on Walk: every child a
// visitor receives must point into the parent's own storage (a field, or the
// backing array of a slice field), never into a heap copy. A value-receiver
// Children() that returns &field points into the receiver COPY, so visitor
// mutations would be silently lost. Such nodes must expose a pointer-receiver
// childrenInPlace and be routed through childrenOf (see JoinClause,
// WindowFrame, MergeStatement, Insert, Delete, Update).
//
// If TestWalk_ChildPointersAliasParentStorage fails for a node, do NOT relax
// the test: add a childrenInPlace method for that type and a case for it in
// childrenOf (visitor.go), then extend TestChildrenOf_InPlaceFastPath.

// aliasCheckTypes lists the Node types exercised by the aliasing test. Add new
// Node types that implement Children() here.
var aliasCheckTypes = []any{
	(*AliasedExpression)(nil),
	(*AllExpression)(nil),
	(*AlterColumnOperation)(nil),
	(*AlterConnectorOperation)(nil),
	(*AlterPolicyOperation)(nil),
	(*AlterRoleOperation)(nil),
	(*AlterSequenceStatement)(nil),
	(*AlterStatement)(nil),
	(*AlterTableAction)(nil),
	(*AlterTableOperation)(nil),
	(*AlterTableStatement)(nil),
	(*AnyExpression)(nil),
	(*ArrayConstructorExpression)(nil),
	(*ArraySliceExpression)(nil),
	(*ArraySubscriptExpression)(nil),
	(*AST)(nil),
	(*BetweenExpression)(nil),
	(*BinaryExpression)(nil),
	(*CaseExpression)(nil),
	(*CastExpression)(nil),
	(*ClusteredBy)(nil),
	(*ColumnConstraint)(nil),
	(*ColumnDef)(nil),
	(*CommentDef)(nil),
	(*CommonTableExpr)(nil),
	(*ConnectByClause)(nil),
	(*CreateIndexStatement)(nil),
	(*CreateMaterializedViewStatement)(nil),
	(*CreateSequenceStatement)(nil),
	(*CreateTable)(nil),
	(*CreateTableStatement)(nil),
	(*CreateViewStatement)(nil),
	(*CubeExpression)(nil),
	(*Delete)(nil),
	(*DeleteStatement)(nil),
	(*DescribeStatement)(nil),
	(*DropSequenceStatement)(nil),
	(*DropStatement)(nil),
	(*ExistsExpression)(nil),
	(*ExtractExpression)(nil),
	(*FetchClause)(nil),
	(*ForClause)(nil),
	(*ForSystemTimeClause)(nil),
	(*FunctionCall)(nil),
	(*FunctionDesc)(nil),
	(*GroupingSetsExpression)(nil),
	(*Ident)(nil),
	(*Identifier)(nil),
	(*IndexColumn)(nil),
	(*InExpression)(nil),
	(*Insert)(nil),
	(*InsertStatement)(nil),
	(*IntervalExpression)(nil),
	(*JoinClause)(nil),
	(*JoinGroup)(nil),
	(*ClauseArgument)(nil),
	(*LogErrorsClause)(nil),
	(*ListExpression)(nil),
	(*LiteralValue)(nil),
	(*MatchRecognizeClause)(nil),
	(*MergeAction)(nil),
	(*MergeStatement)(nil),
	(*MergeWhenClause)(nil),
	(*NamedArgument)(nil),
	(*ObjectLiteral)(nil),
	(*ObjectName)(nil),
	(*QueryTail)(nil),
	(*OnConflict)(nil),
	(*OrderByExpression)(nil),
	(*ParenthesizedExpression)(nil),
	(*PartitionBy)(nil),
	(*PartitionDefinition)(nil),
	(*PeriodDefinition)(nil),
	(*PivotClause)(nil),
	(*PositionExpression)(nil),
	(*PragmaStatement)(nil),
	(*Query)(nil),
	(*ReferenceDefinition)(nil),
	(*RefreshMaterializedViewStatement)(nil),
	(*ReplaceStatement)(nil),
	(*RollupExpression)(nil),
	(*RowAccessPolicy)(nil),
	(*SampleClause)(nil),
	(*Select)(nil),
	(*SelectStatement)(nil),
	(*SetClause)(nil),
	(*SetOperation)(nil),
	(*ShowStatement)(nil),
	(*StatementImpl)(nil),
	(*SubqueryExpression)(nil),
	(*SubstringExpression)(nil),
	(*TableConstraint)(nil),
	(*TableOption)(nil),
	(*TableReference)(nil),
	(*TimeTravelClause)(nil),
	(*TopClause)(nil),
	(*TriggerEvent)(nil),
	(*TriggerExecBody)(nil),
	(*TriggerObject)(nil),
	(*TriggerPeriod)(nil),
	(*TriggerReferencing)(nil),
	(*TruncateStatement)(nil),
	(*TupleExpression)(nil),
	(*UnaryExpression)(nil),
	(*UnpivotClause)(nil),
	(*UnsupportedStatement)(nil),
	(*Update)(nil),
	(*UpdateExpression)(nil),
	(*UpdateStatement)(nil),
	(*UpsertClause)(nil),
	(*Value)(nil),
	(*Values)(nil),
	(*VariantPath)(nil),
	(*WhenClause)(nil),
	(*WindowFrame)(nil),
	(*WindowFrameBound)(nil),
	(*WindowSpec)(nil),
	(*WithClause)(nil),
	(*WithFillClause)(nil),
}

// aliasFillCandidates are concrete values used to populate interface-typed
// fields (Expression, Statement, Node, ...) with distinct, non-nil children.
var aliasFillCandidates = []any{&Identifier{Name: "x"}, &SelectStatement{}, &WindowSpec{}, &WithClause{}, &TableReference{}}

// aliasFill populates exported fields reflectively so Children() has
// something to return for every field kind.
func aliasFill(v reflect.Value, depth int) {
	switch v.Kind() {
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Interface:
		for _, c := range aliasFillCandidates {
			cv := reflect.ValueOf(c)
			if cv.Type().Implements(v.Type()) {
				nv := reflect.New(cv.Type().Elem()) // fresh instance each time
				if id, ok := nv.Interface().(*Identifier); ok {
					id.Name = "x"
				}
				v.Set(nv)
				return
			}
		}
	case reflect.Ptr:
		if depth > 2 || v.Type().Elem().Kind() != reflect.Struct {
			return
		}
		nv := reflect.New(v.Type().Elem())
		aliasFill(nv.Elem(), depth+1)
		v.Set(nv)
	case reflect.Slice:
		if depth > 3 {
			return
		}
		s := reflect.MakeSlice(v.Type(), 2, 2)
		for i := 0; i < 2; i++ {
			aliasFill(s.Index(i), depth+1)
		}
		v.Set(s)
	case reflect.Struct:
		if depth > 4 {
			return
		}
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() && v.Field(i).CanSet() {
				aliasFill(v.Field(i), depth+1)
			}
		}
	}
}

type aliasRange struct{ lo, hi uintptr }

// aliasCollect records the storage ranges of slice backing arrays reachable
// from v and the pointers it holds. A child that is one of those pointers, or
// lies inside one of those ranges, is owned by the parent. A pointer to a
// plain (non-Node) struct, such as SelectStatement.Extras, is storage the
// parent owns through one indirection, so it is searched too.
func aliasCollect(v reflect.Value, ranges *[]aliasRange, ptrs map[uintptr]bool) {
	switch v.Kind() {
	case reflect.Ptr:
		if !v.IsNil() {
			if !ptrs[v.Pointer()] && v.Elem().Kind() == reflect.Struct && !v.Type().Implements(reflect.TypeOf((*Node)(nil)).Elem()) {
				ptrs[v.Pointer()] = true
				aliasCollect(v.Elem(), ranges, ptrs)
			}
			ptrs[v.Pointer()] = true
		}
	case reflect.Interface:
		if !v.IsNil() {
			if e := v.Elem(); e.Kind() == reflect.Ptr {
				ptrs[e.Pointer()] = true
			}
		}
	case reflect.Slice:
		if v.Len() > 0 {
			lo := v.Pointer()
			*ranges = append(*ranges, aliasRange{lo, lo + uintptr(v.Len())*v.Type().Elem().Size()})
			for i := 0; i < v.Len(); i++ {
				aliasCollect(v.Index(i), ranges, ptrs)
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			aliasCollect(v.Field(i), ranges, ptrs)
		}
	}
}

// aliasLeaves is a Visitor that records the direct children of root without
// descending into them.
type aliasLeaves struct {
	root Node
	got  []Node
}

func (d *aliasLeaves) Visit(n Node) (Visitor, error) {
	if n == nil {
		return nil, nil
	}
	if n == d.root {
		return d, nil
	}
	d.got = append(d.got, n)
	return nil, nil
}

// aliasDetached returns the types of kids that do not alias parent's storage.
func aliasDetached(parent reflect.Value, kids []Node) (detached []string) {
	var ranges []aliasRange
	ptrs := map[uintptr]bool{}
	el := parent.Elem()
	lo := parent.Pointer()
	ranges = append(ranges, aliasRange{lo, lo + el.Type().Size()})
	aliasCollect(el, &ranges, ptrs)
	for _, k := range kids {
		kv := reflect.ValueOf(k)
		if kv.Kind() != reflect.Ptr {
			// A node stored by value in the interface is a snapshot the
			// visitor cannot mutate through; that is a different (known)
			// limitation, not pointer aliasing into a receiver copy.
			continue
		}
		p := kv.Pointer()
		ok := ptrs[p]
		for _, r := range ranges {
			if p >= r.lo && p < r.hi {
				ok = true
			}
		}
		if !ok {
			detached = append(detached, fmt.Sprintf("%T", k))
		}
	}
	return detached
}

// TestWalk_ChildPointersAliasParentStorage fills every listed Node type and
// asserts that each child pointer Walk yields lies inside the parent's own
// storage. Calling the exported Children() on a value is documented to return
// copies, so that path is not checked; only Walk's path is.
func TestWalk_ChildPointersAliasParentStorage(t *testing.T) {
	var failures []string
	for _, x := range aliasCheckTypes {
		pt := reflect.TypeOf(x)
		if pt.Elem().Kind() != reflect.Struct {
			continue
		}
		pv := reflect.New(pt.Elem())
		aliasFill(pv.Elem(), 0)
		node, ok := pv.Interface().(Node)
		if !ok {
			continue
		}
		d := &aliasLeaves{root: node}
		func() {
			defer func() {
				if r := recover(); r != nil {
					failures = append(failures, fmt.Sprintf("%s: panic %v", pt.Elem().Name(), r))
				}
			}()
			if err := Walk(d, node); err != nil {
				failures = append(failures, fmt.Sprintf("%s: Walk error %v", pt.Elem().Name(), err))
				return
			}
			if det := aliasDetached(pv, d.got); len(det) > 0 {
				failures = append(failures, fmt.Sprintf("%s: Walk yields children outside the parent's storage: %v", pt.Elem().Name(), det))
			}
		}()
	}
	sort.Strings(failures)
	for _, f := range failures {
		t.Error(f)
	}
	if len(failures) > 0 {
		t.Log("a value-receiver Children() returning &field points into the receiver copy; add a childrenInPlace method and route the type through childrenOf (visitor.go)")
	}
}
