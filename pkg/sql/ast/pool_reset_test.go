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

package ast

import (
	"fmt"
	"reflect"
	"runtime"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// These tests are internal (package ast) because eight expression pools have
// no public Get function. None of them may use t.Parallel: they rely on
// sync.Pool handing the just-Put object back on the same P.

const maxReuseTries = 64

var (
	expressionIfaceType = reflect.TypeOf((*Expression)(nil)).Elem()
	statementIfaceType  = reflect.TypeOf((*Statement)(nil)).Elem()
)

// fillNonZero sets every settable field reachable from v to a non-zero value.
// Pointers get a fresh zero target (non-nil is enough; no recursion, so no
// cycles), slices get one filled element, Expression/Statement interfaces get
// pooled-compatible nodes.
func fillNonZero(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		v.SetUint(1)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if f := v.Field(i); f.CanSet() {
				fillNonZero(f)
			}
		}
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fillNonZero(s.Index(0))
		v.Set(s)
	case reflect.Interface:
		switch {
		case v.Type() == expressionIfaceType:
			v.Set(reflect.ValueOf(&Identifier{Name: "x"}))
		case v.Type() == statementIfaceType:
			v.Set(reflect.ValueOf(GetSelectStatement()))
		case v.Type().NumMethod() == 0:
			v.Set(reflect.ValueOf("v"))
		}
	}
}

// assertFullyReset checks every field of the struct pointed to by v: slices
// must have length 0, every other field must be the zero value.
func assertFullyReset(t *testing.T, label string, v Expression) {
	t.Helper()
	rv := reflect.ValueOf(v).Elem()
	rt := rv.Type()
	for i := 0; i < rv.NumField(); i++ {
		f := rv.Field(i)
		name := rt.Field(i).Name
		if f.Kind() == reflect.Slice {
			if f.Len() != 0 {
				t.Errorf("%s: field %s not reset: len=%d", label, name, f.Len())
			}
			continue
		}
		if !f.IsZero() {
			t.Errorf("%s: field %s not reset: %#v", label, name, f.Interface())
		}
	}
}

type pooledExprCase struct {
	name     string
	get      func() Expression
	typedPut func(t *testing.T, e Expression) // nil when no typed PutX exists
}

// typed adapts a typed PutX wrapper to the table's signature.
func typed[T Expression](put func(T)) func(t *testing.T, e Expression) {
	return func(t *testing.T, e Expression) {
		t.Helper()
		x, ok := e.(T)
		if !ok {
			t.Fatalf("expected %T, got %T", *new(T), e)
		}
		put(x)
	}
}

func poolGet[T Expression](p interface{ Get() any }) func() Expression {
	return func() Expression {
		v, ok := p.Get().(T)
		if !ok {
			panic(fmt.Sprintf("pool returned unexpected type %T", v))
		}
		return v
	}
}

func pooledExpressionCases() []pooledExprCase {
	return []pooledExprCase{
		{"Identifier", func() Expression { return GetIdentifier() }, typed(PutIdentifier)},
		{"LiteralValue", func() Expression { return GetLiteralValue() }, typed(PutLiteralValue)},
		{"BinaryExpression", func() Expression { return GetBinaryExpression() }, typed(PutBinaryExpression)},
		{"FunctionCall", func() Expression { return GetFunctionCall() }, typed(PutFunctionCall)},
		{"CaseExpression", func() Expression { return GetCaseExpression() }, typed(PutCaseExpression)},
		{"BetweenExpression", func() Expression { return GetBetweenExpression() }, typed(PutBetweenExpression)},
		{"InExpression", func() Expression { return GetInExpression() }, typed(PutInExpression)},
		{"SubqueryExpression", func() Expression { return GetSubqueryExpression() }, typed(PutSubqueryExpression)},
		{"CastExpression", func() Expression { return GetCastExpression() }, typed(PutCastExpression)},
		{"IntervalExpression", func() Expression { return GetIntervalExpression() }, typed(PutIntervalExpression)},
		{"ArraySubscriptExpression", func() Expression { return GetArraySubscriptExpression() }, typed(PutArraySubscriptExpression)},
		{"ArraySliceExpression", func() Expression { return GetArraySliceExpression() }, typed(PutArraySliceExpression)},
		{"TupleExpression", func() Expression { return GetTupleExpression() }, typed(PutTupleExpression)},
		{"ArrayConstructorExpression", func() Expression { return GetArrayConstructor() }, typed(PutArrayConstructor)},
		{"AliasedExpression", func() Expression { return GetAliasedExpression() }, typed(PutAliasedExpression)},
		{"ExistsExpression", poolGet[*ExistsExpression](&existsExprPool), nil},
		{"AnyExpression", poolGet[*AnyExpression](&anyExprPool), nil},
		{"AllExpression", poolGet[*AllExpression](&allExprPool), nil},
		{"ListExpression", poolGet[*ListExpression](&listExprPool), nil},
		{"UnaryExpression", poolGet[*UnaryExpression](&unaryExprPool), nil},
		{"ExtractExpression", poolGet[*ExtractExpression](&extractExprPool), nil},
		{"PositionExpression", poolGet[*PositionExpression](&positionExprPool), nil},
		{"SubstringExpression", poolGet[*SubstringExpression](&substringExprPool), nil},
	}
}

// TestPutExpression_ResetsEveryField_Reflective fills every field of every
// pooled expression type, releases it, and checks that the object handed out
// again by the pool is fully zero (slices may keep capacity). A new field
// added to a pooled type without a matching reset fails here.
func TestPutExpression_ResetsEveryField_Reflective(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cases := pooledExpressionCases()
	if len(cases) != 23 {
		t.Fatalf("expected 23 pooled expression types, table has %d", len(cases))
	}
	for _, tc := range cases {
		puts := []struct {
			via string
			put func(t *testing.T, e Expression)
		}{
			{"PutExpression", func(_ *testing.T, e Expression) { PutExpression(e) }},
		}
		if tc.typedPut != nil {
			puts = append(puts, struct {
				via string
				put func(t *testing.T, e Expression)
			}{"Put" + tc.name, tc.typedPut})
		}
		for _, p := range puts {
			t.Run(tc.name+"/"+p.via, func(t *testing.T) {
				v := tc.get()
				for try := 0; try < maxReuseTries; try++ {
					fillNonZero(reflect.ValueOf(v).Elem())
					p.put(t, v)
					w := tc.get()
					if w == v {
						assertFullyReset(t, tc.name, w)
						PutExpression(w)
						return
					}
					v = w
				}
				PutExpression(v)
				t.Fatalf("pool never returned the just-released %s in %d tries; test is vacuous", tc.name, maxReuseTries)
			})
		}
	}
}

// TestPutExpression_FunctionCall_ReleasesOverFilterOrderBy checks that the
// window spec, FILTER, ORDER BY and WITHIN GROUP children are released
// through the queue instead of being dropped.
func TestPutExpression_FunctionCall_ReleasesOverFilterOrderBy(t *testing.T) {
	newID := func(name string) *Identifier {
		id := GetIdentifier()
		id.Name = name
		return id
	}
	filter, ob, wg := newID("filter"), newID("orderby"), newID("withingroup")
	part, overOB, start, end := newID("partition"), newID("over_orderby"), newID("start"), newID("end")
	fillFrom := newID("fill_from")

	fc := GetFunctionCall()
	fc.Name = "agg"
	fc.Filter = filter
	fc.OrderBy = []OrderByExpression{{Expression: ob, WithFill: &WithFillClause{From: fillFrom}}}
	fc.WithinGroup = []OrderByExpression{{Expression: wg}}
	fc.NullTreatment = "IGNORE NULLS"
	fc.Pos = models.Location{Line: 2, Column: 5}
	fc.Over = &WindowSpec{
		PartitionBy: []Expression{part},
		OrderBy:     []OrderByExpression{{Expression: overOB}},
		FrameClause: &WindowFrame{
			Type:  "ROWS",
			Start: WindowFrameBound{Type: "PRECEDING", Value: start},
			End:   &WindowFrameBound{Type: "FOLLOWING", Value: end},
		},
	}

	PutExpression(fc)

	for _, id := range []*Identifier{filter, ob, wg, part, overOB, start, end, fillFrom} {
		if id.Name != "" {
			t.Errorf("identifier %q was not released by PutExpression(FunctionCall)", id.Name)
		}
	}
	if fc.Over != nil || fc.Filter != nil || len(fc.OrderBy) != 0 || len(fc.WithinGroup) != 0 {
		t.Errorf("FunctionCall children not detached: Over=%v Filter=%v OrderBy=%d WithinGroup=%d",
			fc.Over, fc.Filter, len(fc.OrderBy), len(fc.WithinGroup))
	}
	if fc.NullTreatment != "" || fc.Pos != (models.Location{}) || fc.Name != "" {
		t.Errorf("FunctionCall scalars not reset: Name=%q NullTreatment=%q Pos=%+v", fc.Name, fc.NullTreatment, fc.Pos)
	}
}

// TestPutExpression_UnpooledParents_ReleaseChildren checks the pass-through
// cases: the parent has no pool, but its pooled children are released and
// detached.
func TestPutExpression_UnpooledParents_ReleaseChildren(t *testing.T) {
	newID := func() *Identifier {
		id := GetIdentifier()
		id.Name = "child"
		return id
	}
	cases := []struct {
		name     string
		build    func(a, b *Identifier) Expression
		detached func(e Expression) bool
	}{
		{
			"RollupExpression",
			func(a, b *Identifier) Expression { return &RollupExpression{Expressions: []Expression{a, b}} },
			func(e Expression) bool { r, ok := e.(*RollupExpression); return ok && len(r.Expressions) == 0 },
		},
		{
			"CubeExpression",
			func(a, b *Identifier) Expression { return &CubeExpression{Expressions: []Expression{a, b}} },
			func(e Expression) bool { c, ok := e.(*CubeExpression); return ok && len(c.Expressions) == 0 },
		},
		{
			"GroupingSetsExpression",
			func(a, b *Identifier) Expression {
				return &GroupingSetsExpression{Sets: [][]Expression{{a}, {b}}}
			},
			func(e Expression) bool { g, ok := e.(*GroupingSetsExpression); return ok && len(g.Sets) == 0 },
		},
		{
			"NamedArgument",
			func(a, b *Identifier) Expression {
				return &NamedArgument{Name: "n", Value: &BinaryExpression{Left: a, Operator: "+", Right: b}}
			},
			func(e Expression) bool { n, ok := e.(*NamedArgument); return ok && n.Value == nil },
		},
		{
			"StarExpression",
			func(a, b *Identifier) Expression {
				return &StarExpression{Star: &Identifier{Name: "*"}, Ilike: a, Replace: []*AliasedExpression{{Expr: b, Alias: "c"}}}
			},
			func(e Expression) bool {
				s, ok := e.(*StarExpression)
				return ok && s.Star == nil && s.Ilike == nil && len(s.Replace) == 0
			},
		},
		{
			"VariantPath",
			func(a, b *Identifier) Expression {
				return &VariantPath{Root: a, Segments: []VariantPathSegment{{Name: "f"}, {Index: b}}}
			},
			func(e Expression) bool {
				v, ok := e.(*VariantPath)
				return ok && v.Root == nil && v.Segments[1].Index == nil
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newID(), newID()
			parent := tc.build(a, b)
			PutExpression(parent)
			if !tc.detached(parent) {
				t.Errorf("%s still references its children after PutExpression", tc.name)
			}
			if a.Name != "" || b.Name != "" {
				t.Errorf("%s children were not released: a=%q b=%q", tc.name, a.Name, b.Name)
			}
		})
	}
}

func bigInList(n int) *InExpression {
	in := GetInExpression()
	for i := 0; i < n; i++ {
		in.List = append(in.List, GetLiteralValue())
	}
	return in
}

// TestPutExpression_WorkQueueNotPinnedByBigList: releasing one huge list must
// not leave a huge work queue in the pool.
func TestPutExpression_WorkQueueNotPinnedByBigList(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	PutExpression(bigInList(20_000))

	qp, ok := putExpressionWorkQueuePool.Get().(*[]Expression)
	if !ok {
		t.Fatal("work queue pool returned unexpected type")
	}
	defer putExpressionWorkQueuePool.Put(qp)
	if cap(*qp) > maxPooledWorkQueueCap {
		t.Errorf("pooled work queue cap = %d, want <= %d", cap(*qp), maxPooledWorkQueueCap)
	}
	if len(*qp) != 0 {
		t.Errorf("pooled work queue len = %d, want 0", len(*qp))
	}
}

// TestPutExpression_WorkQueueClearedToHighWater: after a release that grew
// the queue past its initial capacity, no slot of the pooled queue may still
// hold an Expression pointer.
func TestPutExpression_WorkQueueClearedToHighWater(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	fc := GetFunctionCall()
	for i := 0; i < 50; i++ {
		be := GetBinaryExpression()
		be.Left = GetIdentifier()
		be.Right = GetIdentifier()
		fc.Arguments = append(fc.Arguments, be)
	}
	PutExpression(fc)

	qp, ok := putExpressionWorkQueuePool.Get().(*[]Expression)
	if !ok {
		t.Fatal("work queue pool returned unexpected type")
	}
	defer putExpressionWorkQueuePool.Put(qp)
	full := (*qp)[:cap(*qp)]
	for i, e := range full {
		if e != nil {
			t.Fatalf("pooled work queue slot %d (cap %d) still holds %T", i, cap(*qp), e)
		}
	}
}

// TestStatementPut_ResetsPos checks that the DML statement Puts reset Pos.
func TestStatementPut_ResetsPos(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pos := models.Location{Line: 7, Column: 3}
	cases := []struct {
		name string
		run  func() (reused bool, got models.Location)
	}{
		{"Select", func() (bool, models.Location) {
			s := GetSelectStatement()
			s.Pos = pos
			PutSelectStatement(s)
			s2 := GetSelectStatement()
			defer PutSelectStatement(s2)
			return s == s2, s2.Pos
		}},
		{"Insert", func() (bool, models.Location) {
			s := GetInsertStatement()
			s.Pos = pos
			PutInsertStatement(s)
			s2 := GetInsertStatement()
			defer PutInsertStatement(s2)
			return s == s2, s2.Pos
		}},
		{"Update", func() (bool, models.Location) {
			s := GetUpdateStatement()
			s.Pos = pos
			PutUpdateStatement(s)
			s2 := GetUpdateStatement()
			defer PutUpdateStatement(s2)
			return s == s2, s2.Pos
		}},
		{"Delete", func() (bool, models.Location) {
			s := GetDeleteStatement()
			s.Pos = pos
			PutDeleteStatement(s)
			s2 := GetDeleteStatement()
			defer PutDeleteStatement(s2)
			return s == s2, s2.Pos
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for try := 0; try < maxReuseTries; try++ {
				reused, got := tc.run()
				if !reused {
					continue
				}
				if got != (models.Location{}) {
					t.Errorf("%sStatement.Pos not reset: %+v", tc.name, got)
				}
				return
			}
			t.Fatalf("pool never returned the just-released %sStatement in %d tries; test is vacuous", tc.name, maxReuseTries)
		})
	}
}
