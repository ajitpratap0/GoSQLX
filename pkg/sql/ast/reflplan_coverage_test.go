// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	"reflect"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/internal/reflplan"
)

// Each independent search has its own visited set, so a failed search through
// a cycle cannot hide a different path to an interface. Unlike reflplan this
// uses ordinary graph search, not propagation of Reach through a fixpoint.
func naiveTypeReachesInterface(typ reflect.Type, seen map[reflect.Type]bool) bool {
	if seen[typ] {
		return false
	}
	seen[typ] = true
	switch typ.Kind() {
	case reflect.Interface:
		return true
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
		return naiveTypeReachesInterface(typ.Elem(), seen)
	case reflect.Struct:
		for i := range typ.NumField() {
			f := typ.Field(i)
			if f.IsExported() && naiveTypeReachesInterface(f.Type, seen) {
				return true
			}
		}
	}
	return false
}

func TestReflectionPlanASTCoverage(t *testing.T) {
	visited := map[reflect.Type]bool{}
	var check func(reflect.Type)
	check = func(typ reflect.Type) {
		if visited[typ] {
			return
		}
		visited[typ] = true
		p := reflplan.Of(typ)
		wantReach := naiveTypeReachesInterface(typ, map[reflect.Type]bool{})
		if p.Type != typ || p.Kind != typ.Kind() || p.Reach != wantReach {
			t.Errorf("%v: metadata/reach mismatch: %+v, want Reach=%v", typ, p, wantReach)
		}
		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
			if p.Elem == nil || p.Elem.Type != typ.Elem() {
				t.Errorf("%v: missing/wrong element plan", typ)
			}
			check(typ.Elem())
		case reflect.Struct:
			var want []int
			for i := range typ.NumField() {
				f := typ.Field(i)
				if f.IsExported() && naiveTypeReachesInterface(f.Type, map[reflect.Type]bool{}) {
					want = append(want, i)
				}
				check(f.Type)
			}
			var got []int
			for _, f := range p.Fields {
				got = append(got, f.Index)
				if f.Index < 0 || f.Index >= typ.NumField() {
					t.Errorf("%v: invalid index %d", typ, f.Index)
					continue
				}
				if f.Plan == nil || f.Plan.Type != typ.Field(f.Index).Type {
					t.Errorf("%v field %d: wrong plan", typ, f.Index)
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%v: planned fields %v, want %v", typ, got, want)
			}
		}
	}
	for _, c := range childrenCoverageCases() {
		check(c.typ)
	}
	for _, value := range []any{BinaryExpression{}, UnaryExpression{}, FunctionCall{}, ParenthesizedExpression{}, LiteralValue{}} {
		typ := reflect.TypeOf(value)
		check(typ)
		if !reflplan.Of(typ).Reach {
			t.Errorf("matched rewrite type %v must reach an interface", typ)
		}
	}
}

func TestRetargetScratchSharedPointersTwice(t *testing.T) {
	abs := &UnaryExpression{Operator: PGAbs, Expr: &Identifier{Name: "a"}}
	shared := &BinaryExpression{Left: abs, Operator: "+", Right: &LiteralValue{Type: "number", Value: 1}}
	stmt := &SelectStatement{Columns: []Expression{shared, shared}}
	for run := range 2 {
		// Reuse the same addresses. Stale seen entries would skip the inner
		// unary slot on the second call, even if outer slots were visited.
		shared.Left = abs
		if err := RetargetOperators(stmt, "postgresql", "mysql"); err != nil {
			t.Fatal(err)
		}
		call, ok := shared.Left.(*FunctionCall)
		if !ok || call.Name != "ABS" || len(call.Arguments) != 1 || call.Arguments[0] != abs.Expr {
			t.Fatalf("run %d: shared child not rewritten: %#v", run, shared.Left)
		}
		if stmt.Columns[0] != shared || stmt.Columns[1] != shared {
			t.Fatalf("run %d: shared tree identity changed", run)
		}
	}
}

func TestRetargetScratchReset(t *testing.T) {
	for _, tc := range []struct {
		name           string
		seen, capacity int
		wantKeep       bool
	}{
		{"empty", 0, 0, true},
		{"at_limit", 4096, 4096, true},
		{"seen_over_limit", 4097, 16, false},
		{"stack_over_limit", 1, 4097, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc := &retargetScratch{seen: make(map[uintptr]struct{}, tc.seen), stack: make([]operatorWalkFrame, tc.capacity)}
			for i := range tc.seen {
				sc.seen[uintptr(i+1)] = struct{}{}
			}
			for i := range sc.stack {
				// Frames still on the stack (an early return on error) hold
				// references; reset must drop every reference-bearing field.
				v := reflect.ValueOf(&Identifier{Name: "retained"})
				sc.stack[i] = operatorWalkFrame{
					value: v, plan: reflplan.Of(v.Type()), slot: v,
					mapValue: reflect.ValueOf(map[string]Expression{}),
					mapKey:   reflect.ValueOf("key"),
					iter:     reflect.ValueOf(map[string]Expression{}).MapRange(),
				}
			}
			if keep := sc.reset(); keep != tc.wantKeep {
				t.Fatalf("reset retention = %v, want %v", keep, tc.wantKeep)
			}
			if !tc.wantKeep {
				return
			}
			if len(sc.seen) != 0 || len(sc.stack) != 0 || cap(sc.stack) != tc.capacity {
				t.Fatal("reset did not clear state while preserving reusable capacity")
			}
			for i, frame := range sc.stack[:cap(sc.stack)] {
				if !reflect.DeepEqual(frame, operatorWalkFrame{}) {
					t.Fatalf("frame %d retains state after reset", i)
				}
			}
		})
	}
}

// TestRetargetWalkZeroesPoppedFrames pins the invariant reset relies on:
// after a successful walk no frame up to the stack's capacity still refers
// into the AST, so reset only has to clear the live length.
func TestRetargetWalkZeroesPoppedFrames(t *testing.T) {
	stmt := &SelectStatement{Columns: []Expression{
		&BinaryExpression{Left: &Identifier{Name: "a"}, Operator: "^", Right: &Identifier{Name: "b"}},
		&FunctionCall{Name: "f", Arguments: []Expression{&Identifier{Name: "c"}}},
	}}
	r := operatorRetargeter{from: "mysql", to: "mysql", seen: map[uintptr]struct{}{}}
	stack := r.walk(reflect.ValueOf(stmt), false, make([]operatorWalkFrame, 0, 64))
	if r.err != nil {
		t.Fatalf("walk: %v", r.err)
	}
	if len(stack) != 0 {
		t.Fatalf("stack length after walk = %d, want 0", len(stack))
	}
	for i, frame := range stack[:cap(stack)] {
		if !reflect.DeepEqual(frame, operatorWalkFrame{}) {
			t.Fatalf("frame %d still holds state after a successful walk", i)
		}
	}
}

func TestRetargetScratchHugeThenSmall(t *testing.T) {
	terms := 490000
	if testing.Short() || raceEnabled {
		terms = 5000 // Still exceeds the 4096-entry pool cap.
	}
	var expr Expression = &LiteralValue{Type: "number", Value: 1}
	for range terms {
		expr = &BinaryExpression{Left: expr, Operator: "OR", Right: &LiteralValue{Type: "number", Value: 1}}
	}
	if err := RetargetOperators(&SelectStatement{Columns: []Expression{expr}}, "postgresql", "mysql"); err != nil {
		t.Fatal(err)
	}
	// The small rewrite must not inherit seen entries or an old frame/error.
	small := &SelectStatement{Columns: []Expression{&UnaryExpression{Operator: PGAbs, Expr: &Identifier{Name: "a"}}}}
	if err := RetargetOperators(small, "postgresql", "mysql"); err != nil {
		t.Fatal(err)
	}
	call, ok := small.Columns[0].(*FunctionCall)
	if !ok || call.Name != "ABS" {
		t.Fatalf("small rewrite after huge tree: %#v", small.Columns[0])
	}
}
