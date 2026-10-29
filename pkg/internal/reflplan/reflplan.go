// Package reflplan precomputes, per reflect.Type, which parts of a value can
// hold an interface value. Reflective AST walkers use it to skip strings,
// numbers, positions and other leaf data without calling reflect.Type.Field
// on every visit. Plans are immutable once published and safe for concurrent
// use. Reach is the least fixpoint over the reachable type graph, seeded by
// interface kinds. Only exported struct fields participate; Fields contains
// exactly those that reach an interface, in declaration order. Pointer, slice,
// array (including zero-length arrays) and map plans always have Elem set.
// Plans are fully built before LoadOrStore publishes them and never mutated
// afterwards. Walkers prune only interface-free static types: every rewrite
// site is an interface slot, and BinaryExpression, UnaryExpression, FunctionCall,
// ParenthesizedExpression and LiteralValue all reach one. Reachable slots keep
// their original visit order.
package reflplan

import (
	"reflect"
	"sync"
)

// Plan describes how to traverse values of one type.
type Plan struct {
	Type reflect.Type
	Kind reflect.Kind
	// Reach reports whether a value of this type can (transitively, through
	// exported fields, elements, pointers or interfaces) hold an interface.
	Reach bool
	// Fields lists the exported struct fields whose type Reaches, in
	// declaration order.
	Fields []Field
	// Elem is the element plan of a pointer, slice, array or map.
	Elem *Plan
}

// Field is one exported struct field worth visiting.
type Field struct {
	Index int
	Plan  *Plan
}

var cache sync.Map // reflect.Type -> *Plan

// Of returns the plan for t, building it (and the plans of every type
// reachable from t) on first use.
func Of(t reflect.Type) *Plan {
	if p, ok := cache.Load(t); ok {
		if plan, ok := p.(*Plan); ok {
			return plan
		}
	}
	return build(t)
}

type rawField struct {
	index int
	t     reflect.Type
}

func build(root reflect.Type) *Plan {
	local := map[reflect.Type]*Plan{}
	raw := map[*Plan][]rawField{}
	var order []*Plan
	var get func(t reflect.Type) *Plan
	get = func(t reflect.Type) *Plan {
		if p, ok := local[t]; ok {
			return p
		}
		if p, ok := cache.Load(t); ok {
			if plan, ok := p.(*Plan); ok {
				local[t] = plan
				return plan
			}
		}
		p := &Plan{Type: t, Kind: t.Kind(), Reach: t.Kind() == reflect.Interface}
		local[t] = p
		order = append(order, p)
		switch t.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
			p.Elem = get(t.Elem())
		case reflect.Struct:
			var fs []rawField
			for i := 0; i < t.NumField(); i++ {
				if sf := t.Field(i); sf.IsExported() {
					fs = append(fs, rawField{i, sf.Type})
					get(sf.Type)
				}
			}
			raw[p] = fs
		}
		return p
	}
	rootPlan := get(root)
	// Least fixpoint of Reach over the (possibly cyclic) type graph.
	for changed := true; changed; {
		changed = false
		for _, p := range order {
			if p.Reach {
				continue
			}
			switch p.Kind {
			case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
				p.Reach = p.Elem.Reach
			case reflect.Struct:
				for _, f := range raw[p] {
					if local[f.t].Reach {
						p.Reach = true
						break
					}
				}
			}
			changed = changed || p.Reach
		}
	}
	for _, p := range order {
		for _, f := range raw[p] {
			if fp := local[f.t]; fp.Reach {
				p.Fields = append(p.Fields, Field{Index: f.index, Plan: fp})
			}
		}
	}
	for _, p := range order {
		cache.LoadOrStore(p.Type, p)
	}
	return rootPlan
}
