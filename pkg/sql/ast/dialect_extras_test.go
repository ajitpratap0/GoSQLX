// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	"reflect"
	"testing"
)

func checkLazyDialectMetadata[T any](t *testing.T, stored func() *T, read func() T, ensure func() *T) {
	t.Helper()
	var zero T
	if stored() != nil || !reflect.DeepEqual(read(), zero) {
		t.Fatal("ordinary node must expose empty metadata without storing it")
	}
	if allocs := testing.AllocsPerRun(100, func() { _ = read() }); allocs != 0 {
		t.Fatalf("reading absent metadata allocated %g times", allocs)
	}
	if stored() != nil {
		t.Fatal("reading metadata allocated a side struct")
	}
	first := ensure()
	if first == nil || stored() != first || !reflect.DeepEqual(read(), *first) || ensure() != first {
		t.Fatal("Ensure must allocate once and reuse the node's metadata")
	}
}

func TestDialectMetadataLazy(t *testing.T) {
	t.Run("literal", func(t *testing.T) {
		n := &LiteralValue{}
		if n.extras != nil || n.DialectExtras() != (LiteralExtras{}) {
			t.Fatal("ordinary literal must have empty metadata")
		}
		if allocs := testing.AllocsPerRun(100, func() { _ = n.DialectExtras() }); allocs != 0 {
			t.Fatalf("reading absent literal metadata allocated %g times", allocs)
		}
		if n.extras != nil {
			t.Fatal("reading literal metadata allocated a side struct")
		}
		first := n.EnsureExtras()
		if first == nil || n.extras != first || n.EnsureExtras() != first {
			t.Fatal("Ensure must allocate once and reuse literal metadata")
		}
		first.Prefix = "N"
		copy := n.DialectExtras()
		copy.Prefix = "X"
		if n.DialectExtras().Prefix != "N" || (&LiteralValue{}).DialectExtras().Prefix != "" {
			t.Fatal("literal metadata leaked across values or nodes")
		}
	})
	t.Run("binary", func(t *testing.T) {
		n := &BinaryExpression{}
		checkLazyDialectMetadata(t, func() *BinaryExtras { return n.Extras }, n.DialectExtras, n.EnsureExtras)
	})
	t.Run("function", func(t *testing.T) {
		n := &FunctionCall{}
		checkLazyDialectMetadata(t, func() *FunctionExtras { return n.Extras }, n.DialectExtras, n.EnsureExtras)
	})
	t.Run("insert", func(t *testing.T) {
		n := &InsertStatement{}
		checkLazyDialectMetadata(t, func() *InsertDialectFields { return n.Extras }, n.DialectExtras, n.EnsureExtras)
	})
	t.Run("select", func(t *testing.T) {
		n := &SelectStatement{}
		checkLazyDialectMetadata(t, func() *SelectExtras { return n.Extras }, n.DialectExtras, n.EnsureExtras)
	})
	t.Run("update", func(t *testing.T) {
		n := &UpdateStatement{}
		checkLazyDialectMetadata(t, func() *DMLTargetFields { return n.Extras }, n.DialectExtras, n.EnsureExtras)
	})
	t.Run("delete", func(t *testing.T) {
		n := &DeleteStatement{}
		checkLazyDialectMetadata(t, func() *DMLTargetFields { return n.Extras }, n.DialectExtras, n.EnsureExtras)
	})
	t.Run("table", func(t *testing.T) {
		n := &TableReference{}
		checkLazyDialectMetadata(t, func() *TableModifiers { return n.Modifiers }, n.DialectModifiers, n.EnsureModifiers)
	})
}

// Mutating a read snapshot must never change the defaults exposed by another
// node. This also checks that Ensure keeps metadata specific to its node.
func checkDialectMetadataIsolation[T any](t *testing.T, read, other func() T, ensure func() *T, mutate func(*T)) {
	t.Helper()
	var zero T
	copy := read()
	mutate(&copy)
	if reflect.DeepEqual(copy, zero) {
		t.Fatal("test mutation did not change metadata")
	}
	if !reflect.DeepEqual(read(), zero) || !reflect.DeepEqual(other(), zero) {
		t.Fatal("read metadata mutation changed node defaults")
	}
	mutate(ensure())
	copy = read()
	if !reflect.DeepEqual(copy, *ensure()) || !reflect.DeepEqual(other(), zero) {
		t.Fatal("Ensure must mutate only its own node")
	}
	copy = zero
	if reflect.DeepEqual(read(), copy) {
		t.Fatal("read metadata must be a detached value")
	}
}

func TestDialectMetadataReadIsolation(t *testing.T) {
	t.Run("function", func(t *testing.T) {
		a, b := &FunctionCall{}, &FunctionCall{}
		checkDialectMetadataIsolation(t, a.DialectExtras, b.DialectExtras, a.EnsureExtras, func(x *FunctionExtras) { x.Separator = &LiteralValue{} })
	})
	t.Run("binary", func(t *testing.T) {
		a, b := &BinaryExpression{}, &BinaryExpression{}
		checkDialectMetadataIsolation(t, a.DialectExtras, b.DialectExtras, a.EnsureExtras, func(x *BinaryExtras) { x.Escape = &Identifier{} })
	})
	t.Run("insert", func(t *testing.T) {
		a, b := &InsertStatement{}, &InsertStatement{}
		checkDialectMetadataIsolation(t, a.DialectExtras, b.DialectExtras, a.EnsureExtras, func(x *InsertDialectFields) { x.RowAlias = "changed" })
	})
	t.Run("select", func(t *testing.T) {
		a, b := &SelectStatement{}, &SelectStatement{}
		checkDialectMetadataIsolation(t, a.DialectExtras, b.DialectExtras, a.EnsureExtras, func(x *SelectExtras) { x.LimitAll = true })
	})
	t.Run("update", func(t *testing.T) {
		a, b := &UpdateStatement{}, &UpdateStatement{}
		checkDialectMetadataIsolation(t, a.DialectExtras, b.DialectExtras, a.EnsureExtras, func(x *DMLTargetFields) { x.Only = true })
	})
	t.Run("delete", func(t *testing.T) {
		a, b := &DeleteStatement{}, &DeleteStatement{}
		checkDialectMetadataIsolation(t, a.DialectExtras, b.DialectExtras, a.EnsureExtras, func(x *DMLTargetFields) { x.Only = true })
	})
	t.Run("table", func(t *testing.T) {
		a, b := &TableReference{}, &TableReference{}
		checkDialectMetadataIsolation(t, a.DialectModifiers, b.DialectModifiers, a.EnsureModifiers, func(x *TableModifiers) { x.Values = &Values{} })
	})
}

// The parser draws tuple expressions from a pool even when their parent is
// heap-allocated. Both release modes must reach tuples held in cold metadata;
// releaseDrawn must continue to leave ordinary expressions to the GC.
func TestDialectMetadataReleaseChildren(t *testing.T) {
	for _, mode := range []releaseMode{releaseAll, releaseDrawn} {
		name := "all"
		if mode == releaseDrawn {
			name = "drawn"
		}
		t.Run(name, func(t *testing.T) {
			for _, kind := range []string{"binary", "function", "insert", "select", "table"} {
				t.Run(kind, func(t *testing.T) {
					child := GetTupleExpression()
					ordinary := &Identifier{Name: "retained_in_drawn_mode"}
					child.Expressions = []Expression{ordinary}
					switch kind {
					case "binary":
						n := &BinaryExpression{}
						n.EnsureExtras().Escape = child
						releaseExpression(n, mode)
						if mode == releaseAll && n.Extras != nil {
							t.Error("binary retained metadata after pooling")
						}
					case "function":
						n := &FunctionCall{}
						n.EnsureExtras().Keep = &KeepClause{OrderBy: []OrderByExpression{{Expression: child}}}
						releaseExpression(n, mode)
						if mode == releaseAll && n.Extras != nil {
							t.Error("function retained metadata after pooling")
						}
					case "insert":
						n := &InsertStatement{}
						n.EnsureExtras().ReturningInto = []Expression{child}
						releaseInsertStatement(n, mode)
						if n.Extras != nil {
							t.Error("insert retained metadata after release")
						}
					case "select":
						n := &SelectStatement{}
						n.EnsureExtras().LimitExpr = child
						releaseSelectStatement(n, mode)
						if n.Extras != nil {
							t.Error("select retained metadata after release")
						}
					case "table":
						n := &TableReference{}
						n.EnsureModifiers().Values = &Values{Rows: [][]Expression{{child}}}
						releaseTableReference(n, mode)
						if n.Modifiers != nil {
							t.Error("table retained modifiers after release")
						}
					}
					if len(child.Expressions) != 0 {
						t.Fatal("release did not reach pooled child in metadata")
					}
					if mode == releaseDrawn && ordinary.Name != "retained_in_drawn_mode" {
						t.Fatal("releaseDrawn reset an ordinary expression")
					}
					if mode == releaseAll && ordinary.Name != "" {
						t.Fatal("releaseAll did not reset descendant")
					}
				})
			}
		})
	}
}

func TestLiteralMetadataPoolReset(t *testing.T) {
	for _, put := range []struct {
		name    string
		release func(*LiteralValue)
	}{
		{"typed", PutLiteralValue},
		{"generic", func(n *LiteralValue) { PutExpression(n) }},
	} {
		t.Run(put.name, func(t *testing.T) {
			n := GetLiteralValue()
			n.Value, n.Type = "value", "string"
			n.EnsureExtras().Prefix = "N"
			n.EnsureExtras().RawBackslash = true
			put.release(n)
			if n.extras != nil || n.Value != nil || n.Type != "" {
				t.Fatal("pooled literal retained metadata or value")
			}
		})
	}
}

func TestDialectMetadataTraversal(t *testing.T) {
	leaf := &Identifier{Name: "cold_child"}
	binary := &BinaryExpression{}
	binary.EnsureExtras().Escape = leaf
	function := &FunctionCall{}
	function.EnsureExtras().Keep = &KeepClause{OrderBy: []OrderByExpression{{Expression: leaf}}}
	separator := &LiteralValue{Value: ",", Type: "string"}
	function.EnsureExtras().Separator = separator
	insert := &InsertStatement{}
	insert.EnsureExtras().ReturningInto = []Expression{leaf}
	selectStmt := &SelectStatement{}
	selectStmt.EnsureExtras().LimitExpr = leaf
	table := &TableReference{}
	table.EnsureModifiers().Values = &Values{Rows: [][]Expression{{leaf}}}
	for _, tc := range []struct {
		name string
		node Node
		want Node
	}{
		{"binary escape", binary, leaf},
		{"function keep", function, leaf},
		{"function separator", function, separator},
		{"insert returning into", insert, leaf},
		{"select limit expression", selectStmt, leaf},
		{"table values", table, leaf},
	} {
		t.Run(tc.name, func(t *testing.T) {
			found := 0
			Inspect(tc.node, func(n Node) bool {
				if n == tc.want {
					found++
				}
				return true
			})
			if found != 1 {
				t.Fatalf("visitor reached metadata child %d times, want 1", found)
			}
		})
	}
}

// Standard dialect strings use the immutable raw marker without paying for a
// metadata allocation. Mutable access must detach from that shared marker.
func TestLiteralRawMetadataIsolation(t *testing.T) {
	if allocs := testing.AllocsPerRun(100, func() {
		n := &LiteralValue{}
		n.SetRawBackslash(true)
		if !n.DialectExtras().RawBackslash {
			t.Fatal("raw marker not applied")
		}
	}); allocs != 0 {
		t.Fatalf("setting raw metadata allocated %g times", allocs)
	}
	first, second := &LiteralValue{}, &LiteralValue{}
	first.SetRawBackslash(true)
	second.SetRawBackslash(true)
	copy := first.DialectExtras()
	copy.RawBackslash = false
	copy.Prefix = "X"
	if first.DialectExtras() != (LiteralExtras{RawBackslash: true}) {
		t.Fatal("modifying metadata value changed shared raw marker")
	}
	first.EnsureExtras().Prefix = "N"
	first.SetRawBackslash(false)
	if got := first.DialectExtras(); got.Prefix != "N" || got.RawBackslash {
		t.Fatalf("raw setter did not preserve custom prefix: %+v", got)
	}
	if second.DialectExtras() != (LiteralExtras{RawBackslash: true}) {
		t.Fatal("mutable metadata changed another raw literal")
	}
	firstMetadata, secondMetadata := first.EnsureExtras(), second.EnsureExtras()
	if firstMetadata == secondMetadata {
		t.Fatal("Ensure shared mutable metadata across literals")
	}
	secondMetadata.Prefix = "B"
	if first.DialectExtras().Prefix != "N" {
		t.Fatal("mutating second literal changed first literal")
	}
	third := &LiteralValue{}
	third.SetRawBackslash(true)
	if third.DialectExtras() != (LiteralExtras{RawBackslash: true}) {
		t.Fatal("Ensure returned the shared raw marker for mutation")
	}
	third.SetRawBackslash(false)
	if third.DialectExtras() != (LiteralExtras{}) {
		t.Fatal("clearing shared raw marker retained metadata")
	}
}
