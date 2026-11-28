// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package goldens

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// Tokens renders a token stream one token per line:
//
//	<start>-<end> <type> <value> [q=<quote>] [long] [w=<word>|<quote style>|<keyword>|<reserved>]
//
// Every field of models.TokenWithSpan is included, so a change to a type,
// value, span, quote, Long flag or Word (including a nil Word) shows up.
func Tokens(toks []models.TokenWithSpan) string {
	var b strings.Builder
	for _, t := range toks {
		fmt.Fprintf(&b, "%s-%s %s %s", loc(t.Start), loc(t.End), t.Token.Type, strconv.Quote(t.Token.Value))
		if t.Token.Quote != 0 {
			fmt.Fprintf(&b, " q=%q", t.Token.Quote)
		}
		if t.Token.Long {
			b.WriteString(" long")
		}
		if w := t.Token.Word; w != nil {
			fmt.Fprintf(&b, " w=%s|%q|", strconv.Quote(w.Value), w.QuoteStyle)
			if w.Keyword != nil {
				fmt.Fprintf(&b, "%s|%t", w.Keyword.Word, w.Keyword.Reserved)
			} else {
				b.WriteString("-")
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func loc(l models.Location) string { return strconv.Itoa(l.Line) + ":" + strconv.Itoa(l.Column) }

// Error renders an error with its structured code and location, so a change
// of code or position is visible even when the message text is unchanged.
func Error(err error) string {
	if err == nil {
		return "ok"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "error code=%s", gosqlx.ErrorCode(err))
	if l := gosqlx.ErrorLocation(err); l != nil {
		fmt.Fprintf(&b, " at=%s", loc(*l))
	}
	if h := gosqlx.ErrorHint(err); h != "" {
		fmt.Fprintf(&b, " hint=%s", strconv.Quote(h))
	}
	fmt.Fprintf(&b, "\n%s", err.Error())
	return b.String()
}

var (
	locationType = reflect.TypeOf(models.Location{})
	modulePrefix = reflect.TypeOf(ast.AST{}).PkgPath()[:len("github.com/ajitpratap0/GoSQLX")]
)

// Positions renders every models.Location reachable from tree, in field
// declaration order, as an indented outline: one line per struct on the way
// (its field path, with the dynamic type after an interface) and one
// "<field> <line>:<column>" line per Location. Spans are covered through
// their Start and End fields. Only types of this module are traversed; maps
// are visited in sorted key order; a struct pointer reached a second time (a
// shared node) is printed as a reference to its first path.
//
// It complements AST.SQL(), which carries no positions: a parser change that
// moves any Pos, StatementStarts, comment span or other location shows up
// here even when the rendered SQL is unchanged.
func Positions(tree *ast.AST) string {
	if tree == nil {
		return ""
	}
	w := posWalker{seen: map[ptrKey]string{}}
	w.walk(reflect.ValueOf(tree).Elem(), "")
	return w.b.String()
}

// ptrKey identifies a struct pointer by address and type: a struct and its
// first field share an address.
type ptrKey struct {
	addr uintptr
	typ  reflect.Type
}

type posWalker struct {
	b       strings.Builder
	seen    map[ptrKey]string
	stack   []string // labels of the structs being walked
	printed int      // stack entries already written
}

// flush writes the struct labels not yet printed, then returns the indent
// for a line inside the innermost struct.
// The root struct (the AST itself, stack[0]) has no line of its own.
func (w *posWalker) flush() string {
	for ; w.printed < len(w.stack); w.printed++ {
		if w.printed == 0 {
			continue
		}
		w.b.WriteString(strings.Repeat("  ", w.printed-1))
		w.b.WriteString(w.stack[w.printed])
		w.b.WriteByte('\n')
	}
	return strings.Repeat("  ", len(w.stack)-1)
}

// walk visits v; seg is its path from the innermost enclosing struct.
func (w *posWalker) walk(v reflect.Value, seg string) {
	t := v.Type()
	if t == locationType {
		fmt.Fprintf(&w.b, "%s%s %d:%d\n", w.flush(), seg, v.Field(0).Int(), v.Field(1).Int())
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() || !inModule(t.Elem()) {
			return
		}
		if t.Elem().Kind() == reflect.Struct {
			key := ptrKey{v.Pointer(), t}
			if first, ok := w.seen[key]; ok {
				fmt.Fprintf(&w.b, "%s%s = %s\n", w.flush(), seg, first)
				return
			}
			w.seen[key] = strings.Join(append(w.stack[1:len(w.stack):len(w.stack)], seg), "/")
		}
		w.walk(v.Elem(), seg)
	case reflect.Interface:
		if v.IsNil() {
			return
		}
		e := v.Elem()
		w.walk(e, seg+"("+typeName(e.Type())+")")
	case reflect.Struct:
		if !inModule(t) {
			return
		}
		w.stack = append(w.stack, seg)
		for i := 0; i < t.NumField(); i++ {
			if mayHoldLocation(t.Field(i).Type) {
				w.walk(v.Field(i), t.Field(i).Name)
			}
		}
		w.stack = w.stack[:len(w.stack)-1]
		w.printed = min(w.printed, len(w.stack))
	case reflect.Slice, reflect.Array:
		if !mayHoldLocation(t.Elem()) {
			return
		}
		for i := 0; i < v.Len(); i++ {
			w.walk(v.Index(i), seg+"["+strconv.Itoa(i)+"]")
		}
	case reflect.Map:
		if !mayHoldLocation(t.Elem()) {
			return
		}
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
		for _, k := range keys {
			w.walk(v.MapIndex(k), seg+"["+fmt.Sprint(k)+"]")
		}
	}
}

func typeName(t reflect.Type) string {
	s := t.String()
	return strings.TrimPrefix(strings.TrimPrefix(s, "*ast."), "ast.")
}

func inModule(t reflect.Type) bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return strings.HasPrefix(t.PkgPath(), modulePrefix)
}

// mayHoldLocation reports whether a value of type t can contain a Location
// that Positions would visit. Interfaces always may.
func mayHoldLocation(t reflect.Type) bool {
	return mayHold(t, map[reflect.Type]bool{})
}

// mayHoldCache maps reflect.Type to the final mayHold answer.
var mayHoldCache sync.Map

func mayHold(t reflect.Type, visiting map[reflect.Type]bool) bool {
	if r, ok := mayHoldCache.Load(t); ok {
		b, ok := r.(bool)
		return ok && b
	}
	if visiting[t] {
		return false // recursion: answered by the outer call
	}
	visiting[t] = true
	r := false
	switch t.Kind() {
	case reflect.Interface:
		r = true
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
		r = mayHold(t.Elem(), visiting)
	case reflect.Struct:
		if t == locationType {
			r = true
			break
		}
		if !inModule(t) {
			break
		}
		for i := 0; i < t.NumField(); i++ {
			if mayHold(t.Field(i).Type, visiting) {
				r = true
				break
			}
		}
	}
	delete(visiting, t)
	if len(visiting) == 0 || r {
		mayHoldCache.Store(t, r)
	}
	return r
}
