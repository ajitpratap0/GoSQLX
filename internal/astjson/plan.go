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

package astjson

import (
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

type field struct {
	name  string
	key   []byte
	index []int
	typ   reflect.Type
	tag   bool
	child *plan
}

type plan struct {
	kind                                  reflect.Kind
	elem                                  *plan
	fields                                []field
	node, root, literal, marshaler, bytes bool
	addrMarshaler                         bool
	discriminator                         []byte
	err                                   error
}

var (
	astNode       = reflect.TypeFor[ast.Node]()
	astRoot       = reflect.TypeFor[ast.AST]()
	literalType   = reflect.TypeFor[ast.LiteralValue]()
	jsonMarshaler = reflect.TypeFor[json.Marshaler]()
	textMarshaler = reflect.TypeFor[encoding.TextMarshaler]()
	planMu        sync.Mutex
	planCache     atomic.Pointer[map[reflect.Type]*plan]
)

func planFor(t reflect.Type) *plan {
	if cache := planCache.Load(); cache != nil {
		if p := (*cache)[t]; p != nil {
			return p
		}
	}
	planMu.Lock()
	defer planMu.Unlock()
	cache := planCache.Load()
	if cache != nil {
		if p := (*cache)[t]; p != nil {
			return p
		}
	}
	next := make(map[reflect.Type]*plan)
	if cache != nil {
		for k, v := range *cache {
			next[k] = v
		}
	}
	p := buildPlan(t, next)
	// Complete error propagation through recursive placeholders before publishing.
	// Only new plans may be changed; entries in the old snapshot are immutable.
	for changed := true; changed; {
		changed = false
		for typ, candidate := range next {
			if cache != nil && (*cache)[typ] != nil || candidate.err != nil {
				continue
			}
			if candidate.elem != nil {
				candidate.err = candidate.elem.err
			}
			for _, f := range candidate.fields {
				if f.child.err != nil {
					candidate.err = f.child.err
					break
				}
			}
			if candidate.err != nil {
				changed = true
			}
		}
	}
	planCache.Store(&next)
	return p
}

func buildPlan(t reflect.Type, local map[reflect.Type]*plan) *plan {
	if p := local[t]; p != nil {
		return p
	}
	p := &plan{kind: t.Kind()}
	local[t] = p // Recursive static children resolve to this build-local placeholder.
	if t == literalType || (t.Kind() == reflect.Pointer && t.Elem() == literalType) {
		p.literal = true
		p.elem = buildPlan(reflect.TypeFor[any](), local)
		return p
	}
	// encoding/json prefers an addressable pointer's JSON method over a
	// value's Text method. A pointer-only method needs a normal value plan too.
	if t.Kind() != reflect.Pointer && t.Kind() != reflect.Interface {
		ptr := reflect.PointerTo(t)
		p.addrMarshaler = ptr.Implements(jsonMarshaler) || (!t.Implements(jsonMarshaler) && ptr.Implements(textMarshaler))
	}
	if t.Kind() != reflect.Interface && (t.Implements(jsonMarshaler) || t.Implements(textMarshaler)) {
		p.marshaler = true
		return p
	}
	switch t.Kind() {
	case reflect.Struct:
		p.root = t == astRoot
		p.node = reflect.PointerTo(t).Implements(astNode) || t.Implements(astNode)
		p.discriminator = appendString([]byte(`"node_type":`), t.Name())
		var err error
		p.fields, err = typeFields(t)
		if err != nil {
			p.err = err
			return p
		}
		for i := range p.fields {
			f := &p.fields[i]
			f.child = buildPlan(f.typ, local)
			if f.child.err != nil {
				p.err = f.child.err
			}
		}
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
		if t.Kind() == reflect.Map {
			switch t.Key().Kind() {
			case reflect.String, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			default:
				p.err = fmt.Errorf("astjson: unsupported map key %s", t.Key())
				return p
			}
		}
		p.bytes = t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8 && !reflect.PointerTo(t.Elem()).Implements(jsonMarshaler) && !reflect.PointerTo(t.Elem()).Implements(textMarshaler)
		p.elem = buildPlan(t.Elem(), local)
		p.err = p.elem.err
	case reflect.Bool, reflect.String, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr, reflect.Float32, reflect.Float64, reflect.Interface:
	default:
		p.err = fmt.Errorf("astjson: unsupported kind %s", t.Kind())
	}
	return p
}
