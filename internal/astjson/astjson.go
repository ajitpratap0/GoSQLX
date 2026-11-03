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

// Package astjson encodes AST JSON v1.
//
// 1. Document: `{"version":1,"node_type":"AST",<AST fields>}`; compact (no insignificant whitespace); deterministic bytes for a given tree.
// 2. Discriminator: every JSON object for a struct type T where `*T` or `T` implements `ast.Node`, plus the root, starts with `"node_type":"<T's Go type name>"` (e.g. `SelectStatement`, `Identifier`, `LiteralValue`). Non-node structs (`models.Location`, `models.Comment`, `UnicodeIdentifierSpelling`, `*Extras` types) carry no discriminator. Key is `node_type`, not `type`: many nodes have a Go field `Type` (LiteralValue, ColumnDef...) and case-only-distinct keys confuse consumers; AstTab already recognises `node_type`.
// 3. Field keys and order: exactly what `encoding/json` would produce for the same value (Go field names, struct order, embedded structs promoted with encoding/json's dominance rules, `json:"name"` / `json:"-"` honoured). No AST type has json tags today.
// 4. Omission (object fields only): nil pointer; nil interface, or interface holding a typed-nil pointer; nil/empty slice, array of length 0, nil/empty map; `""`; `false`; numeric 0; a non-pointer struct value that is `reflect.Value.IsZero()`. **An omitted field means the Go zero value.**
// 5. Never omitted: a non-nil pointer (presence is semantic) even if its pointee is all-zero (emits `{}` or `{"node_type":"X"}`); slice/array elements (nil element -> `null`, positions kept); map values.
// 6. Scalars: strings escaped like encoding/json minus HTML escaping (`<`,`>`,`&` stay literal; control chars, `"`, `\\`, U+2028/U+2029 escaped; invalid UTF-8 -> `�`); ints/uints decimal; floats formatted exactly as encoding/json (copy its `floatEncoder` rule); `[]byte` base64 (parity); map keys: string/int/uint kinds, sorted by their string form as encoding/json does.
// 7. `ast.LiteralValue`: native encoder mirroring `LiteralValue.MarshalJSON` (pkg/sql/ast/literal_json.go): `node_type`, `Value`, `Type`, `Prefix`, `RawBackslash` with rule 4 omission; reads extras via `DialectExtras()`. Any other `json.Marshaler` / `encoding.TextMarshaler` reachable: call it and append the compacted result (correct fallback; none exist today).
package astjson

import (
	"bytes"
	"encoding"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// Version is the compact typed AST JSON document version.
const Version = 1

// Append appends the AST JSON v1 document for tree to dst.
func Append(dst []byte, tree *ast.AST) ([]byte, error) {
	if tree == nil {
		return dst, fmt.Errorf("astjson: nil tree")
	}
	return appendValue(dst, reflect.ValueOf(tree))
}

// Marshal is Append(nil, tree).
func Marshal(tree *ast.AST) ([]byte, error) { return Append(nil, tree) }

func appendValue(dst []byte, v reflect.Value) ([]byte, error) {
	if !v.IsValid() {
		return append(dst, "null"...), nil
	}
	p := planFor(v.Type())
	return p.append(dst, v, 0)
}

func omitted(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Interface:
		return v.IsNil() || (v.Elem().Kind() == reflect.Pointer && v.Elem().IsNil())
	case reflect.Pointer:
		return v.IsNil()
	case reflect.Slice, reflect.Array, reflect.Map, reflect.String:
		return v.Len() == 0
	default:
		return v.IsZero()
	}
}

func (p *plan) append(dst []byte, v reflect.Value, depth int) ([]byte, error) {
	if p.err != nil {
		return dst, p.err
	}
	if depth > 10000 {
		return dst, fmt.Errorf("astjson: nesting exceeds 10000")
	}
	if (p.kind == reflect.Pointer || p.kind == reflect.Interface) && v.IsNil() {
		return append(dst, "null"...), nil
	}
	if p.literal {
		return p.appendLiteral(dst, v, depth)
	}
	if p.addrMarshaler && v.CanAddr() {
		return appendMarshaler(dst, v.Addr())
	}
	if p.marshaler {
		return appendMarshaler(dst, v)
	}
	if (p.kind == reflect.Map || p.kind == reflect.Slice) && v.IsNil() {
		return append(dst, "null"...), nil
	}
	switch p.kind {
	case reflect.Pointer:
		return p.elem.append(dst, v.Elem(), depth+1)
	case reflect.Interface:
		x := v.Elem()
		return planFor(x.Type()).append(dst, x, depth+1)
	case reflect.Bool:
		return strconv.AppendBool(dst, v.Bool()), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.AppendInt(dst, v.Int(), 10), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return strconv.AppendUint(dst, v.Uint(), 10), nil
	case reflect.Float32, reflect.Float64:
		f := v.Float()
		bits := v.Type().Bits()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return dst, fmt.Errorf("astjson: unsupported float %v", f)
		}
		// Adapted from encoding/json.floatEncoder (Go Authors, BSD-3-Clause).
		abs := math.Abs(f)
		format := byte('f')
		if abs != 0 && ((bits == 64 && (abs < 1e-6 || abs >= 1e21)) || (bits == 32 && (float32(abs) < 1e-6 || float32(abs) >= 1e21))) {
			format = 'e'
		}
		dst = strconv.AppendFloat(dst, f, format, -1, bits)
		if format == 'e' {
			n := len(dst)
			if n >= 4 && dst[n-4] == 'e' && dst[n-3] == '-' && dst[n-2] == '0' {
				dst[n-2] = dst[n-1]
				dst = dst[:n-1]
			}
		}
		return dst, nil
	case reflect.String:
		return appendString(dst, v.String()), nil
	case reflect.Struct:
		dst = append(dst, '{')
		wrote := false
		if p.root {
			dst = append(dst, `"version":1,"node_type":"AST"`...)
			wrote = true
		} else if p.node {
			dst = append(dst, p.discriminator...)
			wrote = true
		}
		for i := range p.fields {
			f := &p.fields[i]
			fv := v
			for _, index := range f.index {
				if fv.Kind() == reflect.Pointer {
					if fv.IsNil() {
						fv = reflect.Value{}
						break
					}
					fv = fv.Elem()
				}
				fv = fv.Field(index)
			}
			if !fv.IsValid() || omitted(fv) {
				continue
			}
			if wrote {
				dst = append(dst, ',')
			}
			wrote = true
			dst = append(dst, f.key...)
			var err error
			dst, err = f.child.append(dst, fv, depth+1)
			if err != nil {
				return dst, fmt.Errorf("astjson: field %s: %w", f.name, err)
			}
		}
		return append(dst, '}'), nil
	case reflect.Array, reflect.Slice:
		if p.bytes {
			dst = append(dst, '"')
			dst = base64.StdEncoding.AppendEncode(dst, v.Bytes())
			return append(dst, '"'), nil
		}
		dst = append(dst, '[')
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				dst = append(dst, ',')
			}
			var err error
			dst, err = p.elem.append(dst, v.Index(i), depth+1)
			if err != nil {
				return dst, err
			}
		}
		return append(dst, ']'), nil
	case reflect.Map:
		type entry struct {
			name string
			key  reflect.Value
		}
		entries := make([]entry, 0, v.Len())
		iter := v.MapRange()
		for iter.Next() {
			k := iter.Key()
			var name string
			switch k.Kind() {
			case reflect.String:
				name = k.String()
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				name = strconv.FormatInt(k.Int(), 10)
			default:
				name = strconv.FormatUint(k.Uint(), 10)
			}
			entries = append(entries, entry{name, k})
		}
		slices.SortFunc(entries, func(a, b entry) int {
			if a.name < b.name {
				return -1
			}
			if a.name > b.name {
				return 1
			}
			return 0
		})
		dst = append(dst, '{')
		for i, e := range entries {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendString(dst, e.name)
			dst = append(dst, ':')
			var err error
			dst, err = p.elem.append(dst, v.MapIndex(e.key), depth+1)
			if err != nil {
				return dst, err
			}
		}
		return append(dst, '}'), nil
	}
	return dst, fmt.Errorf("astjson: unsupported kind %s", p.kind)
}

func (p *plan) appendLiteral(dst []byte, v reflect.Value, depth int) ([]byte, error) {
	// Pointer extraction does not box a struct or allocate on the AST hot path.
	var l *ast.LiteralValue
	if v.Kind() == reflect.Pointer {
		l, _ = v.Interface().(*ast.LiteralValue)
	} else if v.CanAddr() {
		l, _ = v.Addr().Interface().(*ast.LiteralValue)
	} else {
		value, ok := v.Interface().(ast.LiteralValue)
		if !ok {
			return dst, fmt.Errorf("astjson: invalid literal")
		}
		l = &value
	}
	if l == nil {
		return dst, fmt.Errorf("astjson: invalid literal")
	}
	x := l.DialectExtras()
	dst = append(dst, `{"node_type":"LiteralValue"`...)
	value := reflect.ValueOf(&l.Value).Elem()
	if !omitted(value) {
		dst = append(dst, `,"Value":`...)
		var err error
		dst, err = p.elem.append(dst, value, depth+1)
		if err != nil {
			return dst, err
		}
	}
	if l.Type != "" {
		dst = append(dst, `,"Type":`...)
		dst = appendString(dst, l.Type)
	}
	if x.Prefix != "" {
		dst = append(dst, `,"Prefix":`...)
		dst = appendString(dst, x.Prefix)
	}
	if x.RawBackslash {
		dst = append(dst, `,"RawBackslash":true`...)
	}
	return append(dst, '}'), nil
}

func appendMarshaler(dst []byte, v reflect.Value) ([]byte, error) {
	if !v.CanInterface() {
		return dst, fmt.Errorf("astjson: inaccessible marshaler %s", v.Type())
	}
	x := v.Interface()
	if m, ok := x.(json.Marshaler); ok {
		b, err := m.MarshalJSON()
		if err != nil {
			return dst, fmt.Errorf("astjson: MarshalJSON: %w", err)
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, b); err != nil {
			return dst, fmt.Errorf("astjson: compact MarshalJSON: %w", err)
		}
		return append(dst, compact.Bytes()...), nil
	}
	if m, ok := x.(encoding.TextMarshaler); ok {
		b, err := m.MarshalText()
		if err != nil {
			return dst, fmt.Errorf("astjson: MarshalText: %w", err)
		}
		return appendString(dst, string(b)), nil
	}
	return dst, fmt.Errorf("astjson: inaccessible marshaler method %s", v.Type())
}
