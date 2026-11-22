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

package transpiler

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/internal/reflplan"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// retargetStringLiterals rewrites every string literal under node so the
// formatter writes it with the target dialect's rules and the literal keeps
// its value there.
//
// The parser records how the SOURCE dialect reads a literal (whether a
// backslash escapes, and introducers such as E'..', q'[..]' or _utf8mb4'..').
// Written unchanged for another dialect that record is wrong: a PostgreSQL
// 'C:\dir' written for MySQL turns \d into d, and a PostgreSQL 'x\' followed
// by more text closes early in MySQL, so the rest of the statement would run
// as code. So each literal gets the target's backslash mode and loses any
// introducer the target does not have; the decoded value is unchanged and is
// re-escaped for the target when written.
//
// A value the target cannot spell in a plain literal is refused rather than
// written with a different value (see unrepresentable).
func retargetStringLiterals(node ast.Node, to keywords.SQLDialect) error {
	target := dialect.Parse(string(to))
	esc := target.StringEscape()
	var err error
	forEachLiteral(reflect.ValueOf(node), make(map[seenPtr]bool), func(lit *ast.LiteralValue) {
		if err != nil || !strings.EqualFold(lit.Type, "string") {
			return
		}
		retargetPrefix(lit, target)
		if lit.DialectExtras().Prefix == "E" || lit.DialectExtras().Prefix == "e" {
			// A kept E'..' is always written with escapes.
			lit.SetRawBackslash(false)
		} else {
			lit.SetRawBackslash(esc == dialect.StringEscapeNone)
		}
		text, ok := lit.Value.(string)
		if !ok {
			return
		}
		if c, bad := unrepresentable(lit, esc, text); bad {
			err = fmt.Errorf("string literal contains the control character %U, which %s cannot represent in a string literal", c, to)
		}
	})
	return err
}

// unrepresentable reports a NUL or Ctrl-Z in text that the writer cannot
// spell for the target: a dialect without backslash escapes has no NUL (the
// writer would drop it); the writer spells NUL as \0 and Ctrl-Z as \Z, which
// only MySQL reads back exactly (ClickHouse keeps \Z as two characters,
// Snowflake reads \0 followed by digits as an octal escape and \Z as Z, and
// a tokenizer with no dialect rejects both). An E'..' literal spells them
// \000 and raw, which PostgreSQL reads back.
func unrepresentable(lit *ast.LiteralValue, esc dialect.StringEscape, text string) (rune, bool) {
	if lit.DialectExtras().Prefix == "E" || lit.DialectExtras().Prefix == "e" {
		return 0, false
	}
	hasNUL := strings.IndexByte(text, 0) >= 0
	hasSUB := strings.IndexByte(text, 0x1a) >= 0
	switch {
	case lit.DialectExtras().RawBackslash:
		return 0, hasNUL
	case esc == dialect.StringEscapeMySQL:
		return 0, false
	case esc == dialect.StringEscapeLenient:
		return 0x1a, hasSUB
	case hasNUL:
		return 0, true
	default:
		return 0x1a, hasSUB
	}
}

// retargetPrefix drops a string introducer the target dialect lacks. Only
// introducers that are pure spelling are dropped (the decoded value already
// holds the text): PostgreSQL E'..', Oracle q'[..]' and a MySQL character-set
// introducer outside the MySQL family. N, X and B change the literal's type
// and are kept.
func retargetPrefix(lit *ast.LiteralValue, target dialect.Dialect) {
	switch p := lit.DialectExtras().Prefix; {
	case p == "":
	case p == "E" || p == "e":
		if target != dialect.PostgreSQL {
			lit.EnsureExtras().Prefix = ""
		}
	case p == "q" || p == "Q":
		if target != dialect.Oracle {
			lit.EnsureExtras().Prefix = ""
		}
	case p[0] == '_':
		if target != dialect.MySQL && target != dialect.MariaDB {
			lit.EnsureExtras().Prefix = ""
		}
	}
}

var literalType = reflect.TypeOf(ast.LiteralValue{})

// seenPtr identifies a visited pointer. The type is part of the key because
// a struct and its first field share an address.
type seenPtr struct {
	t reflect.Type
	p uintptr
}

// forEachLiteral calls f for every *ast.LiteralValue reachable from v through
// exported fields, slices, arrays, maps, pointers and interfaces. It uses
// reflection rather than Node.Children so a literal held by a node whose
// Children list is incomplete is still retargeted: one missed literal would
// keep the source escaping. seen guards against shared or cyclic pointers.
// An explicit stack preserves pre-order without consuming the goroutine stack.
func forEachLiteral(v reflect.Value, seen map[seenPtr]bool, f func(*ast.LiteralValue)) {
	type item struct {
		v reflect.Value
		p *reflplan.Plan
	}
	if !v.IsValid() {
		return
	}
	var small [64]item
	stack := append(small[:0], item{v, reflplan.Of(v.Type())})
	for len(stack) > 0 {
		it := stack[len(stack)-1]
		v, p := it.v, it.p
		stack = stack[:len(stack)-1]
		switch v.Kind() {
		case reflect.Interface:
			if !v.IsNil() {
				e := v.Elem()
				stack = append(stack, item{e, reflplan.Of(e.Type())})
			}
		case reflect.Pointer:
			if v.IsNil() {
				continue
			}
			key := seenPtr{p.Type, v.Pointer()}
			if seen[key] {
				continue
			}
			seen[key] = true
			if p.Elem.Type == literalType {
				if lit, ok := v.Interface().(*ast.LiteralValue); ok {
					f(lit)
				}
				continue
			}
			stack = append(stack, item{v.Elem(), p.Elem})
		case reflect.Struct:
			if p.Type == literalType {
				if v.CanAddr() {
					if lit, ok := v.Addr().Interface().(*ast.LiteralValue); ok {
						f(lit)
					}
				}
				continue
			}
			for i := len(p.Fields) - 1; i >= 0; i-- {
				fp := p.Fields[i]
				stack = append(stack, item{v.Field(fp.Index), fp.Plan})
			}
		case reflect.Slice, reflect.Array:
			if !p.Elem.Reach {
				continue
			}
			for i := v.Len() - 1; i >= 0; i-- {
				stack = append(stack, item{v.Index(i), p.Elem})
			}
		case reflect.Map:
			if !p.Elem.Reach {
				continue
			}
			iter := v.MapRange()
			start := len(stack)
			for iter.Next() {
				stack = append(stack, item{iter.Value(), p.Elem})
			}
			// Preserve this iterator's order with a LIFO stack.
			for i, j := start, len(stack)-1; i < j; i, j = i+1, j-1 {
				stack[i], stack[j] = stack[j], stack[i]
			}
		}
	}
}
