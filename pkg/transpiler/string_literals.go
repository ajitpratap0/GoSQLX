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
		if lit.Prefix == "E" || lit.Prefix == "e" {
			// A kept E'..' is always written with escapes.
			lit.RawBackslash = false
		} else {
			lit.RawBackslash = esc == dialect.StringEscapeNone
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
	if lit.Prefix == "E" || lit.Prefix == "e" {
		return 0, false
	}
	hasNUL := strings.IndexByte(text, 0) >= 0
	hasSUB := strings.IndexByte(text, 0x1a) >= 0
	switch {
	case lit.RawBackslash:
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
	switch p := lit.Prefix; {
	case p == "":
	case p == "E" || p == "e":
		if target != dialect.PostgreSQL {
			lit.Prefix = ""
		}
	case p == "q" || p == "Q":
		if target != dialect.Oracle {
			lit.Prefix = ""
		}
	case p[0] == '_':
		if target != dialect.MySQL && target != dialect.MariaDB {
			lit.Prefix = ""
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
func forEachLiteral(v reflect.Value, seen map[seenPtr]bool, f func(*ast.LiteralValue)) {
	switch v.Kind() {
	case reflect.Interface:
		if !v.IsNil() {
			forEachLiteral(v.Elem(), seen, f)
		}
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		key := seenPtr{v.Type(), v.Pointer()}
		if seen[key] {
			return
		}
		seen[key] = true
		if v.Elem().Type() == literalType {
			if lit, ok := v.Interface().(*ast.LiteralValue); ok {
				f(lit)
			}
			return
		}
		forEachLiteral(v.Elem(), seen, f)
	case reflect.Struct:
		if v.Type() == literalType {
			if v.CanAddr() {
				if lit, ok := v.Addr().Interface().(*ast.LiteralValue); ok {
					f(lit)
				}
			}
			return
		}
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if t.Field(i).IsExported() {
				forEachLiteral(v.Field(i), seen, f)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			forEachLiteral(v.Index(i), seen, f)
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			forEachLiteral(iter.Value(), seen, f)
		}
	}
}
