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

// LiteralExtras records the uncommon string literal metadata.
type LiteralExtras struct {
	// Prefix is the introducer written before a string literal's opening
	// quote, as it appeared in the source: N for a national string, X or B for
	// a hex or bit string, or a MySQL character-set introducer such as
	// _utf8mb4. Empty for a plain string. Only meaningful when Type is STRING.
	Prefix string
	// RawBackslash is set when the literal came from a dialect in which a
	// backslash inside a string is an ordinary character (PostgreSQL standard
	// strings, Oracle, SQLite, SQL Server). Such a literal is written back
	// without doubling backslashes or turning line breaks into escapes.
	// Only meaningful when Type is STRING.
	RawBackslash bool
}

// FunctionExtras holds dialect aggregate clauses.
type FunctionExtras struct {
	Separator *LiteralValue // MySQL/MariaDB GROUP_CONCAT(... SEPARATOR 'str'); nil when absent
	Keep      *KeepClause   // Oracle KEEP (DENSE_RANK FIRST|LAST ORDER BY ...); nil when absent
}

// BinaryExtras holds dialect pattern-matching metadata.
type BinaryExtras struct {
	// Escape is the ESCAPE character expression of a LIKE / ILIKE /
	// SIMILAR TO pattern match (a LIKE 'x!%' ESCAPE '!'); nil when absent.
	Escape Expression
}

// rawLiteralExtras is immutable. Its address never escapes through an accessor.
var rawLiteralExtras = LiteralExtras{RawBackslash: true}

// DialectExtras returns a copy of the literal's string metadata. Mutating the
// returned value cannot affect this literal or another literal.
func (n *LiteralValue) DialectExtras() LiteralExtras {
	if n.extras != nil {
		return *n.extras
	}
	return LiteralExtras{}
}

// EnsureExtras returns mutable metadata, allocating it on first use or copying
// immutable shared metadata before any mutation.
func (n *LiteralValue) EnsureExtras() *LiteralExtras {
	if n.extras == nil {
		n.extras = &LiteralExtras{}
	}
	if n.extras == &rawLiteralExtras {
		x := *n.extras
		n.extras = &x
	}
	return n.extras
}

// SetRawBackslash records the string escape mode without allocating metadata
// for a prefix-free literal. Prefixes continue to use private mutable storage.
func (n *LiteralValue) SetRawBackslash(raw bool) {
	if n.extras == nil || n.extras == &rawLiteralExtras {
		n.extras = nil
		if raw {
			n.extras = &rawLiteralExtras
		}
		return
	}
	n.extras.RawBackslash = raw
}

var noFunctionExtras FunctionExtras

// DialectExtras returns the optional dialect metadata, or a read-only empty
// value when absent. Call EnsureExtras before writing; never mutate this result.
func (n *FunctionCall) DialectExtras() *FunctionExtras {
	if n.Extras != nil {
		return n.Extras
	}
	return &noFunctionExtras
}

// EnsureExtras returns mutable metadata, allocating it on first use.
func (n *FunctionCall) EnsureExtras() *FunctionExtras {
	if n.Extras == nil {
		n.Extras = &FunctionExtras{}
	}
	return n.Extras
}

var noBinaryExtras BinaryExtras

// DialectExtras returns the optional dialect metadata, or a read-only empty
// value when absent. Call EnsureExtras before writing; never mutate this result.
func (n *BinaryExpression) DialectExtras() *BinaryExtras {
	if n.Extras != nil {
		return n.Extras
	}
	return &noBinaryExtras
}

// EnsureExtras returns mutable metadata, allocating it on first use.
func (n *BinaryExpression) EnsureExtras() *BinaryExtras {
	if n.Extras == nil {
		n.Extras = &BinaryExtras{}
	}
	return n.Extras
}

var noInsertDialectFields InsertDialectFields

// DialectExtras returns the optional dialect metadata, or a read-only empty
// value when absent. Call EnsureExtras before writing; never mutate this result.
func (n *InsertStatement) DialectExtras() *InsertDialectFields {
	if n.Extras != nil {
		return n.Extras
	}
	return &noInsertDialectFields
}

// EnsureExtras returns mutable metadata, allocating it on first use.
func (n *InsertStatement) EnsureExtras() *InsertDialectFields {
	if n.Extras == nil {
		n.Extras = &InsertDialectFields{}
	}
	return n.Extras
}

// DialectExtras returns the SELECT dialect clauses for read access. Call
// EnsureExtras before writing; never mutate the empty stand-in it may return.
func (s *SelectStatement) DialectExtras() *SelectExtras { return s.extras() }

var noTableModifiers TableModifiers

// DialectModifiers returns the optional table modifiers for read access. Call
// EnsureModifiers before writing; never mutate the empty stand-in it may return.
func (t *TableReference) DialectModifiers() *TableModifiers {
	if t.Modifiers != nil {
		return t.Modifiers
	}
	return &noTableModifiers
}

// EnsureModifiers returns mutable modifiers, allocating them on first use.
func (t *TableReference) EnsureModifiers() *TableModifiers {
	if t.Modifiers == nil {
		t.Modifiers = &TableModifiers{}
	}
	return t.Modifiers
}
