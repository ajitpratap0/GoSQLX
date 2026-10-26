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
	"bytes"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// ClauseArgument is a function argument followed by dialect clause words that
// are kept as text: the path of a JSON_TABLE call with its COLUMNS clause
// (MySQL, MariaDB, Oracle), or the XPath of XMLTABLE with PASSING and COLUMNS.
//
//	JSON_TABLE(doc, '$[*]' COLUMNS (id INT PATH '$.id', n FOR ORDINALITY))
//	XMLTABLE('/rows/row' PASSING XMLTYPE(:x) COLUMNS id NUMBER PATH 'id')
//
// The clause is kept as the text of its tokens, with string literals and
// delimited names exactly as written, because each dialect has its own column
// grammar (PATH, EXISTS PATH, NESTED PATH, ON EMPTY / ON ERROR handlers,
// FORMAT JSON, ...).
type ClauseArgument struct {
	// Head is the argument the clause belongs to, usually a path literal.
	Head Expression
	// Clause is the clause text, "COLUMNS (id INT PATH '$.id', ...)".
	Clause string
	// Pos is the position of the first clause word.
	Pos models.Location
}

func (c *ClauseArgument) expressionNode()     {}
func (c ClauseArgument) TokenLiteral() string { return "COLUMNS" }

// Children returns the head expression.
func (c ClauseArgument) Children() []Node {
	if c.Head == nil {
		return nil
	}
	return []Node{c.Head}
}

// IsPlainRawText reports whether s, the verbatim text of a clause kept by the
// parser, can be written back unchanged. Renderers drop text that is not
// plain, so a parser that keeps such text must refuse the input instead.
func IsPlainRawText(s string) bool { return rawTextIsPlain(s) }

// SQL renders the head and the clause.
func (c *ClauseArgument) SQL() string {
	if c == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	c.writeSQL(buf)
	return buf.String()
}

func (c *ClauseArgument) writeSQL(buf *bytes.Buffer) {
	if c == nil {
		return
	}
	writeExpr(buf, c.Head)
	// A clause that is not plain text (hand-built AST) is dropped rather than
	// written where it could change the statement.
	if c.Clause != "" && rawTextIsPlain(c.Clause) {
		buf.WriteByte(' ')
		buf.WriteString(c.Clause)
	}
}

// JSONObjectEntry is one name/value pair argument of JSON_OBJECT or
// JSON_OBJECTAGG in the keyword forms of Oracle, SQL Server and PostgreSQL:
//
//	JSON_OBJECT('id' VALUE employee_id, KEY 'name' VALUE last_name)
//	JSON_OBJECT('id': employee_id)
type JSONObjectEntry struct {
	// Key is the member name expression.
	Key Expression
	// Value is the member value expression.
	Value Expression
	// KeyKeyword marks the optional KEY word before the name.
	KeyKeyword bool
	// Colon marks the name: value form; otherwise NAME VALUE value is written.
	Colon bool
	Pos   models.Location
}

func (j *JSONObjectEntry) expressionNode()     {}
func (j JSONObjectEntry) TokenLiteral() string { return "VALUE" }

// Children returns the name and value expressions.
func (j JSONObjectEntry) Children() []Node {
	nodes := make([]Node, 0, 2)
	if j.Key != nil {
		nodes = append(nodes, j.Key)
	}
	if j.Value != nil {
		nodes = append(nodes, j.Value)
	}
	return nodes
}

// SQL renders the pair.
func (j *JSONObjectEntry) SQL() string {
	if j == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	j.writeSQL(buf)
	return buf.String()
}

func (j *JSONObjectEntry) writeSQL(buf *bytes.Buffer) {
	if j == nil {
		return
	}
	if j.KeyKeyword {
		buf.WriteString("KEY ")
	}
	writeExpr(buf, j.Key)
	if j.Colon {
		buf.WriteString(": ")
	} else {
		buf.WriteString(" VALUE ")
	}
	writeExpr(buf, j.Value)
}
