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

// ObjectLiteral is a Snowflake semi-structured object constant:
//
//	{'name': 'x', 'n': 1}
//
// It is the constant form of OBJECT_CONSTRUCT.
type ObjectLiteral struct {
	Entries []ObjectEntry
	Pos     models.Location // Source position of the opening brace
}

// ObjectEntry is one key: value pair of an ObjectLiteral.
type ObjectEntry struct {
	Key   Expression
	Value Expression
}

func (o *ObjectLiteral) expressionNode()     {}
func (o ObjectLiteral) TokenLiteral() string { return "{" }

// Children returns the keys and values in source order.
func (o ObjectLiteral) Children() []Node {
	nodes := make([]Node, 0, 2*len(o.Entries))
	for _, e := range o.Entries {
		if e.Key != nil {
			nodes = append(nodes, e.Key)
		}
		if e.Value != nil {
			nodes = append(nodes, e.Value)
		}
	}
	return nodes
}

// SQL renders the object constant.
func (o *ObjectLiteral) SQL() string {
	if o == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	o.writeSQL(buf)
	return buf.String()
}

func (o *ObjectLiteral) writeSQL(buf *bytes.Buffer) {
	if o == nil {
		return
	}
	buf.WriteByte('{')
	for i, e := range o.Entries {
		if i > 0 {
			buf.WriteString(", ")
		}
		writeExpr(buf, e.Key)
		buf.WriteString(": ")
		writeExpr(buf, e.Value)
	}
	buf.WriteByte('}')
}
