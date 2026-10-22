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
	"strings"
)

// StarExpression is a select-list wildcard with column modifiers:
//
//	SELECT * EXCLUDE (a, b) FROM t                 -- Snowflake, DuckDB
//	SELECT * EXCEPT (a) FROM t                     -- ClickHouse, BigQuery
//	SELECT * REPLACE (UPPER(name) AS name) FROM t  -- Snowflake, ClickHouse, BigQuery
//	SELECT t.* RENAME (id AS t_id) FROM t          -- Snowflake
//	SELECT * ILIKE '%name%' FROM t                 -- Snowflake
//
// A plain "*" or "t.*" without modifiers stays an *Identifier with Name "*";
// StarExpression is only produced when at least one modifier is present.
type StarExpression struct {
	// Star is the wildcard itself: an *Identifier with Name "*" and an
	// optional Table qualifier.
	Star Expression
	// Ilike is the Snowflake ILIKE pattern (a string literal), or nil.
	Ilike Expression
	// ExcludeKeyword is EXCLUDE or EXCEPT; Exclude lists the excluded columns.
	ExcludeKeyword string
	Exclude        []string
	// Replace holds REPLACE (expr AS col, ...) items.
	Replace []*AliasedExpression
	// Rename holds RENAME (col AS new_name, ...) items.
	Rename []StarRename
}

// StarRename is one RENAME (old AS new) item of a StarExpression.
type StarRename struct {
	Column string
	Alias  string
}

func (s *StarExpression) expressionNode()     {}
func (s StarExpression) TokenLiteral() string { return "*" }

// Children returns the wildcard, the ILIKE pattern and the REPLACE items.
func (s StarExpression) Children() []Node {
	nodes := make([]Node, 0, 2+len(s.Replace))
	if s.Star != nil {
		nodes = append(nodes, s.Star)
	}
	if s.Ilike != nil {
		nodes = append(nodes, s.Ilike)
	}
	for _, r := range s.Replace {
		if r != nil {
			nodes = append(nodes, r)
		}
	}
	return nodes
}

// SQL renders the wildcard and its modifiers.
func (s *StarExpression) SQL() string {
	if s == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	s.writeSQL(buf)
	return buf.String()
}

func (s *StarExpression) writeSQL(buf *bytes.Buffer) {
	if s == nil {
		return
	}
	if s.Star != nil {
		writeExpr(buf, s.Star)
	} else {
		buf.WriteByte('*')
	}
	if s.Ilike != nil {
		buf.WriteString(" ILIKE ")
		writeExpr(buf, s.Ilike)
	}
	if len(s.Exclude) > 0 {
		kw := "EXCLUDE"
		if strings.EqualFold(s.ExcludeKeyword, "EXCEPT") {
			kw = "EXCEPT"
		}
		buf.WriteByte(' ')
		buf.WriteString(kw)
		buf.WriteString(" (")
		for i, n := range s.Exclude {
			if i > 0 {
				buf.WriteString(", ")
			}
			writeStarColumnName(buf, n)
		}
		buf.WriteByte(')')
	}
	if len(s.Replace) > 0 {
		buf.WriteString(" REPLACE (")
		for i, r := range s.Replace {
			if i > 0 {
				buf.WriteString(", ")
			}
			if r == nil {
				continue
			}
			writeExpr(buf, r.Expr)
			buf.WriteString(" AS ")
			writeName(buf, r.Alias)
		}
		buf.WriteByte(')')
	}
	if len(s.Rename) > 0 {
		buf.WriteString(" RENAME (")
		for i, r := range s.Rename {
			if i > 0 {
				buf.WriteString(", ")
			}
			writeName(buf, r.Column)
			buf.WriteString(" AS ")
			writeName(buf, r.Alias)
		}
		buf.WriteByte(')')
	}
}

// writeStarColumnName writes an EXCLUDE / EXCEPT column name. The parser
// stores a qualified name (t.col) joined with dots, so each dot-separated
// part is quoted on its own: t.col must not become the single identifier
// "t.col".
func writeStarColumnName(buf *bytes.Buffer, name string) {
	for {
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			writeName(buf, name)
			return
		}
		writeName(buf, name[:dot])
		buf.WriteByte('.')
		name = name[dot+1:]
	}
}
