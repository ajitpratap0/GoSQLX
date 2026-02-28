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

// Select represents a SELECT statement
type Select struct {
	Distinct bool
	Columns  []Expression
	From     []TableReference
	Where    Expression
	GroupBy  []Expression
	Having   Expression
	OrderBy  []OrderByExpression
	Limit    *int64
	Offset   *int64
}

func (s *Select) statementNode() {}

// TokenLiteral implements Node and returns "SELECT".
func (s Select) TokenLiteral() string { return "SELECT" }

// Children implements Node and returns all child nodes of this Select statement.
func (s Select) Children() []Node {
	children := make([]Node, 0)
	children = append(children, nodifyExpressions(s.Columns)...)
	for _, from := range s.From {
		from := from // G601: Create local copy to avoid memory aliasing
		children = append(children, &from)
	}
	if s.Where != nil {
		children = append(children, s.Where)
	}
	children = append(children, nodifyExpressions(s.GroupBy)...)
	if s.Having != nil {
		children = append(children, s.Having)
	}
	for _, orderBy := range s.OrderBy {
		orderBy := orderBy // G601: Create local copy to avoid memory aliasing
		children = append(children, &orderBy)
	}
	return children
}

// Insert represents an INSERT statement
type Insert struct {
	Table           TableReference
	Columns         []Expression
	Values          [][]Expression
	ReturningClause []Expression
}

func (i *Insert) statementNode() {}

// TokenLiteral implements Node and returns "INSERT".
func (i Insert) TokenLiteral() string { return "INSERT" }

// Children implements Node and returns all child nodes of this Insert statement.
func (i Insert) Children() []Node {
	children := make([]Node, 0)
	children = append(children, &i.Table)
	children = append(children, nodifyExpressions(i.Columns)...)
	for _, row := range i.Values {
		children = append(children, nodifyExpressions(row)...)
	}
	children = append(children, nodifyExpressions(i.ReturningClause)...)
	return children
}

// Delete represents a DELETE statement
type Delete struct {
	Table           TableReference
	Where           Expression
	ReturningClause []Expression
}

func (d *Delete) statementNode() {}

// TokenLiteral implements Node and returns "DELETE".
func (d Delete) TokenLiteral() string { return "DELETE" }

// Children implements Node and returns all child nodes of this Delete statement.
func (d Delete) Children() []Node {
	children := make([]Node, 0)
	children = append(children, &d.Table)
	if d.Where != nil {
		children = append(children, d.Where)
	}
	children = append(children, nodifyExpressions(d.ReturningClause)...)
	return children
}

// Update represents an UPDATE statement
type Update struct {
	Table           TableReference
	Updates         []UpdateExpression
	Where           Expression
	ReturningClause []Expression
}

func (u *Update) statementNode() {}

// TokenLiteral implements Node and returns "UPDATE".
func (u Update) TokenLiteral() string { return "UPDATE" }

// Children implements Node and returns all child nodes of this Update statement.
func (u Update) Children() []Node {
	children := make([]Node, 0)
	children = append(children, &u.Table)
	for _, update := range u.Updates {
		update := update // G601: Create local copy to avoid memory aliasing
		children = append(children, &update)
	}
	if u.Where != nil {
		children = append(children, u.Where)
	}
	children = append(children, nodifyExpressions(u.ReturningClause)...)
	return children
}
