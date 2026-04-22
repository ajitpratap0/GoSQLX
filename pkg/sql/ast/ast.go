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
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Node represents any node in the Abstract Syntax Tree.
//
// Node is the base interface that all AST nodes must implement. It provides
// two core methods for tree inspection and traversal:
//
//   - TokenLiteral(): Returns the literal token value that starts this node
//   - Children(): Returns all child nodes for tree traversal
//
// The Node interface enables the visitor pattern for AST traversal. Use the
// Walk() and Inspect() functions from visitor.go to traverse the tree.
//
// Example - Checking node type:
//
//	switch node := astNode.(type) {
//	case *SelectStatement:
//	    fmt.Println("Found SELECT statement")
//	case *BinaryExpression:
//	    fmt.Printf("Binary operator: %s\n", node.Operator)
//	}
type Node interface {
	TokenLiteral() string
	Children() []Node
}

// Statement represents a SQL statement node in the AST.
//
// Statement extends the Node interface and represents top-level SQL statements
// such as SELECT, INSERT, UPDATE, DELETE, CREATE TABLE, etc. Statements form
// the root nodes of the syntax tree.
//
// All statement types implement both Node and Statement interfaces. The
// statementNode() method is a marker method to distinguish statements from
// expressions at compile time.
//
// Supported Statement Types:
//   - DML: SelectStatement, InsertStatement, UpdateStatement, DeleteStatement
//   - DDL: CreateTableStatement, AlterTableStatement, DropStatement
//   - Advanced: MergeStatement, TruncateStatement, WithClause, SetOperation
//   - Views: CreateViewStatement, CreateMaterializedViewStatement
//
// Example - Type assertion:
//
//	if stmt, ok := node.(Statement); ok {
//	    fmt.Printf("Statement type: %s\n", stmt.TokenLiteral())
//	}
type Statement interface {
	Node
	statementNode()
}

// Expression represents a SQL expression node in the AST.
//
// Expression extends the Node interface and represents SQL expressions that
// can appear within statements, such as literals, identifiers, binary operations,
// function calls, subqueries, etc.
//
// All expression types implement both Node and Expression interfaces. The
// expressionNode() method is a marker method to distinguish expressions from
// statements at compile time.
//
// Supported Expression Types:
//   - Basic: Identifier, LiteralValue, AliasedExpression
//   - Operators: BinaryExpression, UnaryExpression, BetweenExpression, InExpression
//   - Functions: FunctionCall (with window function support)
//   - Subqueries: SubqueryExpression, ExistsExpression, AnyExpression, AllExpression
//   - Conditional: CaseExpression, CastExpression
//   - Grouping: RollupExpression, CubeExpression, GroupingSetsExpression
//
// Example - Building an expression:
//
//	// Build: column = 'value'
//	expr := &BinaryExpression{
//	    Left:     &Identifier{Name: "column"},
//	    Operator: "=",
//	    Right:    &LiteralValue{Value: "value", Type: "STRING"},
//	}
type Expression interface {
	Node
	expressionNode()
}

// Helper function to convert []Expression to []Node
func nodifyExpressions(exprs []Expression) []Node {
	nodes := make([]Node, len(exprs))
	for i, expr := range exprs {
		nodes[i] = expr
	}
	return nodes
}

// Identifier represents a column or table name
type Identifier struct {
	Name  string
	Table string          // Optional table qualifier
	Pos   models.Location // Source position of this identifier (1-based line and column)
}

func (i *Identifier) expressionNode()     {}
func (i Identifier) TokenLiteral() string { return i.Name }
func (i Identifier) Children() []Node     { return nil }

// LiteralValue represents a literal value in SQL
type LiteralValue struct {
	Value interface{}
	Type  string // INTEGER, FLOAT, STRING, BOOLEAN, NULL, etc.
}

func (l *LiteralValue) expressionNode()     {}
func (l LiteralValue) TokenLiteral() string { return fmt.Sprintf("%v", l.Value) }
func (l LiteralValue) Children() []Node     { return nil }

// AST represents the root of the Abstract Syntax Tree produced by parsing one or
// more SQL statements.
//
// AST is obtained from the pool via NewAST and must be returned via ReleaseAST
// when the caller no longer needs it:
//
//	tree, err := p.ParseFromModelTokens(tokens)
//	if err != nil { return err }
//	defer ast.ReleaseAST(tree)
//
// The Statements slice contains one entry per SQL statement separated by
// semicolons. Comments captured during tokenization are preserved in Comments
// for formatters that wish to round-trip them.
//
// SQL() returns the canonical SQL string for all statements joined by ";\n".
// Span() returns the union of all statement spans for source-location tracking.
type AST struct {
	Statements []Statement
	Comments   []models.Comment // Comments captured during tokenization, preserved during formatting
}

// TokenLiteral implements Node. Returns an empty string - the AST root has no
// representative keyword.
func (a AST) TokenLiteral() string { return "" }

// Children implements Node and returns all top-level statements as a slice of Node.
func (a AST) Children() []Node {
	children := make([]Node, len(a.Statements))
	for i, stmt := range a.Statements {
		children[i] = stmt
	}
	return children
}

// HasUnsupportedStatements returns true if the AST contains any
// UnsupportedStatement nodes — statements the parser consumed but
// could not fully model.
func (a AST) HasUnsupportedStatements() bool {
	for _, stmt := range a.Statements {
		if _, ok := stmt.(*UnsupportedStatement); ok {
			return true
		}
	}
	return false
}
